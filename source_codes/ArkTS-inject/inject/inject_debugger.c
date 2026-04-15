/*
 * inject_debugger — 通过 ptrace 在目标进程中启动 Ark Inspector 调试服务器
 *
 * 策略: 不使用 code cave，而是使用 PTRACE_SYSCALL 拦截方式执行 syscall。
 * 对于函数调用，搜索目标库中已有的 "call rax / ret" gadget。
 *
 * 流程:
 *   1. ptrace ATTACH
 *   2. 使用 PTRACE_INTERRUPT 停止线程
 *   3. 执行 socketpair syscall (通过修改寄存器 + 找到 syscall 指令)
 *   4. 调用 StartServerForSocketPair(sv[0])
 *   5. 输出 sv[1]
 *
 * 编译:
 *   clang --target=x86_64-linux-ohos -O2 -o inject_debugger inject_debugger.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <errno.h>
#include <stdint.h>
#include <elf.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/types.h>

static void die(const char *msg)
{
    fprintf(stderr, "[DBG-INJECT-ERR] %s: %s\n", msg, strerror(errno));
    exit(1);
}

/* ---------- memory helpers ---------- */

static int mem_write(pid_t pid, uint64_t addr, const void *data, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = pwrite(fd, (void *)data, len, (off_t)addr);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

static int mem_read(pid_t pid, uint64_t addr, void *buf, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = pread(fd, buf, len, (off_t)addr);
    close(fd);
    return (n == (ssize_t)len) ? 0 : -1;
}

/* ---------- module info ---------- */

struct module_info {
    uint64_t rx_start, rx_end;
    uint64_t rw_start, rw_end;
    uint64_t base;
};

static int find_module(pid_t pid, const char *name, struct module_info *info)
{
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
    FILE *f = fopen(mpath, "r");
    if (!f) return -1;
    memset(info, 0, sizeof(*info));
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, name)) continue;
        found = 1;
        unsigned long start, end;
        char perms[8];
        sscanf(line, "%lx-%lx %4s", &start, &end, perms);
        if (!info->base) info->base = start;
        if (strcmp(perms, "r-xp") == 0) {
            if (!info->rx_start) info->rx_start = start;
            info->rx_end = end;
        } else if (strcmp(perms, "rw-p") == 0) {
            if (!info->rw_start) info->rw_start = start;
            info->rw_end = end;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

/* ---------- Find a "syscall" instruction in an r-xp mapping ---------- */
/*
 * 在指定的 r-xp 范围内搜索 0x0F 0x05 (syscall) 后跟 0xCC (int3) 或 0xC3 (ret)。
 * 返回 syscall 指令的地址。
 */
static uint64_t find_syscall_gadget(pid_t pid, uint64_t rx_start, uint64_t rx_end)
{
    /* Search backwards from end — syscall gadgets often near PLT area */
    /* We search in chunks */
    size_t chunk = 4096;
    uint8_t buf[4096];

    for (uint64_t off = rx_end - chunk; off >= rx_start; off -= chunk / 2) {
        size_t to_read = chunk;
        if (off + to_read > rx_end) to_read = (size_t)(rx_end - off);
        if (mem_read(pid, off, buf, to_read) < 0) break;

        for (size_t i = 0; i < to_read - 2; i++) {
            if (buf[i] == 0x0F && buf[i+1] == 0x05) {
                /* Check what follows: int3 (0xCC) or ret (0xC3) */
                if (i + 2 < to_read && (buf[i+2] == 0xCC || buf[i+2] == 0xC3)) {
                    uint64_t addr = off + i;
                    fprintf(stderr, "[DBG-INJECT] Found syscall gadget at 0x%lx (followed by 0x%02x)\n",
                            (unsigned long)addr, buf[i+2]);
                    return addr;
                }
            }
        }
    }
    return 0;
}

/* ---------- Find "call rax" gadget in r-xp mapping ---------- */
/* 0xFF 0xD0 = call rax
 * We search for call rax followed by anything — we'll patch the next byte to int3.
 * Also search for other call patterns: call r8 (41 FF D0), call r9 (41 FF D1), etc.
 */
static uint64_t find_call_rax_gadget(pid_t pid, uint64_t rx_start, uint64_t rx_end)
{
    size_t chunk = 4096;
    uint8_t buf[4096];

    for (uint64_t off = rx_end - chunk; off >= rx_start; off -= chunk / 2) {
        size_t to_read = chunk;
        if (off + to_read > rx_end) to_read = (size_t)(rx_end - off);
        if (mem_read(pid, off, buf, to_read) < 0) break;

        for (size_t i = 0; i < to_read - 2; i++) {
            /* call rax: FF D0 */
            if (buf[i] == 0xFF && buf[i+1] == 0xD0) {
                uint64_t addr = off + i;
                fprintf(stderr, "[DBG-INJECT] Found call rax at 0x%lx (followed by 0x%02x)\n",
                        (unsigned long)addr, (i + 2 < to_read) ? buf[i+2] : 0);
                return addr;
            }
        }
    }
    return 0;
}

/* ---------- Execute syscall via PTRACE_SYSCALL intercept ---------- */
/*
 * Strategy: We find an existing "syscall; ret" gadget in the target process.
 * We set RIP to that gadget, set registers for the desired syscall,
 * then PTRACE_CONT. The process will execute the syscall and continue
 * until it hits our int3 (or the next stop).
 *
 * Actually, the simplest approach: set RIP to a "syscall; int3" sequence
 * that we write to a code cave. But code caves crash on OHOS.
 *
 * Better: use PTRACE_SETREGS + PTRACE_SINGLESTEP to execute one instruction
 * at a time. But that's slow.
 *
 * Best: find "syscall; ret" in vdso or libc. Set regs, set RIP to syscall,
 * set a breakpoint at ret instruction, PTRACE_CONT, wait for SIGTRAP.
 *
 * Even better approach for function calls:
 * Use PTRACE_SETREGS to set RAX, args, then find "call rax; ret" gadget.
 */

/*
 * Execute a syscall in the target.
 * Uses a "syscall; CC" or "syscall; C3" gadget found in target memory.
 * If followed by C3 (ret), we set a hardware breakpoint or use single-step.
 * For simplicity, we write our own "syscall; int3" to a known writable+executable
 * location. But since code caves don't work on OHOS, we use an alternative:
 *
 * We use the fact that libc.so contains many syscall instructions.
 * We find one followed by int3 (0xCC) in an r-xp mapping.
 * If no int3 follows, we patch the byte after syscall to int3 temporarily.
 */
static uint64_t exec_syscall_in_target(pid_t pid, struct user_regs_struct *orig_regs,
                                        uint64_t syscall_gadget,
                                        uint64_t sysno,
                                        uint64_t a0, uint64_t a1, uint64_t a2,
                                        uint64_t a3, uint64_t a4, uint64_t a5)
{
    /* Check what follows the syscall instruction */
    uint8_t after[2];
    mem_read(pid, syscall_gadget + 2, after, 1);
    int need_restore = 0;
    uint8_t orig_after = after[0];

    if (after[0] != 0xCC) {
        /* Temporarily patch to int3 */
        uint8_t cc = 0xCC;
        mem_write(pid, syscall_gadget + 2, &cc, 1);
        need_restore = 1;
    }

    struct user_regs_struct regs = *orig_regs;
    regs.rax = sysno;
    regs.rdi = a0;
    regs.rsi = a1;
    regs.rdx = a2;
    regs.r10 = a3;
    regs.r8  = a4;
    regs.r9  = a5;
    regs.rip = syscall_gadget;
    regs.orig_rax = (uint64_t)-1;  /* Prevent syscall restart from clobbering RIP */

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] SETREGS for syscall: %s\n", strerror(errno));
        if (need_restore) mem_write(pid, syscall_gadget + 2, &orig_after, 1);
        return (uint64_t)-1;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] CONT for syscall: %s\n", strerror(errno));
        if (need_restore) mem_write(pid, syscall_gadget + 2, &orig_after, 1);
        return (uint64_t)-1;
    }

    int status;
    waitpid(pid, &status, 0);

    uint64_t result = (uint64_t)-1;
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        struct user_regs_struct ret_regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &ret_regs);
        result = ret_regs.rax;
    } else {
        fprintf(stderr, "[DBG-INJECT-ERR] syscall unexpected stop: status=0x%x sig=%d\n",
                status, WIFSTOPPED(status) ? WSTOPSIG(status) : -1);
    }

    /* Restore patched byte */
    if (need_restore) {
        mem_write(pid, syscall_gadget + 2, &orig_after, 1);
    }

    return result;
}

/* ---------- Call a function with 1 argument ---------- */
/*
 * Find a "call rax" gadget, set RDI=arg, RAX=func, set RIP to gadget,
 * place int3 after it.
 */
static uint64_t exec_call1_in_target(pid_t pid, struct user_regs_struct *orig_regs,
                                      uint64_t call_rax_gadget,
                                      uint64_t func_addr, uint64_t arg0)
{
    /* Check what follows the call rax */
    uint8_t after;
    mem_read(pid, call_rax_gadget + 2, &after, 1);
    int need_restore = 0;
    uint8_t orig_after = after;

    if (after != 0xCC) {
        uint8_t cc = 0xCC;
        mem_write(pid, call_rax_gadget + 2, &cc, 1);
        need_restore = 1;
    }

    struct user_regs_struct regs = *orig_regs;
    regs.rdi = arg0;
    regs.rax = func_addr;
    regs.rip = call_rax_gadget;
    regs.orig_rax = (uint64_t)-1;  /* Prevent syscall restart from clobbering RIP */
    /* Align stack to 16 bytes */
    regs.rsp = (orig_regs->rsp - 256) & ~0xFULL;

    if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] SETREGS for call: %s\n", strerror(errno));
        if (need_restore) mem_write(pid, call_rax_gadget + 2, &orig_after, 1);
        return (uint64_t)-1;
    }

    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] CONT for call: %s\n", strerror(errno));
        if (need_restore) mem_write(pid, call_rax_gadget + 2, &orig_after, 1);
        return (uint64_t)-1;
    }

    int status;
    waitpid(pid, &status, 0);

    uint64_t result = (uint64_t)-1;
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        struct user_regs_struct ret_regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &ret_regs);
        result = ret_regs.rax;
    } else {
        struct user_regs_struct crash_regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &crash_regs);
        fprintf(stderr, "[DBG-INJECT-ERR] call unexpected stop: status=0x%x sig=%d\n",
                status, WIFSTOPPED(status) ? WSTOPSIG(status) : -1);
        fprintf(stderr, "[DBG-INJECT-ERR] crash RIP=0x%lx RSP=0x%lx RAX=0x%lx\n",
                (unsigned long)crash_regs.rip, (unsigned long)crash_regs.rsp,
                (unsigned long)crash_regs.rax);
    }

    /* Restore */
    if (need_restore) {
        mem_write(pid, call_rax_gadget + 2, &orig_after, 1);
    }

    return result;
}

/* ---------- ELF symbol resolver ---------- */

static uint64_t resolve_symbol(pid_t pid, struct module_info *mod, const char *sym_name)
{
    uint64_t base = mod->base;
    uint8_t ehdr[64];
    if (mem_read(pid, base, ehdr, sizeof(ehdr)) < 0) return 0;
    uint64_t e_phoff = *(uint64_t *)(ehdr + 32);
    uint16_t e_phentsize = *(uint16_t *)(ehdr + 54);
    uint16_t e_phnum = *(uint16_t *)(ehdr + 56);

    uint64_t dynamic_addr = 0;
    for (int i = 0; i < e_phnum; i++) {
        uint8_t ph[56];
        if (mem_read(pid, base + e_phoff + i * e_phentsize, ph, e_phentsize) < 0) return 0;
        if (*(uint32_t *)ph == 2) {
            dynamic_addr = base + *(uint64_t *)(ph + 16);
            break;
        }
    }
    if (!dynamic_addr) return 0;

    uint64_t strtab = 0, symtab = 0;
    uint64_t jmprel = 0, pltrelsz = 0;
    uint64_t gnu_hash = 0;

    for (int i = 0; i < 512; i++) {
        uint8_t dyn[16];
        if (mem_read(pid, dynamic_addr + i * 16, dyn, 16) < 0) break;
        int64_t tag = *(int64_t *)dyn;
        uint64_t val = *(uint64_t *)(dyn + 8);
        if (tag == 0) break;
        switch (tag) {
            case 5:  strtab = base + val; break;
            case 6:  symtab = base + val; break;
            case 23: jmprel = base + val; break;
            case 2:  pltrelsz = val; break;
            case 0x6ffffef5: gnu_hash = base + val; break;
        }
    }
    if (!strtab || !symtab) return 0;

    /* Determine symbol count via GNU hash */
    int sym_count = 0;
    if (gnu_hash) {
        uint32_t gnu_hdr[4];
        if (mem_read(pid, gnu_hash, gnu_hdr, sizeof(gnu_hdr)) < 0) return 0;
        uint32_t nbuckets = gnu_hdr[0];
        uint32_t symoffset = gnu_hdr[1];
        uint32_t max_sym = symoffset;
        for (uint32_t b = 0; b < nbuckets; b++) {
            uint32_t idx;
            if (mem_read(pid, gnu_hash + 16 + b * 4, &idx, 4) < 0) break;
            if (idx > max_sym) max_sym = idx;
        }
        if (max_sym > symoffset) {
            uint32_t maskwords = 0;
            mem_read(pid, gnu_hash + 8, &maskwords, 4);
            uint64_t chains = gnu_hash + 16 + nbuckets * 4 + (uint64_t)maskwords * 8;
            uint32_t cur = max_sym - symoffset;
            for (int limit = 0; limit < 65536; limit++) {
                uint32_t hash_val;
                if (mem_read(pid, chains + cur * 4, &hash_val, 4) < 0) break;
                if ((hash_val & 1) != 0) break;
                cur++;
            }
            sym_count = symoffset + cur + 1;
        } else {
            sym_count = 4096;
        }
    } else {
        sym_count = (strtab > symtab) ? (int)((strtab - symtab) / 24) : 4096;
    }
    if (sym_count > 65536) sym_count = 65536;

    /* Search .dynsym */
    for (int i = 0; i < sym_count; i++) {
        uint8_t sym[24];
        if (mem_read(pid, symtab + i * 24, sym, 24) < 0) break;
        uint64_t st_value = *(uint64_t *)(sym + 8);
        if (!st_value) continue;

        char name[256];
        if (mem_read(pid, strtab + *(uint32_t *)sym, name, sizeof(name)) < 0) break;
        name[255] = 0;

        if (strcmp(name, sym_name) == 0) {
            fprintf(stderr, "[DBG-INJECT] Found %s: base=0x%lx offset=0x%lx addr=0x%lx\n",
                    sym_name, (unsigned long)base, (unsigned long)st_value,
                    (unsigned long)(base + st_value));
            return base + st_value;
        }
    }

    /* Search JMPREL (PLT imports) */
    if (jmprel && pltrelsz) {
        int count = (int)(pltrelsz / 24);
        for (int i = 0; i < count; i++) {
            uint8_t rela[24];
            if (mem_read(pid, jmprel + i * 24, rela, 24) < 0) break;
            uint64_t r_info = *(uint64_t *)(rela + 8);
            uint32_t sym_idx = (uint32_t)(r_info >> 32);
            if ((r_info & 0xffffffff) != 7) continue;

            uint8_t sym[24];
            if (mem_read(pid, symtab + sym_idx * 24, sym, 24) < 0) break;
            char name[256];
            if (mem_read(pid, strtab + *(uint32_t *)sym, name, sizeof(name)) < 0) break;
            name[255] = 0;

            if (strcmp(name, sym_name) == 0) {
                uint64_t got_addr = base + *(uint64_t *)rela;
                uint64_t resolved;
                if (mem_read(pid, got_addr, &resolved, 8) < 0) return 0;
                fprintf(stderr, "[DBG-INJECT] Found %s via PLT: resolved=0x%lx\n",
                        sym_name, (unsigned long)resolved);
                return resolved;
            }
        }
    }

    fprintf(stderr, "[DBG-INJECT] Symbol %s not found\n", sym_name);
    return 0;
}

/* ---------- CDP/WS helpers ---------- */

/* Build a masked WebSocket text frame containing CDP JSON.
 * Returns total frame length, or 0 on error. */
static size_t build_ws_frame(const char *json, uint8_t *out, size_t out_size)
{
    size_t payload_len = strlen(json);
    size_t idx = 0;
    out[idx++] = 0x81; /* FIN=1, opcode=text */
    if (payload_len <= 125) {
        out[idx++] = 0x80 | (uint8_t)payload_len; /* mask=1 + len */
    } else if (payload_len <= 65535) {
        out[idx++] = 0x80 | 0x7e; /* 126 → 16-bit length */
        out[idx++] = (uint8_t)((payload_len >> 8) & 0xff);
        out[idx++] = (uint8_t)(payload_len & 0xff);
    } else {
        return 0; /* too large */
    }
    /* mask key (arbitrary) */
    uint8_t mask[4] = {0x37, 0xfa, 0x21, 0x3d};
    out[idx++] = mask[0];
    out[idx++] = mask[1];
    out[idx++] = mask[2];
    out[idx++] = mask[3];
    if (idx + payload_len > out_size) return 0;
    for (size_t i = 0; i < payload_len; i++) {
        out[idx + i] = (uint8_t)json[i] ^ mask[i % 4];
    }
    return idx + payload_len;
}

/* Send a CDP JSON command via ptrace write on sv_fd.
 * Returns write syscall result. */
static uint64_t send_cdp(pid_t pid, struct user_regs_struct *regs,
                          uint64_t syscall_gadget, int sv_fd,
                          uint64_t data_buf, const char *json)
{
    uint8_t ws_frame[4096];
    size_t frame_len = build_ws_frame(json, ws_frame, sizeof(ws_frame));
    if (!frame_len) return (uint64_t)-1;
    mem_write(pid, data_buf, ws_frame, frame_len);
    uint64_t wr = exec_syscall_in_target(pid, regs, syscall_gadget,
        SYS_write, (uint64_t)sv_fd, data_buf, (uint64_t)frame_len, 0, 0, 0);
    ptrace(PTRACE_SETREGS, pid, NULL, regs);
    return wr;
}

/* Read and parse WS response from sv_fd. Skips WS frame header.
 * Writes JSON payload into resp_buf. Returns payload length, or negative on error. */
static int64_t read_ws_response(pid_t pid, struct user_regs_struct *regs,
                                 uint64_t syscall_gadget, int sv_fd,
                                 uint64_t rd_buf, char *resp_buf, size_t resp_size)
{
    uint64_t rr = exec_syscall_in_target(pid, regs, syscall_gadget,
        SYS_read, (uint64_t)sv_fd, rd_buf, 4096, 0, 0, 0);
    ptrace(PTRACE_SETREGS, pid, NULL, regs);
    if ((int64_t)rr <= 0) return (int64_t)rr;
    size_t total = (size_t)rr;
    char raw[4096];
    memset(raw, 0, sizeof(raw));
    size_t to_read = total;
    if (to_read > sizeof(raw) - 1) to_read = sizeof(raw) - 1;
    mem_read(pid, rd_buf, raw, to_read);
    raw[to_read] = 0;
    /* Skip WS frame header */
    char *json = raw;
    if (to_read >= 2) {
        size_t skip = 2;
        unsigned char len_byte = (unsigned char)raw[1] & 0x7f;
        if (len_byte == 126) skip = 4;
        else if (len_byte == 127) skip = 10;
        if (skip < to_read) json = raw + skip;
    }
    size_t json_len = strlen(json);
    if (json_len >= resp_size) json_len = resp_size - 1;
    memcpy(resp_buf, json, json_len);
    resp_buf[json_len] = 0;
    return (int64_t)json_len;
}

/* Find "callFrameId":N in a JSON string. Returns N, or -1 if not found. */
static int find_call_frame_id(const char *json)
{
    const char *p = strstr(json, "\"callFrameId\":");
    if (!p) p = strstr(json, "\"callFrameId\" :");
    if (!p) return -1;
    p = strchr(p + 14, ':');
    if (!p) return -1;
    p++;
    while (*p == ' ') p++;
    if (*p == '"') p++; /* skip opening quote for string format */
    return atoi(p);
}

/* Find the objectId of the "module" scope from a Debugger.paused JSON.
 * Returns -1 if not found. */
static int find_module_scope_id(const char *json)
{
    /* Find "type":"module" in scopeChain */
    const char *mod = strstr(json, "\"type\":\"module\"");
    if (!mod) mod = strstr(json, "\"type\" : \"module\"");
    if (!mod) return -1;
    /* Find the next objectId after this point */
    const char *oid = strstr(mod, "\"objectId\":");
    if (!oid) oid = strstr(mod, "\"objectId\" :");
    if (!oid) return -1;
    oid = strchr(oid + 10, ':');
    if (!oid) return -1;
    oid++;
    while (*oid == ' ') oid++;
    if (*oid == '"') oid++;
    return atoi(oid);
}

/* Parse all WS text frames from a raw byte buffer, concatenate JSON payloads.
 * Returns total JSON bytes written to out_buf. */
static size_t parse_ws_frames(const uint8_t *raw, size_t raw_len,
                               char *out_buf, size_t out_size)
{
    size_t out_pos = 0;
    size_t i = 0;
    while (i < raw_len && out_pos < out_size - 1) {
        if (i + 2 > raw_len) break;
        /* Skip FIN+opcode byte */
        i++;
        /* Payload length */
        uint8_t len_byte = raw[i] & 0x7f;
        i++;
        size_t payload_len;
        if (len_byte < 126) {
            payload_len = len_byte;
        } else if (len_byte == 126) {
            if (i + 2 > raw_len) break;
            payload_len = ((size_t)raw[i] << 8) | raw[i + 1];
            i += 2;
        } else {
            if (i + 8 > raw_len) break;
            payload_len = 0;
            for (int b = 0; b < 8; b++)
                payload_len = (payload_len << 8) | raw[i + b];
            i += 8;
        }
        /* Server→client frames are NOT masked */
        if (i + payload_len > raw_len) {
            payload_len = raw_len - i;
        }
        /* Copy payload to output */
        size_t copy = payload_len;
        if (out_pos + copy >= out_size) copy = out_size - 1 - out_pos;
        memcpy(out_buf + out_pos, raw + i, copy);
        out_pos += copy;
        i += payload_len;
    }
    out_buf[out_pos] = 0;
    return out_pos;
}

/* Detach, sleep, re-attach. Returns 0 on success, -1 on failure.
 * Fills running_regs with current state after re-attach. */
static int detach_wait_reattach(pid_t pid, int usec,
                                 struct user_regs_struct *running_regs, int *status)
{
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    usleep((useconds_t)usec);
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) return -1;
    waitpid(pid, status, 0);
    if (!WIFSTOPPED(*status)) return -1;
    ptrace(PTRACE_GETREGS, pid, NULL, running_regs);
    return 0;
}

/* ---------- main ---------- */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    fprintf(stderr, "[DBG-INJECT] === Ark Inspector Debugger Injector ===\n");
    fprintf(stderr, "[DBG-INJECT] PID=%d\n", pid);

    /* ====== Step 1: ptrace ATTACH ====== */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) die("ATTACH");
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) {
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    fprintf(stderr, "[DBG-INJECT] Attached (stopped by signal %d)\n", WSTOPSIG(status));

    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) < 0) die("GETREGS");
    fprintf(stderr, "[DBG-INJECT] orig RIP=0x%lx RSP=0x%lx\n",
            (unsigned long)orig_regs.rip, (unsigned long)orig_regs.rsp);

    /* ====== Step 2: Find gadgets ====== */
    /* We need:
     * - A "syscall" instruction (0x0F 0x05) in an r-xp mapping for syscalls
     * - A "call rax" instruction (0xFF 0xD0) for function calls
     * Search in large libraries like libc.so or libark_jsruntime.so
     */
    struct module_info libc_mod, jsrt_mod, ld_mod;
    uint64_t syscall_gadget = 0;
    uint64_t call_rax_gadget = 0;

    /* Also search for a "call rax; int3" or "call rax; ret" in ALL r-xp segments.
     * We search more aggressively through the target's maps. */
    const char *gadget_libs[] = {
        "libark_jsruntime.so", "libark_tooling.so", "libark_inspector",
        "libark_connect_inspector", "ld-musl", NULL
    };

    for (int i = 0; gadget_libs[i]; i++) {
        struct module_info m;
        if (find_module(pid, gadget_libs[i], &m) < 0) continue;
        fprintf(stderr, "[DBG-INJECT] Searching %s: rx=[0x%lx-0x%lx]\n",
                gadget_libs[i], (unsigned long)m.rx_start, (unsigned long)m.rx_end);

        if (!syscall_gadget)
            syscall_gadget = find_syscall_gadget(pid, m.rx_start, m.rx_end);
        if (!call_rax_gadget)
            call_rax_gadget = find_call_rax_gadget(pid, m.rx_start, m.rx_end);

        if (syscall_gadget && call_rax_gadget) break;
    }

    if (!syscall_gadget) {
        fprintf(stderr, "[DBG-INJECT-ERR] No syscall gadget found\n");
        goto fail;
    }
    if (!call_rax_gadget) {
        fprintf(stderr, "[DBG-INJECT-ERR] No call rax gadget found\n");
        goto fail;
    }
    fprintf(stderr, "[DBG-INJECT] syscall gadget=0x%lx  call rax gadget=0x%lx\n",
            (unsigned long)syscall_gadget, (unsigned long)call_rax_gadget);

    /* ====== Step 3: Find rw-p memory for our data (sv[2]) ====== */
    /* On OHOS, musl libc is ld-musl-*.so — use its rw-p segment */
    if (find_module(pid, "ld-musl", &ld_mod) < 0 || !ld_mod.rw_start) {
        /* Fallback: use libark_jsruntime rw-p */
        if (find_module(pid, "libark_jsruntime.so", &libc_mod) < 0 || !libc_mod.rw_start) {
            fprintf(stderr, "[DBG-INJECT-ERR] No rw-p segment found\n");
            goto fail;
        }
    } else {
        libc_mod = ld_mod;
    }
    /* Use end of rw-p segment (less likely to be in active use) */
    uint64_t data_area = libc_mod.rw_end - 256;
    fprintf(stderr, "[DBG-INJECT] Data area at 0x%lx (in rw-p)\n", (unsigned long)data_area);

    /* ====== Step 4: mmap for code and data ====== */
    /* Allocate RW memory first, write shellcode, then mprotect to RX */
    fprintf(stderr, "[DBG-INJECT] Executing mmap syscall (RW)...\n");
    uint64_t mmap_addr = exec_syscall_in_target(pid, &orig_regs, syscall_gadget,
        SYS_mmap,        /* rax = 9 */
        0,               /* rdi = NULL */
        0x4000,          /* rsi = 16384 (four pages: code + data) */
        3,               /* rdx = PROT_READ|PROT_WRITE */
        0x22,            /* r10 = MAP_PRIVATE|MAP_ANONYMOUS */
        (uint64_t)-1,    /* r8 = -1 */
        0                /* r9 = 0 */
    );

    /* Restore orig regs for next use */
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);

    if (!mmap_addr || mmap_addr == (uint64_t)-1) {
        fprintf(stderr, "[DBG-INJECT-ERR] mmap failed: 0x%lx\n", (unsigned long)mmap_addr);
        goto fail;
    }
    fprintf(stderr, "[DBG-INJECT] mmap returned 0x%lx\n", (unsigned long)mmap_addr);

    /* ====== Step 5: socketpair(AF_UNIX, SOCK_STREAM, 0, sv) ====== */
    /* sv array is at mmap_addr */
    int sv_init[2] = { -1, -1 };
    mem_write(pid, mmap_addr, sv_init, sizeof(sv_init));

    fprintf(stderr, "[DBG-INJECT] Executing socketpair syscall...\n");
    uint64_t sp_result = exec_syscall_in_target(pid, &orig_regs, syscall_gadget,
        53,              /* SYS_socketpair */
        1,               /* AF_UNIX */
        1,               /* SOCK_STREAM */
        0,               /* protocol */
        mmap_addr,       /* sv array addr (r10 used as 4th param on x86_64) */
        (uint64_t)-1, 0
    );

    /* Restore regs */
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);

    if ((int64_t)sp_result < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] socketpair failed: %ld\n", (long)(int64_t)sp_result);
        goto fail;
    }
    fprintf(stderr, "[DBG-INJECT] socketpair returned %ld\n", (long)(int64_t)sp_result);

    int sv[2];
    if (mem_read(pid, mmap_addr, sv, sizeof(sv)) < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] Failed to read sv array\n");
        goto fail;
    }
    fprintf(stderr, "[DBG-INJECT] sv[0]=%d  sv[1]=%d\n", sv[0], sv[1]);

    if (sv[0] < 0 || sv[1] < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] Invalid socket fds\n");
        goto fail;
    }

    /* ====== Step 6: Find libark_inspector.z.so ====== */
    /* We use hardcoded VA offsets (verified by disassembly) instead of runtime symbol resolution */
    struct module_info inspector_mod;
    if (find_module(pid, "libark_inspector.z.so", &inspector_mod) < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] libark_inspector.z.so not found\n");
        goto fail;
    }
    fprintf(stderr, "[DBG-INJECT] libark_inspector.z.so base=0x%lx\n",
            (unsigned long)inspector_mod.base);

    /* ====== Step 7.5: Get EcmaVM pointer ====== */
    /* InitializeDebuggerForSocketpair(void* vm) needs an EcmaVM pointer.
     * We can get it by calling GetEcmaVM(int tid) from libark_inspector.z.so */
    uint64_t get_vm_fn = resolve_symbol(pid, &inspector_mod,
                                         "_ZN4OHOS11ArkCompiler9Toolchain9GetEcmaVMEi");
    if (!get_vm_fn) {
        fprintf(stderr, "[DBG-INJECT-ERR] GetEcmaVM not found\n");
        goto fail;
    }
    fprintf(stderr, "[DBG-INJECT] GetEcmaVM at 0x%lx\n", (unsigned long)get_vm_fn);

    /* Call GetEcmaVM(pid) via call_rax gadget */
    fprintf(stderr, "[DBG-INJECT] Calling GetEcmaVM(%d)...\n", pid);
    uint64_t vm_ptr = exec_call1_in_target(pid, &orig_regs, call_rax_gadget,
                                            get_vm_fn, (uint64_t)pid);
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    fprintf(stderr, "[DBG-INJECT] GetEcmaVM returned vm_ptr=0x%lx\n", (unsigned long)vm_ptr);

    if (!vm_ptr || vm_ptr == (uint64_t)-1) {
        fprintf(stderr, "[DBG-INJECT-ERR] GetEcmaVM returned NULL or error — VM not registered?\n");
        fprintf(stderr, "[DBG-INJECT-ERR] App may not have been started with -D flag, or StoreDebuggerInfo was not called\n");
        goto fail;
    }

    /* ====== Step 8: Plan A — Preset global function pointers to bypass dlopen/dlsym ====== */
    /*
     * InitializeDebuggerForSocketpair(vm) internally:
     *   1. Checks g_handle (TLS via emutls at VA 0x15be0) — if NULL, calls dlopen → CRASH
     *   2. Checks g_hasArkFuncsInited (byte at VA 0x15dd0) — if 1, skip dlsym
     *   3. Calls g_initializeDebugger(vm, callback) — actual init
     *
     * Plan A: Preset all 6 function pointers + g_hasArkFuncsInited = 1,
     * then use shellcode to set g_handle (TLS) via __emutls_get_address,
     * then call StartDebugForSocketpair(tid, socketfd) which handles the full flow.
     */

    /* Find libark_tooling.so */
    struct module_info tooling_mod;
    if (find_module(pid, "libark_tooling.so", &tooling_mod) < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] libark_tooling.so not loaded\n");
        goto fail;
    }
    fprintf(stderr, "[DBG-INJECT] libark_tooling.so base=0x%lx\n",
            (unsigned long)tooling_mod.base);

    /* Resolve 6 functions from libark_tooling.so and write to globals in libark_inspector.z.so.
     * These are the functions that InitializeArkFunctions() would resolve via dlsym.
     * NOTE: resolve_symbol has a GNU hash bug for large symbol tables (index > ~1000),
     * so we use hardcoded VA offsets verified by static analysis of the device library. */
    struct {
        const char *name;
        uint64_t tooling_va;  /* VA offset in libark_tooling.so (st_value) */
        uint64_t global_va;   /* VA offset in libark_inspector.z.so where pointer is stored */
    } func_table[] = {
        { "InitializeDebugger",    0x9a7e0, 0x15db8 },
        { "UninitializeDebugger",  0x9ac20, 0x15dc8 },
        { "WaitForDebugger",       0x9aef0, 0x15dc0 },
        { "OnMessage",             0x9b070, 0x15d68 },
        { "GetDispatchStatus",     0x9b370, 0x15d70 },
        { "ProcessMessage",        0x9b1f0, 0x15dd8 },
    };

    for (int i = 0; i < 6; i++) {
        /* First try resolve_symbol (works for early symbols), fallback to hardcoded offset */
        uint64_t fn_addr = resolve_symbol(pid, &tooling_mod, func_table[i].name);
        if (!fn_addr) {
            fn_addr = tooling_mod.base + func_table[i].tooling_va;
            fprintf(stderr, "[DBG-INJECT] %s: resolve_symbol failed, using hardcoded offset 0x%lx -> 0x%lx\n",
                    func_table[i].name, (unsigned long)func_table[i].tooling_va, (unsigned long)fn_addr);
        }
        uint64_t target = inspector_mod.base + func_table[i].global_va;
        if (mem_write(pid, target, &fn_addr, 8) < 0) {
            fprintf(stderr, "[DBG-INJECT-ERR] Failed to write %s ptr to 0x%lx\n",
                    func_table[i].name, (unsigned long)target);
            goto fail;
        }
        fprintf(stderr, "[DBG-INJECT] %s = 0x%lx -> global[0x%lx]\n",
                func_table[i].name, (unsigned long)fn_addr,
                (unsigned long)func_table[i].global_va);
    }

    /* Set g_hasArkFuncsInited = 1 (byte at VA 0x15dd0) */
    {
        uint8_t init_flag = 1;
        uint64_t flag_addr = inspector_mod.base + 0x15dd0;
        if (mem_write(pid, flag_addr, &init_flag, 1) < 0) {
            fprintf(stderr, "[DBG-INJECT-ERR] Failed to set g_hasArkFuncsInited\n");
            goto fail;
        }
        fprintf(stderr, "[DBG-INJECT] Set g_hasArkFuncsInited = 1 at 0x%lx\n",
                (unsigned long)flag_addr);
    }

    /* Verify writes */
    fprintf(stderr, "[DBG-INJECT] Verifying global writes...\n");
    for (int i = 0; i < 6; i++) {
        uint64_t val;
        uint64_t addr = inspector_mod.base + func_table[i].global_va;
        mem_read(pid, addr, &val, 8);
        fprintf(stderr, "[DBG-INJECT]   global[0x%lx] = 0x%lx (%s) %s\n",
                (unsigned long)func_table[i].global_va, (unsigned long)val,
                func_table[i].name, val ? "OK" : "ZERO!");
    }

    /* ====== Step 9: mprotect code page to RX ====== */
    fprintf(stderr, "[DBG-INJECT] mprotect code page to RX...\n");
    uint64_t mprotect_result = exec_syscall_in_target(pid, &orig_regs, syscall_gadget,
        SYS_mprotect, mmap_addr, 0x1000, 5, 0, 0, 0);
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    fprintf(stderr, "[DBG-INJECT] mprotect returned %ld\n", (long)(int64_t)mprotect_result);

    if ((int64_t)mprotect_result < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] mprotect failed\n");
        goto fail;
    }

    /* ====== Step 10: Build shellcode ====== */
    /*
     * Shellcode does:
     *   sub rsp, 16                    ; align stack to 16 bytes
     *   ; --- Set g_handle (TLS) to non-NULL ---
     *   mov rdi, <emutls_g_handle>     ; arg = emutls control struct addr
     *   mov rax, <__emutls_get_address_plt>
     *   call rax                       ; rax = &g_handle (TLS variable)
     *   mov qword [rax], 1             ; g_handle = 1 (skip dlopen)
     *   ; --- Call StartDebugForSocketpair(pid, sv[0]) ---
     *   mov edi, <pid>                 ; arg1 = tid (int32)
     *   mov esi, <sv[0]>               ; arg2 = socketfd (int32)
     *   mov rax, <StartDebugForSocketpair>
     *   call rax                       ; returns bool
     *   ; --- done ---
     *   add rsp, 16
     *   int3                           ; break back to ptrace
     *
     * StartDebugForSocketpair internally calls:
     *   GetEcmaVM(tid) → vm
     *   g_vm = vm (emutls store)
     *   InitializeDebuggerForSocketpair(vm) → skips dlopen+dlsym → calls g_initializeDebugger
     *   GetDebuggerPostTask(tid) → postTask
     *   Creates WsServer + pthread_create → WebSocket server on sv[0]
     */
    {
        uint64_t emutls_plt = inspector_mod.base + 0x13280;   /* __emutls_get_address@plt */
        uint64_t emutls_control = inspector_mod.base + 0x15be0; /* emutls control for g_handle */
        uint64_t start_debug_fn = inspector_mod.base + 0xb4b0; /* StartDebugForSocketpair */

        fprintf(stderr, "[DBG-INJECT] __emutls_get_address@plt = 0x%lx\n", (unsigned long)emutls_plt);
        fprintf(stderr, "[DBG-INJECT] emutls control (g_handle) = 0x%lx\n", (unsigned long)emutls_control);
        fprintf(stderr, "[DBG-INJECT] StartDebugForSocketpair = 0x%lx\n", (unsigned long)start_debug_fn);

        uint8_t shellcode[256];
        size_t sc_len = 0;

        /* sub rsp, 16 */
        shellcode[sc_len++] = 0x48; shellcode[sc_len++] = 0x83;
        shellcode[sc_len++] = 0xEC; shellcode[sc_len++] = 0x10;

        /* mov rdi, <emutls_control> (imm64) */
        shellcode[sc_len++] = 0x48; shellcode[sc_len++] = 0xBF;
        memcpy(shellcode + sc_len, &emutls_control, 8); sc_len += 8;

        /* mov rax, <emutls_plt> (imm64) */
        shellcode[sc_len++] = 0x48; shellcode[sc_len++] = 0xB8;
        memcpy(shellcode + sc_len, &emutls_plt, 8); sc_len += 8;

        /* call rax — __emutls_get_address(emutls_control) → rax = &g_handle */
        shellcode[sc_len++] = 0xFF; shellcode[sc_len++] = 0xD0;

        /* mov qword [rax], 1 — set g_handle = (void*)1 */
        shellcode[sc_len++] = 0x48; shellcode[sc_len++] = 0xC7;
        shellcode[sc_len++] = 0x00; shellcode[sc_len++] = 0x01;
        shellcode[sc_len++] = 0x00; shellcode[sc_len++] = 0x00;
        shellcode[sc_len++] = 0x00;

        /* mov edi, <pid> (imm32) */
        shellcode[sc_len++] = 0xBF;
        uint32_t pid32 = (uint32_t)pid;
        memcpy(shellcode + sc_len, &pid32, 4); sc_len += 4;

        /* mov esi, <sv[0]> (imm32) */
        shellcode[sc_len++] = 0xBE;
        uint32_t sv0_32 = (uint32_t)sv[0];
        memcpy(shellcode + sc_len, &sv0_32, 4); sc_len += 4;

        /* mov rax, <start_debug_fn> (imm64) */
        shellcode[sc_len++] = 0x48; shellcode[sc_len++] = 0xB8;
        memcpy(shellcode + sc_len, &start_debug_fn, 8); sc_len += 8;

        /* call rax — StartDebugForSocketpair(pid, sv[0]) */
        shellcode[sc_len++] = 0xFF; shellcode[sc_len++] = 0xD0;

        /* add rsp, 16 */
        shellcode[sc_len++] = 0x48; shellcode[sc_len++] = 0x83;
        shellcode[sc_len++] = 0xC4; shellcode[sc_len++] = 0x10;

        /* int3 */
        shellcode[sc_len++] = 0xCC;

        mem_write(pid, mmap_addr, shellcode, sc_len);

        /* Verify shellcode */
        uint8_t verify[256];
        mem_read(pid, mmap_addr, verify, sc_len);
        fprintf(stderr, "[DBG-INJECT] Shellcode at 0x%lx (%zu bytes): ",
                (unsigned long)mmap_addr, sc_len);
        for (size_t i = 0; i < sc_len; i++) fprintf(stderr, "%02x ", verify[i]);
        fprintf(stderr, "\n");

        /* Set RIP to shellcode, set orig_rax = -1 */
        struct user_regs_struct run_regs = orig_regs;
        run_regs.rip = mmap_addr;
        run_regs.orig_rax = (uint64_t)-1;
        run_regs.rsp = (orig_regs.rsp - 512) & ~0xFULL; /* plenty of stack space */

        if (ptrace(PTRACE_SETREGS, pid, NULL, &run_regs) < 0) {
            fprintf(stderr, "[DBG-INJECT-ERR] SETREGS for shellcode: %s\n", strerror(errno));
            goto fail;
        }

        /* Verify */
        struct user_regs_struct check_regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &check_regs);
        fprintf(stderr, "[DBG-INJECT] Verify: RIP=0x%lx RSP=0x%lx\n",
                (unsigned long)check_regs.rip, (unsigned long)check_regs.rsp);

        fprintf(stderr, "[DBG-INJECT] Executing shellcode under ptrace...\n");
        if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) {
            fprintf(stderr, "[DBG-INJECT-ERR] CONT: %s\n", strerror(errno));
            goto fail;
        }

        int sc_status;
        waitpid(pid, &sc_status, 0);
        int sc_sig = WIFSTOPPED(sc_status) ? WSTOPSIG(sc_status) : -1;
        fprintf(stderr, "[DBG-INJECT] Shellcode stopped: status=0x%x sig=%d\n", sc_status, sc_sig);

        int cdp_ok = 0;
        if (WIFSTOPPED(sc_status) && sc_sig == SIGTRAP) {
            struct user_regs_struct sc_regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &sc_regs);
            fprintf(stderr, "[DBG-INJECT] After shellcode: RIP=0x%lx RAX=0x%lx\n",
                    (unsigned long)sc_regs.rip, (unsigned long)sc_regs.rax);
            if (sc_regs.rax == 0) {
                fprintf(stderr, "[DBG-INJECT-WARN] StartDebugForSocketpair returned FALSE\n");
            } else {
                fprintf(stderr, "[DBG-INJECT] StartDebugForSocketpair returned 0x%lx — assuming success!\n",
                        (unsigned long)sc_regs.rax);
                cdp_ok = 1;
            }
        } else if (WIFSTOPPED(sc_status) && sc_sig == SIGSEGV) {
            struct user_regs_struct crash_regs;
            ptrace(PTRACE_GETREGS, pid, NULL, &crash_regs);
            fprintf(stderr, "[DBG-INJECT-ERR] SIGSEGV at RIP=0x%lx RSP=0x%lx\n",
                    (unsigned long)crash_regs.rip, (unsigned long)crash_regs.rsp);
        }

        /* ====== Step 10.5: CDP Communication via ptrace syscall on sv[1] ====== */
        if (cdp_ok) {
            /* Data buffers in mmap second page (still RW) */
            uint64_t data_buf = mmap_addr + 0x2000;  /* write buffer: 0x2000 */
            uint64_t rd_buf   = mmap_addr + 0x3000;  /* read buffer: 0x3000 */

            /* Wait for Inspector server thread to initialize */
            fprintf(stderr, "[DBG-INJECT] Waiting 500ms for Inspector server thread...\n");
            usleep(500000);

            /* --- WebSocket Handshake --- */
            const char ws_hs[] =
                "GET /ws HTTP/1.1\r\n"
                "Host: localhost\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
                "Sec-WebSocket-Version: 13\r\n"
                "\r\n";
            size_t hs_len = strlen(ws_hs);
            mem_write(pid, data_buf, ws_hs, hs_len + 1);

            fprintf(stderr, "[DBG-INJECT] Sending WebSocket handshake (%zu bytes) to sv[1]=%d...\n",
                    hs_len, sv[1]);
            uint64_t wr = exec_syscall_in_target(pid, &orig_regs, syscall_gadget,
                SYS_write, (uint64_t)sv[1], data_buf, (uint64_t)hs_len, 0, 0, 0);
            ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
            fprintf(stderr, "[DBG-INJECT] write(handshake) returned %ld\n", (long)(int64_t)wr);

            if ((int64_t)wr > 0) {
                /* Read handshake response */
                uint64_t rr = exec_syscall_in_target(pid, &orig_regs, syscall_gadget,
                    SYS_read, (uint64_t)sv[1], rd_buf, 2048, 0, 0, 0);
                ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
                fprintf(stderr, "[DBG-INJECT] read(response) returned %ld\n", (long)(int64_t)rr);

                if ((int64_t)rr > 0) {
                    char resp[2048];
                    memset(resp, 0, sizeof(resp));
                    size_t to_read = (size_t)rr;
                    if (to_read > sizeof(resp) - 1) to_read = sizeof(resp) - 1;
                    mem_read(pid, rd_buf, resp, to_read);
                    resp[to_read] = 0;
                    fprintf(stderr, "[DBG-INJECT] WS Response:\n%s\n", resp);

                    if (strstr(resp, "101")) {
                        fprintf(stderr, "[DBG-INJECT] WebSocket handshake OK!\n");

                        /* --- Set sv[1] to non-blocking mode --- */
                        fprintf(stderr, "[DBG-INJECT] Setting sv[1]=%d to O_NONBLOCK...\n", sv[1]);
                        {
                            uint64_t fcntl_ret = exec_syscall_in_target(pid, &orig_regs,
                                syscall_gadget,
                                72, (uint64_t)sv[1], 4, 0x800, 0, 0, 0);
                            ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
                            fprintf(stderr, "[DBG-INJECT] fcntl(O_NONBLOCK) returned %ld\n",
                                    (long)(int64_t)fcntl_ret);
                        }

                        /* --- Phase 1: Enable domains + Pause --- */
                        /* The dynamic dispatcher only supports Debugger.evaluateOnCallFrame,
                         * NOT Runtime.evaluate. We must pause the debugger first. */
                        {
                            uint64_t wr;
                            fprintf(stderr, "[DBG-INJECT] === Phase 1: Enable + Pause ===\n");
                            wr = send_cdp(pid, &orig_regs, syscall_gadget, sv[1],
                                          data_buf, "{\"id\":1,\"method\":\"Runtime.enable\"}");
                            fprintf(stderr, "[DBG-INJECT] Runtime.enable → write %ld\n", (long)(int64_t)wr);

                            wr = send_cdp(pid, &orig_regs, syscall_gadget, sv[1],
                                          data_buf, "{\"id\":2,\"method\":\"Debugger.enable\"}");
                            fprintf(stderr, "[DBG-INJECT] Debugger.enable → write %ld\n", (long)(int64_t)wr);

                            wr = send_cdp(pid, &orig_regs, syscall_gadget, sv[1],
                                          data_buf, "{\"id\":3,\"method\":\"Debugger.pause\"}");
                            fprintf(stderr, "[DBG-INJECT] Debugger.pause → write %ld\n", (long)(int64_t)wr);

                            wr = send_cdp(pid, &orig_regs, syscall_gadget, sv[1],
                                          data_buf, "{\"id\":10,\"method\":\"Runtime.runIfWaitingForDebugger\"}");
                            fprintf(stderr, "[DBG-INJECT] Runtime.runIfWaitingForDebugger → write %ld\n", (long)(int64_t)wr);
                        }

                        /* Detach: let main thread process CDP commands and potentially pause */
                        fprintf(stderr, "[DBG-INJECT] Detaching for pause processing (5s)...\n");
                        {
                            struct user_regs_struct rr;
                            if (detach_wait_reattach(pid, 5000000, &rr, &status) < 0) {
                                fprintf(stderr, "[DBG-INJECT-ERR] Re-attach after pause failed\n");
                                goto done;
                            }
                            fprintf(stderr, "[DBG-INJECT] Re-attached. RIP=0x%lx\n", (unsigned long)rr.rip);
                        }

                        /* --- Phase 2: Drain responses, find callFrameId --- */
                        fprintf(stderr, "[DBG-INJECT] === Phase 2: Read pause responses ===\n");
                        {
                            struct user_regs_struct running_regs;
                            ptrace(PTRACE_GETREGS, pid, NULL, &running_regs);

                            /* Drain all pending WS messages with multi-frame parsing */
                            char all_json[16384];
                            memset(all_json, 0, sizeof(all_json));
                            size_t all_json_len = 0;
                            int call_frame_id = -1;

                            for (int drain = 0; drain < 10; drain++) {
                                /* Read raw bytes from sv[1] */
                                uint64_t rr = exec_syscall_in_target(pid, &running_regs,
                                    syscall_gadget,
                                    SYS_read, (uint64_t)sv[1], rd_buf, 8192, 0, 0, 0);
                                ptrace(PTRACE_SETREGS, pid, NULL, &running_regs);

                                if ((int64_t)rr <= 0) {
                                    fprintf(stderr, "[DBG-INJECT] Drain %d: read=%ld (done)\n",
                                            drain, (long)(int64_t)rr);
                                    break;
                                }

                                /* Parse all WS frames from this read */
                                uint8_t raw_buf[8192];
                                mem_read(pid, rd_buf, raw_buf, (size_t)rr);
                                char frame_json[8192];
                                size_t json_len = parse_ws_frames(raw_buf, (size_t)rr,
                                                                  frame_json, sizeof(frame_json));
                                fprintf(stderr, "[DBG-INJECT] Drain %d: %zu bytes raw → %zu json\n",
                                        drain, (size_t)rr, json_len);
                                if (json_len > 0) {
                                    fprintf(stderr, "[DBG-INJECT]   JSON: %s\n", frame_json);
                                    size_t copy = json_len;
                                    if (all_json_len + copy >= sizeof(all_json) - 1)
                                        copy = sizeof(all_json) - 1 - all_json_len;
                                    memcpy(all_json + all_json_len, frame_json, copy);
                                    all_json_len += copy;
                                    all_json[all_json_len] = 0;
                                }

                                /* Check for Debugger.paused event */
                                if (strstr(frame_json, "Debugger.paused")) {
                                    call_frame_id = find_call_frame_id(frame_json);
                                    fprintf(stderr, "[DBG-INJECT] ★ Debugger.paused! callFrameId=%d\n",
                                            call_frame_id);
                                }
                            }

                            fprintf(stderr, "[DBG-INJECT] All JSON responses:\n%s\n", all_json);

                            if (call_frame_id < 0) {
                                call_frame_id = find_call_frame_id(all_json);
                                if (call_frame_id >= 0) {
                                    fprintf(stderr, "[DBG-INJECT] ★ Found callFrameId=%d in combined\n",
                                            call_frame_id);
                                } else {
                                    fprintf(stderr, "[DBG-INJECT] No Debugger.paused event — debugger did not pause.\n");
                                    fprintf(stderr, "[DBG-INJECT] Will try evaluateOnCallFrame(0) anyway.\n");
                                }
                            }

                            char call_frame_id_str[16];
                            snprintf(call_frame_id_str, sizeof(call_frame_id_str), "%d",
                                     call_frame_id >= 0 ? call_frame_id : 0);

                            /* --- Phase 3: callFunctionOn with base64 Ark bytecode (.abc) ---
                             *
                             * Dynamic CDP dispatcher requires base64-encoded Ark bytecode,
                             * NOT JavaScript source strings. We pre-compile the monkey-patch
                             * to .abc via es2abc and embed the base64 here.
                             *
                             * Source (monkey_patch.js):
                             *   var _gm = globalThis.requireModuleAccess('@kit.LocationKit')
                             *             .geoLocationManager;
                             *   var _orig = _gm.getCurrentLocation;
                             *   _gm.getCurrentLocation = function(request) {
                             *     return new Promise(function(resolve, reject) {
                             *       _orig.call(_gm, request).then(function(loc) {
                             *         loc.latitude = 39.9087;
                             *         loc.longitude = 116.3975;
                             *         resolve(loc);
                             *       }).catch(function(e) { reject(e); });
                             *     });
                             *   };
                             */
                            fprintf(stderr, "[DBG-INJECT] === Phase 3: callFunctionOn (simple test) ===\n");
                            {
                                /* Simple test: just console.log + globalThis write */
                                const char abc_b64[] =
                                    "UEFOREEAAAAIexuiDAACAFgCAAAAAAAAAAAAAAMAAAA8AAAAAQAAAFQCAAABAAAASAAA"
                                    "AAEAAABMAAAA7gAAAB0BAABQAQAAxQEAAJwAAABYAgAABAAAAHQAAAAGAAAAhAAAAP//"
                                    "//////////////////8GAAAA7gAAAB0BAABQAQAAnAAAALEAAADKAAAA2QAAAOIAAADp"
                                    "AAAAJ1NJTVBMRV9URVNUOiBzdGVwPTEAL1NJTVBMRV9URVNUOiB0aGlzX3R5cGU9ABtf"
                                    "X1NJTVBMRV9URVNUAA9jb25zb2xlAAtoZWxsbwAHbG9nACNMX0VTTW9kdWxlUmVjb3Jk"
                                    "OwAAAAAAAQEAAgAAAQAAABoBAAAAAsUBAAAAA0MAM0xfRVNTbG90TnVtYmVyQW5ub3Rh"
                                    "dGlvbjsAAAAAAIFAAAACAAAXZnVuY19tYWluXzAAE0xfR0xPQkFMOwAAAAAAAQABAgAA"
                                    "AwD//0MBAACIAgH6AQAAAgAFSAIAAAbtAQAAAIMBQzovTWFzdGVyL0hhcm1vbnkvb3Bl"
                                    "bkhhcm1vbnkvc3lzX3ZlcmlmeS9pbmplY3QvdGVzdF9zaW1wbGVfdjMuanMABgAAAAA"
                                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABVTbG90TnVtYmVyAAIAAQDhAQAADwAAADcD"
                                    "A0MAbWEAPgQAQwACAAA/AgMAYQBCAwUAYQE+AQBhAmAFHAUKBwJhAmABLggAAj8KAwBh"
                                    "AEILBQBhAT4AAGECYAEuDQACZQkLAREBDQABAAWBAwArFwAAAABBAgAA";

                                char cdp_json[4800];
                                int cdp_len = snprintf(cdp_json, sizeof(cdp_json),
                                    "{\"id\":4,\"method\":\"Debugger.callFunctionOn\","
                                    "\"params\":{\"callFrameId\":\"%s\","
                                    "\"functionDeclaration\":\"%s\"}}",
                                    call_frame_id_str, abc_b64);

                                fprintf(stderr, "[DBG-INJECT] Sending callFunctionOn (%d bytes, abc_b64=%d)\n",
                                        cdp_len, (int)strlen(abc_b64));
                                uint64_t wr = send_cdp(pid, &running_regs, syscall_gadget,
                                                       sv[1], data_buf, cdp_json);
                                fprintf(stderr, "[DBG-INJECT] write → %ld\n", (long)(int64_t)wr);
                            }

                            /* Detach for evaluation */
                            fprintf(stderr, "[DBG-INJECT] Detaching for evaluation (3s)...\n");
                            if (detach_wait_reattach(pid, 3000000, &running_regs, &status) < 0) {
                                fprintf(stderr, "[DBG-INJECT-ERR] Re-attach after evaluate failed\n");
                                goto done;
                            }
                            fprintf(stderr, "[DBG-INJECT] Re-attached. RIP=0x%lx\n",
                                    (unsigned long)running_regs.rip);

                            /* Read evaluate response */
                            {
                                char eval_resp[4096];
                                int64_t rlen = read_ws_response(pid, &running_regs, syscall_gadget,
                                                                sv[1], rd_buf, eval_resp, sizeof(eval_resp));
                                fprintf(stderr, "[DBG-INJECT] evaluate response: %s\n",
                                        (rlen > 0) ? eval_resp : "(empty)");
                            }

                            /* --- Phase 4: Resume debugger --- */
                            fprintf(stderr, "[DBG-INJECT] === Phase 4: Resume ===\n");
                            {
                                uint64_t wr = send_cdp(pid, &running_regs, syscall_gadget, sv[1],
                                                       data_buf, "{\"id\":5,\"method\":\"Debugger.resume\"}");
                                fprintf(stderr, "[DBG-INJECT] Debugger.resume → write %ld\n", (long)(int64_t)wr);
                            }

                            /* --- Phase 4: Detach, wait for resume + second pause --- */
                            fprintf(stderr, "[DBG-INJECT] Detaching for resume + second pause (3s)...\n");
                            if (detach_wait_reattach(pid, 3000000, &running_regs, &status) < 0) {
                                fprintf(stderr, "[DBG-INJECT-WARN] Re-attach after resume failed\n");
                                goto done;
                            }
                            fprintf(stderr, "[DBG-INJECT] Re-attached. RIP=0x%lx\n",
                                    (unsigned long)running_regs.rip);

                            /* --- Phase 4.5: Drain responses, find second Debugger.paused --- */
                            fprintf(stderr, "[DBG-INJECT] === Phase 4.5: Drain + find second paused ===\n");
                            {
                                char all_resp[16384];
                                memset(all_resp, 0, sizeof(all_resp));
                                size_t all_resp_len = 0;
                                int second_cf_id = -1;

                                for (int drain = 0; drain < 15; drain++) {
                                    uint64_t rr = exec_syscall_in_target(pid, &running_regs,
                                        syscall_gadget,
                                        SYS_read, (uint64_t)sv[1], rd_buf, 8192, 0, 0, 0);
                                    ptrace(PTRACE_SETREGS, pid, NULL, &running_regs);

                                    if ((int64_t)rr <= 0) {
                                        if (drain < 3) continue;
                                        fprintf(stderr, "[DBG-INJECT] Drain %d: read=%ld (done)\n",
                                                drain, (long)(int64_t)rr);
                                        break;
                                    }

                                    uint8_t raw_buf[8192];
                                    mem_read(pid, rd_buf, raw_buf, (size_t)rr);
                                    char frame_json[8192];
                                    size_t json_len = parse_ws_frames(raw_buf, (size_t)rr,
                                                                      frame_json, sizeof(frame_json));
                                    fprintf(stderr, "[DBG-INJECT] Drain %d: %zu bytes -> %zu json\n",
                                            drain, (size_t)rr, json_len);
                                    if (json_len > 0) {
                                        fprintf(stderr, "[DBG-INJECT]   JSON: %s\n", frame_json);
                                        size_t copy = json_len;
                                        if (all_resp_len + copy >= sizeof(all_resp) - 1)
                                            copy = sizeof(all_resp) - 1 - all_resp_len;
                                        memcpy(all_resp + all_resp_len, frame_json, copy);
                                        all_resp_len += copy;
                                        all_resp[all_resp_len] = 0;
                                    }

                                    /* Look for second Debugger.paused (skip Debugger.resumed) */
                                    const char *paused_pos = strstr(frame_json, "\"Debugger.paused\"");
                                    if (paused_pos) {
                                        second_cf_id = find_call_frame_id(paused_pos);
                                        if (second_cf_id >= 0) {
                                            fprintf(stderr, "[DBG-INJECT] >> Second Debugger.paused! callFrameId=%d\n",
                                                    second_cf_id);
                                            break;
                                        }
                                    }
                                }

                                fprintf(stderr, "[DBG-INJECT] All Phase 4.5 responses:\n%s\n", all_resp);

                                /* --- Phase 5: Probe + monkey-patch at second pause --- */
                                if (second_cf_id >= 0) {
                                    char cf_id_str2[16];
                                    snprintf(cf_id_str2, sizeof(cf_id_str2), "%d", second_cf_id);

                                    /* Extract module scope objectId from second pause */
                                    int module_scope_id = find_module_scope_id(all_resp);
                                    fprintf(stderr, "[DBG-INJECT] Module scope objectId = %d\n", module_scope_id);
                                    char module_oid_str[16];
                                    snprintf(module_oid_str, sizeof(module_oid_str), "%d", module_scope_id);

                                    /* Phase 5a: Probe with evaluateOnCallFrame */
                                    fprintf(stderr, "[DBG-INJECT] === Phase 5a: evaluateOnCallFrame probes ===\n");
                                    {
                                        /* Probe 1: LocationUtil (imported in EntryAbility.ts) */
                                        char eval_cdp[512];
                                        snprintf(eval_cdp, sizeof(eval_cdp),
                                            "{\"id\":6,\"method\":\"Debugger.evaluateOnCallFrame\","
                                            "\"params\":{\"callFrameId\":\"%s\","
                                            "\"expression\":\"LocationUtil\"}}",
                                            cf_id_str2);
                                        send_cdp(pid, &running_regs, syscall_gadget,
                                                 sv[1], data_buf, eval_cdp);
                                        /* Probe 2: requireModuleAccess type */
                                        snprintf(eval_cdp, sizeof(eval_cdp),
                                            "{\"id\":61,\"method\":\"Debugger.evaluateOnCallFrame\","
                                            "\"params\":{\"callFrameId\":\"%s\","
                                            "\"expression\":\"typeof requireModuleAccess\"}}",
                                            cf_id_str2);
                                        send_cdp(pid, &running_regs, syscall_gadget,
                                                 sv[1], data_buf, eval_cdp);
                                        /* Probe 3: globalThis keys (first 80 chars) */
                                        snprintf(eval_cdp, sizeof(eval_cdp),
                                            "{\"id\":62,\"method\":\"Debugger.evaluateOnCallFrame\","
                                            "\"params\":{\"callFrameId\":\"%s\","
                                            "\"expression\":\"Object.keys(globalThis).join().substring(0,80)\"}}",
                                            cf_id_str2);
                                        send_cdp(pid, &running_regs, syscall_gadget,
                                                 sv[1], data_buf, eval_cdp);
                                    }
                                    /* Detach briefly for evaluation */
                                    if (detach_wait_reattach(pid, 2000000, &running_regs, &status) < 0) {
                                        fprintf(stderr, "[DBG-INJECT-ERR] Re-attach after evalOCF failed\n");
                                        goto done;
                                    }
                                    /* Drain all probe responses */
                                    {
                                        for (int drain = 0; drain < 10; drain++) {
                                            char eval_resp[4096];
                                            int64_t rlen = read_ws_response(pid, &running_regs, syscall_gadget,
                                                                            sv[1], rd_buf, eval_resp, sizeof(eval_resp));
                                            if (rlen > 0)
                                                fprintf(stderr, "[DBG-INJECT] evalOCF probe %d: %s\n", drain, eval_resp);
                                            else break;
                                        }
                                    }

                                    /* Phase 5b: callFunctionOn with v3 monkey-patch (globalThis.requireModuleAccess) */
                                    fprintf(stderr, "[DBG-INJECT] === Phase 5b: callFunctionOn (v3 patch) ===\n");
                                    {
                                        /* Monkey-patch v4: requireModuleAccess via scope filename (API 12) */
                                        /* Step 1: Minimal test - log + enumerate globalThis */
                                        /* Step 2: Explore requireNapi paths to geoLocationManager */
                                        /* Step 2: Monkey-patch geoLocationManager via requireNapi */
                                        /* Step 2b: defineProperty + Proxy fallback */
                                        /* Step 2c: defineProperty + Proxy (compact) */
                                        const char abc_b64_v2[] =
    "UEFOREEAAABJqf1CDAACAEQIAAAAAAAAAAAAAAMAAAA8AAAABQAAADAIAAABAAAASAAA"
    "AAEAAABMAAAAPQMAAGwDAACqAwAA5QQAAAABAABECAAABAAAAHQAAAAfAAAAhAAAAP//"
    "//////////////////8GAAAAPQMAAGwDAACqAwAAYQEAAGUBAAB+AQAAngEAAMABAADe"
    "AQAABQIAAB4CAAAyAgAAUwIAAHsCAACHAgAAjwIAAJoCAACoAgAArgIAALcCAADAAgAA"
    "ygIAAN4CAADyAgAABwMAABEDAAAWAwAAIQMAACoDAAA3AwAALwQAANsDAAD3AwAAEwQA"
    "AC8uIzEwNTU0NTA4MzgxMDgzNzc1OTczIwAtLiM0NjY2NjQ5MjkwMDAwNzYzNDk3IwAt"
    "LiM1Mjc3NTc1MTM1ODg4MjY3NzYyIwAtLiM1MzAzMDQxNjE1MzU0MjYyMjYxIwAFOiAA"
    "L01QX0g6IGNvcGllZCBwcm9wZXJ0eTogAD1NUF9IOiBmYWlsZWQgdG8gY29weSBwcm9w"
    "ZXJ0eSAAQU1QX0g6IGdldEN1cnJlbnRMb2NhdGlvbiBjYWxsZWQhADlNUF9IOiBob29r"
    "ZWQgb2JqZWN0IGNyZWF0ZWQhAEtNUF9IOiBpbnRlcmNlcHRlZCBnZW9Mb2NhdGlvbk1h"
    "bmFnZXIhAC9NUF9IOiBsb2NhdGlvbiBwYXRjaGVkIQAlTVBfSDogb3JpZ1JOIHNhdmVk"
    "AD9NUF9IOiByZXF1aXJlTmFwaSBjYWxsZWQgd2l0aDogAE1NUF9IOiByZXF1aXJlTmFw"
    "aSBob29rZWQgc3VjY2Vzc2Z1bGx5IQAVTVBfSF9FUlI6IAANT2JqZWN0ABNfX0dFT19F"
    "UlIAGV9fR0VPX0hPT0tFRAAJY2FsbAAPY29uc29sZQAPZm9yRWFjaAARZnVuY3Rpb24A"
    "JWdlb0xvY2F0aW9uTWFuYWdlcgAlZ2V0Q3VycmVudExvY2F0aW9uACdnZXRPd25Qcm9w"
    "ZXJ0eU5hbWVzABFsYXRpdHVkZQAHbG9nABNsb25naXR1ZGUAD21lc3NhZ2UAF3JlcXVp"
    "cmVOYXBpAAl0aGVuACNMX0VTTW9kdWxlUmVjb3JkOwAAAAAAAQEAAgAAAQAAAGkDAAAA"
    "AuUEAAAAA0MAM0xfRVNTbG90TnVtYmVyQW5ub3RhdGlvbjsAAAAAAIFAAAACAAAtIzEw"
    "NTU0NTA4MzgxMDgzNzc1OTczIwATTF9HTE9CQUw7AAAAAAABAAUCAAADAP//2AQAAIgC"
    "ARgHAAACAAUdCAAABkEFAAAAAwD//5MEAACIAgGNBQAAAgAFxwcAAAYaBQAAAAMA//+q"
    "BAAAiAIB/QUAAAIABegHAAAGJwUAAAADAP//wQQAAIgCAdIGAAACAAUBCAAABjQFAAAA"
    "AwD//5IDAACIAgFOBQAAAgAFtQcAAAYNBQAAAIsBQzovTWFzdGVyL0hhcm1vbnkvb3Bl"
    "bkhhcm1vbnkvc3lzX3ZlcmlmeS9pbmplY3QvbW9ua2V5X3BhdGNoX3Njb3BlLmpzACsj"
    "NDY2NjY0OTI5MDAwMDc2MzQ5NyMAKyM1Mjc3NTc1MTM1ODg4MjY3NzYyIwArIzUzMDMw"
    "NDE2MTUzNTQyNjIyNjEjABdmdW5jX21haW5fMAAGAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAFVNsb3ROdW1iZXIAAgABAAEFAAAJAAAANwIAAQABBQAAFAAAADcCAAEAAQUA"
    "ACcAAAA3AgABAAEFAAAOAAAANwIAAQABBQAAHQAAADcDBDsAYAYkUTVj4XoUrkfVhEBD"
    "ABUABmPXo3A9CseLQEMCFwAGPwQPAGEAQgUWAGEBPgYAYQJgAS4HAAJgBmQEBGYB1TwA"
    "YQE8EGECYAc3AAI4AgEHPwQPAGEBQgUWAGECPgEAYQNgBwoHA2EDYAIuCAEDTTVhAD8K"
    "DwBhAUILFgBhAj4CAGEDYAcKDQNhAz4AAAoOA2EDYABCDxgAChEDYQBgAi4SAQBlAS8B"
    "ADIAAwTQAQAJAwA9AAA9IAA9EDwBKgAGPRA/Ag8AYQBCAxYAYQE+CABhAmAGCgUCYQJg"
    "AS4GAAI+EgAoCAZhACRRBjwQYQBgACSbiwA8EEIJEwAcC2EAPhEAKA0AJFF3Pw4PAGEA"
    "Qg8WAGEBPgUAYQJgAS4RAAI8EEITEwA9IAQ9AD8VCwBhAEIWFABhATwQYQJgAS4YAAJh"
    "AEIaEABhATMcHAABYQJgAS4dAAI8AGEAMx8eAAFDIBMAAD8iDwBhAEIjFgBhAT4EAGEC"
    "YAEuJQACPABkPBBkAwRCAD8ADwBhAEIBFgBhAT4DAGECYAEuAwACPCBhAEIFDgBhATwQ"
    "YQJgAS8HAAIGYQBCCRoAYQEzCxsAAWECYAEuDAACZAQDigEB1QkBAD0AbUIAGQA9AD8C"
    "DwBhAUIDFgBhAj4HAGEDYAIuBQEDbWEBMwcdAAFDCBkAAT8KDwBhAUILFgBhAj4JAGED"
    "YAIuDQEDbWEBYgEAAABDDw0AAU00YQA/EQ8AYQFCEhYAYQI+CgBhA2AAQhQYAAoWA2ED"
    "YAIuFwEDbWEBYABCGRgAQxsMAAFlBk8BAFcACQtc4+MBEwAhAATLCAAXAAkLAREBES8B"
    "EgAWAAbLCAASIDEBCQu+egESAREBEotAARoBAhABETIeLwD/////DwAKywgAHigXKw4M"
    "FwIJCwERARgAHwAFywgAFyoDCQttewETAQIQARPzLwERAQIQAP////8PAArLCAAXDSoX"
    "Ig5HBACtBwAAvQcAANEHAAD6BwAACggAAA==";

                                        char cdp_json2[8192];
                                        int cdp_len2;
                                        if (module_scope_id >= 0) {
                                            cdp_len2 = snprintf(cdp_json2, sizeof(cdp_json2),
                                                "{\"id\":7,\"method\":\"Debugger.callFunctionOn\","
                                                "\"params\":{\"callFrameId\":\"%s\","
                                                "\"objectId\":\"%s\","
                                                "\"functionDeclaration\":\"%s\"}}",
                                                cf_id_str2, module_oid_str, abc_b64_v2);
                                        } else {
                                            cdp_len2 = snprintf(cdp_json2, sizeof(cdp_json2),
                                                "{\"id\":7,\"method\":\"Debugger.callFunctionOn\","
                                                "\"params\":{\"callFrameId\":\"%s\","
                                                "\"functionDeclaration\":\"%s\"}}",
                                                cf_id_str2, abc_b64_v2);
                                        }

                                        fprintf(stderr, "[DBG-INJECT] Sending callFunctionOn v3 (%d bytes)\n", cdp_len2);
                                        uint64_t wr2 = send_cdp(pid, &running_regs, syscall_gadget,
                                                               sv[1], data_buf, cdp_json2);
                                        fprintf(stderr, "[DBG-INJECT] write -> %ld\n", (long)(int64_t)wr2);
                                    }

                                    /* Detach for evaluation */
                                    fprintf(stderr, "[DBG-INJECT] Detaching for v3 evaluation (3s)...\n");
                                    if (detach_wait_reattach(pid, 3000000, &running_regs, &status) < 0) {
                                        fprintf(stderr, "[DBG-INJECT-ERR] Re-attach after v3 failed\n");
                                        goto done;
                                    }
                                    fprintf(stderr, "[DBG-INJECT] Re-attached. RIP=0x%lx\n",
                                            (unsigned long)running_regs.rip);

                                    /* Read v3 response */
                                    {
                                        char v2_resp[4096];
                                        int64_t rlen = read_ws_response(pid, &running_regs, syscall_gadget,
                                                                        sv[1], rd_buf, v2_resp, sizeof(v2_resp));
                                        fprintf(stderr, "[DBG-INJECT] v3 response: %s\n",
                                                (rlen > 0) ? v2_resp : "(empty)");
                                    }

                                    /* --- Phase 6: Final resume --- */
                                    fprintf(stderr, "[DBG-INJECT] === Phase 6: Final resume ===\n");
                                    {
                                        uint64_t wr3 = send_cdp(pid, &running_regs, syscall_gadget, sv[1],
                                                               data_buf, "{\"id\":8,\"method\":\"Debugger.resume\"}");
                                        fprintf(stderr, "[DBG-INJECT] Final resume -> write %ld\n", (long)(int64_t)wr3);
                                    }

                                    if (detach_wait_reattach(pid, 1000000, &running_regs, &status) < 0) {
                                        fprintf(stderr, "[DBG-INJECT-WARN] Re-attach after final resume failed\n");
                                    }
                                    {
                                        char fin_resp[4096];
                                        int64_t rlen = read_ws_response(pid, &running_regs, syscall_gadget,
                                                                        sv[1], rd_buf, fin_resp, sizeof(fin_resp));
                                        if (rlen > 0)
                                            fprintf(stderr, "[DBG-INJECT] Final response: %s\n", fin_resp);
                                    }

                                    /* --- Phase 7: Disable debugger to clean up --- */
                                    fprintf(stderr, "[DBG-INJECT] === Phase 7: Disable debugger ===\n");
                                    {
                                        send_cdp(pid, &running_regs, syscall_gadget, sv[1],
                                                 data_buf, "{\"id\":9,\"method\":\"Debugger.disable\"}");
                                        fprintf(stderr, "[DBG-INJECT] Debugger.disable sent\n");

                                        send_cdp(pid, &running_regs, syscall_gadget, sv[1],
                                                 data_buf, "{\"id\":10,\"method\":\"Runtime.disable\"}");
                                        fprintf(stderr, "[DBG-INJECT] Runtime.disable sent\n");
                                    }

                                    if (detach_wait_reattach(pid, 500000, &running_regs, &status) < 0) {
                                        fprintf(stderr, "[DBG-INJECT-WARN] Re-attach after disable failed\n");
                                    }
                                    {
                                        char dis_resp[4096];
                                        int64_t rlen = read_ws_response(pid, &running_regs, syscall_gadget,
                                                                        sv[1], rd_buf, dis_resp, sizeof(dis_resp));
                                        if (rlen > 0)
                                            fprintf(stderr, "[DBG-INJECT] Disable response: %s\n", dis_resp);
                                    }
                                } else {
                                    fprintf(stderr, "[DBG-INJECT] No second Debugger.paused found\n");
                                }
                            }
                        }
                    } else {
                        fprintf(stderr, "[DBG-INJECT-ERR] WebSocket handshake failed "
                                "(no 101 in response)\n");
                    }
                }
            }
        }
    }

done:
    /* ====== Step 11: Restore and detach ====== */
    fprintf(stderr, "[DBG-INJECT] Restoring registers and detaching...\n");
    /* If we went through detach/reattach, use orig_regs won't be correct.
     * Just detach — the thread was stopped in its normal event loop. */
    if (kill(pid, 0) < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] Process died during CDP communication!\n");
        return 1;
    }

    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] DETACH: %s\n", strerror(errno));
        return 1;
    }

    if (kill(pid, 0) < 0) {
        fprintf(stderr, "[DBG-INJECT-ERR] Process died after DETACH!\n");
        return 1;
    }
    fprintf(stderr, "[DBG-INJECT] Process alive after DETACH\n");

    fprintf(stderr, "[DBG-INJECT] === Done! ===\n");

    printf("OK\n");

    return 0;

fail:
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 1;
}
