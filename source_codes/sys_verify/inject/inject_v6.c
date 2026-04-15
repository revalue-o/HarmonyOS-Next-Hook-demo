/*
 * inject_v6 — PLT Hook (修改 PLT stub 而非 GOT)
 *
 * 与 v5 的区别:
 *   v5 修改 GOT 条目 (r--p 只读页, 可能被内核丢弃)
 *   v6 直接修改 PLT stub 代码 (r-xp 可执行页, 活跃使用中不易被丢弃)
 *
 * PLT stub 格式 (16 bytes):
 *   ff 25 xx xx xx xx   ; jmp [rip+disp32] → 读 GOT → 跳到原函数
 *   68 nn 00 00 00      ; push reloc_index (lazy binding fallback)
 *   e9 xx xx xx xx      ; jmp PLT[0] (resolver)
 *
 * 我们将其替换为:
 *   ff 25 00 00 00 00   ; jmp [rip+0] → 读紧接的 8 字节地址
 *   <hook_entry 8字节>  ; 直接跳到 hook, 不经过 GOT
 *   90 90               ; nop nop (对齐到 16)
 *
 * 编译:
 *   clang --target=x86_64-linux-ohos -O2 -o inject_v6 inject_v6.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/user.h>
#include <errno.h>
#include <stdint.h>
#include <elf.h>
#include <fcntl.h>

static double g_fake_lat = 666.66;
static double g_fake_lon = 888.88;

static void die(const char *msg)
{
    fprintf(stderr, "[INJECT-ERR] %s: %s\n", msg, strerror(errno));
    exit(1);
}

static int mem_write(pid_t pid, uint64_t addr, const void *data, size_t len)
{
    char path[64];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = pwrite(fd, data, len, (off_t)addr);
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

static uint64_t find_code_cave(pid_t pid, uint64_t rx_start, uint64_t rx_end, size_t needed)
{
    uint8_t buf[4096];
    for (uint64_t off = rx_end - sizeof(buf); off >= rx_start; off -= sizeof(buf)/2) {
        if (mem_read(pid, off, buf, sizeof(buf)) < 0) break;
        int consecutive = 0;
        for (int i = sizeof(buf) - 1; i >= 0; i--) {
            if (buf[i] == 0) {
                consecutive++;
                if ((size_t)consecutive >= needed + 32) {
                    uint64_t cave = off + i + 1;
                    return (cave + 15) & ~15ULL;
                }
            } else consecutive = 0;
        }
    }
    return 0;
}

static uint64_t find_got_entry(pid_t pid, struct module_info *mod, const char *func_name)
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
        if (*(uint32_t *)ph == 2) { dynamic_addr = base + *(uint64_t *)(ph + 16); break; }
    }
    if (!dynamic_addr) return 0;

    uint64_t strtab = 0, symtab = 0, jmprel = 0, pltrelsz = 0;
    for (int i = 0; i < 512; i++) {
        uint8_t dyn[16];
        if (mem_read(pid, dynamic_addr + i * 16, dyn, 16) < 0) break;
        int64_t tag = *(int64_t *)dyn;
        uint64_t val = *(uint64_t *)(dyn + 8);
        if (tag == 0) break;
        switch (tag) {
            case 5: strtab = base + val; break;
            case 6: symtab = base + val; break;
            case 23: jmprel = base + val; break;
            case 2: pltrelsz = val; break;
        }
    }
    if (!strtab || !symtab || !jmprel || !pltrelsz) return 0;

    int count = (int)(pltrelsz / 24);
    for (int i = 0; i < count; i++) {
        uint8_t rela[24];
        if (mem_read(pid, jmprel + i * 24, rela, 24) < 0) break;
        uint64_t r_offset = *(uint64_t *)rela;
        uint64_t r_info = *(uint64_t *)(rela + 8);
        uint32_t sym_idx = (uint32_t)(r_info >> 32);
        if ((r_info & 0xffffffff) != 7) continue;

        uint8_t sym[24];
        if (mem_read(pid, symtab + sym_idx * 24, sym, 24) < 0) break;
        char name[256];
        if (mem_read(pid, strtab + *(uint32_t *)sym, name, sizeof(name)) < 0) break;
        name[255] = 0;

        if (strcmp(name, func_name) == 0) {
            fprintf(stderr, "[INJECT] Found %s: GOT at base+0x%lx\n",
                    func_name, (unsigned long)r_offset);
            /* Return the GOT virtual address */
            return base + r_offset;
        }
    }
    return 0;
}

/*
 * 在 PLT 中找到跳转到指定 GOT 地址的 stub
 *
 * PLT stub 格式: ff 25 <rel32> (jmp [rip+rel32])
 * rel32 计算: target_GOT = stub_addr + 6 + rel32
 * 所以: rel32 = target_GOT - stub_addr - 6
 */
static uint64_t find_plt_stub(pid_t pid, struct module_info *mod, uint64_t got_addr)
{
    uint64_t rx_start = mod->rx_start;
    uint64_t rx_end = mod->rx_end;
    /* PLT 通常在代码段末尾, 但搜索整个 r-xp 段以确保找到 */
    uint64_t search_start = rx_start;

    size_t len = (size_t)(rx_end - search_start);
    uint8_t *buf = malloc(len);
    if (!buf) return 0;
    if (mem_read(pid, search_start, buf, len) < 0) { free(buf); return 0; }

    for (size_t i = 0; i <= len - 6; i++) {
        if (buf[i] == 0xff && buf[i+1] == 0x25) {
            int32_t rel = *(int32_t *)(buf + i + 2);
            uint64_t stub_addr = search_start + i;
            uint64_t target = stub_addr + 6 + (int64_t)rel;
            if (target == got_addr) {
                fprintf(stderr, "[INJECT] PLT stub at 0x%lx -> GOT 0x%lx\n",
                        (unsigned long)stub_addr, (unsigned long)got_addr);
                free(buf);
                return stub_addr;
            }
        }
    }
    free(buf);
    return 0;
}

/* Hook trampoline: 调用原函数 + 修改经纬度 */
static size_t build_hook_code(uint8_t *buf, uint64_t orig_func,
                               double fake_lat, double fake_lon)
{
    size_t idx = 0;
    memcpy(buf + idx, &orig_func, 8); idx += 8;
    memcpy(buf + idx, &fake_lat, 8);  idx += 8;
    memcpy(buf + idx, &fake_lon, 8);  idx += 8;

    size_t code_start = (idx + 15) & ~15ULL;
    idx = code_start;

    /* sub rsp, 0x78 */
    buf[idx++] = 0x48; buf[idx++] = 0x81; buf[idx++] = 0xEC;
    buf[idx++] = 0x78; buf[idx++] = 0x00; buf[idx++] = 0x00; buf[idx++] = 0x00;
    /* mov [rsp+0x08], rdi */
    buf[idx++] = 0x48; buf[idx++] = 0x89; buf[idx++] = 0x7C; buf[idx++] = 0x24; buf[idx++] = 0x08;
    /* mov [rsp+0x10], rsi */
    buf[idx++] = 0x48; buf[idx++] = 0x89; buf[idx++] = 0x74; buf[idx++] = 0x24; buf[idx++] = 0x10;
    /* mov rax, [rip+rel] -> orig_func */
    { size_t p = idx; buf[idx++] = 0x48; buf[idx++] = 0x8B; buf[idx++] = 0x05;
      int32_t rel = (int32_t)(0 - (int32_t)(p + 7));
      memcpy(buf + idx, &rel, 4); idx += 4; }
    /* call rax */
    buf[idx++] = 0xFF; buf[idx++] = 0xD0;
    /* mov rdi, [rsp+0x08] */
    buf[idx++] = 0x48; buf[idx++] = 0x8B; buf[idx++] = 0x7C; buf[idx++] = 0x24; buf[idx++] = 0x08;
    /* mov rax, [rip+rel] -> fake_lat */
    { size_t p = idx; buf[idx++] = 0x48; buf[idx++] = 0x8B; buf[idx++] = 0x05;
      int32_t rel = (int32_t)(8 - (int32_t)(p + 7));
      memcpy(buf + idx, &rel, 4); idx += 4; }
    /* mov [rdi], rax */
    buf[idx++] = 0x48; buf[idx++] = 0x89; buf[idx++] = 0x07;
    /* mov rax, [rip+rel] -> fake_lon */
    { size_t p = idx; buf[idx++] = 0x48; buf[idx++] = 0x8B; buf[idx++] = 0x05;
      int32_t rel = (int32_t)(16 - (int32_t)(p + 7));
      memcpy(buf + idx, &rel, 4); idx += 4; }
    /* mov [rdi+8], rax */
    buf[idx++] = 0x48; buf[idx++] = 0x89; buf[idx++] = 0x47; buf[idx++] = 0x08;
    /* add rsp, 0x78 */
    buf[idx++] = 0x48; buf[idx++] = 0x81; buf[idx++] = 0xC4;
    buf[idx++] = 0x78; buf[idx++] = 0x00; buf[idx++] = 0x00; buf[idx++] = 0x00;
    /* ret */
    buf[idx++] = 0xC3;
    return idx;
}

static size_t build_mmap_sc(uint8_t *buf)
{
    size_t len = 0;
    buf[len++] = 0x48; buf[len++] = 0xC7; buf[len++] = 0xC0; /* mov rax, 9 */
    buf[len++] = 0x09; buf[len++] = 0x00; buf[len++] = 0x00; buf[len++] = 0x00;
    buf[len++] = 0x48; buf[len++] = 0x31; buf[len++] = 0xFF;     /* xor rdi, rdi */
    buf[len++] = 0x48; buf[len++] = 0xC7; buf[len++] = 0xC6;     /* mov rsi, 0x1000 */
    buf[len++] = 0x00; buf[len++] = 0x10; buf[len++] = 0x00; buf[len++] = 0x00;
    buf[len++] = 0x48; buf[len++] = 0xC7; buf[len++] = 0xC2;     /* mov rdx, 7 */
    buf[len++] = 0x07; buf[len++] = 0x00; buf[len++] = 0x00; buf[len++] = 0x00;
    buf[len++] = 0x49; buf[len++] = 0xC7; buf[len++] = 0xC2;     /* mov r10, 0x22 */
    buf[len++] = 0x22; buf[len++] = 0x00; buf[len++] = 0x00; buf[len++] = 0x00;
    buf[len++] = 0x49; buf[len++] = 0xC7; buf[len++] = 0xC0;     /* mov r8, -1 */
    buf[len++] = 0xFF; buf[len++] = 0xFF; buf[len++] = 0xFF; buf[len++] = 0xFF;
    buf[len++] = 0x4D; buf[len++] = 0x31; buf[len++] = 0xC9;     /* xor r9, r9 */
    buf[len++] = 0x0F; buf[len++] = 0x05;                         /* syscall */
    buf[len++] = 0xCC;                                             /* int3 */
    return len;
}

/*
 * 构建 PLT 跳转 patch (16 bytes):
 *   jmp [rip+0]        ; ff 25 00 00 00 00
 *   .quad hook_entry   ; 直接地址, 不经过 GOT
 *   nop nop            ; 90 90
 */
static void build_plt_patch(uint8_t *patch, uint64_t hook_entry)
{
    /* jmp [rip+0] — 读取紧随其后的 8 字节作为跳转目标 */
    patch[0] = 0xFF; patch[1] = 0x25;
    patch[2] = 0x00; patch[3] = 0x00; patch[4] = 0x00; patch[5] = 0x00;
    /* 64-bit hook address */
    memcpy(patch + 6, &hook_entry, 8);
    /* nop padding */
    patch[14] = 0x90; patch[15] = 0x90;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    fprintf(stderr, "[INJECT] === PLT Hook v6 ===\n");
    fprintf(stderr, "[INJECT] PID=%d fake=(%.6f, %.6f)\n", pid, g_fake_lat, g_fake_lon);

    /* Attach */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) die("ATTACH");
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) { ptrace(PTRACE_DETACH, pid, NULL, NULL); return 1; }
    fprintf(stderr, "[INJECT] Attached\n");

    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) < 0) die("GETREGS");

    /* Find modules */
    struct module_info entry_mod, ld_mod;
    if (find_module(pid, "libentry.so", &entry_mod) < 0) {
        fprintf(stderr, "[INJECT-ERR] libentry.so not found\n"); goto fail;
    }
    if (find_module(pid, "ld-musl", &ld_mod) < 0) {
        fprintf(stderr, "[INJECT-ERR] ld-musl not found\n"); goto fail;
    }
    fprintf(stderr, "[INJECT] libentry.so base=0x%lx rx=[0x%lx-0x%lx]\n",
            (unsigned long)entry_mod.base,
            (unsigned long)entry_mod.rx_start, (unsigned long)entry_mod.rx_end);

    /* Step 1: 找到 GOT 地址 (仅用于定位 PLT stub) */
    uint64_t got_addr = find_got_entry(pid, &entry_mod, "OH_LocationInfo_GetBasicInfo");
    if (!got_addr) { fprintf(stderr, "[INJECT-ERR] GOT not found\n"); goto fail; }

    /* Step 2: 找到 PLT stub (r-xp 段中跳转到该 GOT 的指令) */
    uint64_t plt_addr = find_plt_stub(pid, &entry_mod, got_addr);
    if (!plt_addr) { fprintf(stderr, "[INJECT-ERR] PLT stub not found\n"); goto fail; }

    /* 读取原始 PLT stub (用于调试) */
    uint8_t orig_plt[16];
    mem_read(pid, plt_addr, orig_plt, 16);
    fprintf(stderr, "[INJECT] Original PLT: ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x ", orig_plt[i]);
    fprintf(stderr, "\n");

    /* Step 3: 读取 GOT 中的原始函数地址 (hook 需要调用原函数) */
    uint64_t orig_func;
    if (mem_read(pid, got_addr, &orig_func, 8) < 0) die("read GOT");
    fprintf(stderr, "[INJECT] orig_func=0x%lx\n", (unsigned long)orig_func);

    /* Step 4: mmap 分配匿名可执行内存 (放 hook 代码) */
    uint8_t mmap_sc[64];
    size_t mmap_sc_len = build_mmap_sc(mmap_sc);
    uint64_t cave = find_code_cave(pid, ld_mod.rx_start, ld_mod.rx_end, mmap_sc_len);
    if (!cave) { fprintf(stderr, "[INJECT-ERR] No cave\n"); goto fail; }

    uint8_t orig_cave[64];
    mem_read(pid, cave, orig_cave, mmap_sc_len);
    mem_write(pid, cave, mmap_sc, mmap_sc_len);

    struct user_regs_struct mmap_regs = orig_regs;
    mmap_regs.rip = cave;
    if (ptrace(PTRACE_SETREGS, pid, NULL, &mmap_regs) < 0) die("SETREGS mmap");
    if (ptrace(PTRACE_CONT, pid, NULL, NULL) < 0) die("CONT mmap");

    waitpid(pid, &status, 0);
    uint64_t mmap_result = 0;
    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
        struct user_regs_struct ret_regs;
        ptrace(PTRACE_GETREGS, pid, NULL, &ret_regs);
        mmap_result = ret_regs.rax;
    }
    mem_write(pid, cave, orig_cave, mmap_sc_len);

    if (!mmap_result || mmap_result == (uint64_t)-1) {
        fprintf(stderr, "[INJECT-ERR] mmap failed: 0x%lx\n", (unsigned long)mmap_result);
        ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
        ptrace(PTRACE_DETACH, pid, NULL, NULL);
        return 1;
    }
    fprintf(stderr, "[INJECT] mmap=0x%lx\n", (unsigned long)mmap_result);

    /* Step 5: 写入 hook trampoline 到匿名内存 */
    uint8_t hook_buf[256];
    size_t hook_len = build_hook_code(hook_buf, orig_func, g_fake_lat, g_fake_lon);
    if (mem_write(pid, mmap_result, hook_buf, hook_len) < 0) die("write hook");

    size_t code_start = ((3 * 8) + 15) & ~15ULL;
    uint64_t hook_entry = mmap_result + code_start;
    fprintf(stderr, "[INJECT] Hook entry=0x%lx\n", (unsigned long)hook_entry);

    /* 验证 */
    uint8_t verify[64];
    mem_read(pid, mmap_result, verify, 32);
    fprintf(stderr, "[INJECT] Verify: ");
    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x ", verify[i]);
    fprintf(stderr, "\n");

    /* Step 6: 构建 PLT patch 并写入 */
    uint8_t plt_patch[16];
    build_plt_patch(plt_patch, hook_entry);
    fprintf(stderr, "[INJECT] PLT patch: ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x ", plt_patch[i]);
    fprintf(stderr, "\n");

    if (mem_write(pid, plt_addr, plt_patch, 16) < 0) die("write PLT");

    /* 验证 PLT patch */
    uint8_t v_plt[16];
    mem_read(pid, plt_addr, v_plt, 16);
    fprintf(stderr, "[INJECT] PLT verify: ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x ", v_plt[i]);
    fprintf(stderr, "\n");

    /* Restore regs and detach */
    if (ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs) < 0) die("SETREGS restore");
    if (ptrace(PTRACE_DETACH, pid, NULL, 0) < 0) die("DETACH");

    fprintf(stderr, "[INJECT] === PLT Hook done! ===\n");
    fprintf(stderr, "[INJECT] PLT at 0x%lx -> hook at 0x%lx\n",
            (unsigned long)plt_addr, (unsigned long)hook_entry);
    fprintf(stderr, "[INJECT] Location will be: lat=%.6f lon=%.6f\n", g_fake_lat, g_fake_lon);
    return 0;

fail:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 1;
}
