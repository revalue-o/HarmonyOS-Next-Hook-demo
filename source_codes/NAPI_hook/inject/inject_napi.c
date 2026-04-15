/*
 * inject_napi — NAPI Inline Hook: 替换 NativeGetCurrentLocation
 *
 * 通过 inline hook 直接修改 libentry.so 中 NativeGetCurrentLocation 函数的
 * 机器码，使其跳转到我们控制的 fake_getLocation 函数。
 *
 * 这是代码层面的修改: 原函数的代码不再执行，完全由我们的函数接管。
 * 与 inject_v6 的区别:
 *   - inject_v6: 修改 PLT stub (数据调度层)，原函数仍执行，覆写返回数据
 *   - 本方案:    修改函数代码本身，原函数不执行，完全替换为不同代码
 *
 * 编译:
 *   clang --target=x86_64-linux-ohos -O2 --sysroot=<sdk>/sysroot \
 *         -o inject_napi inject_napi.c
 *
 * 用法:
 *   ./inject_napi <pid>
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

/* ---- 伪造坐标 ---- */
static double g_fake_lat = 666.66;
static double g_fake_lon = 888.88;
static double g_fake_alt = 50.0;
static double g_fake_acc = 5.0;
static double g_fake_spd = 0.0;

/* NativeGetCurrentLocation 在 libentry.so 中的偏移 (x86_64) */
#define NATIVE_GET_LOCATION_OFFSET 0x2980

static void die(const char *msg)
{
    fprintf(stderr, "[INJECT-ERR] %s: %s\n", msg, strerror(errno));
    exit(1);
}

/* ---- /proc/pid/mem 读写 ---- */

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

/* ---- 查找模块基址 ---- */

static uint64_t find_module_base(pid_t pid, const char *name)
{
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
    FILE *f = fopen(mpath, "r");
    if (!f) return 0;
    char line[512];
    uint64_t base = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, name)) {
            sscanf(line, "%lx-", (unsigned long *)&base);
            break;
        }
    }
    fclose(f);
    return base;
}

/* ---- 查找模块 r-xp 段 ---- */
static uint64_t find_module_rx(pid_t pid, const char *name, uint64_t *rx_end)
{
    char mpath[64];
    snprintf(mpath, sizeof(mpath), "/proc/%d/maps", pid);
    FILE *f = fopen(mpath, "r");
    if (!f) return 0;
    char line[512];
    uint64_t rx_start = 0;
    *rx_end = 0;
    while (fgets(line, sizeof(line), f)) {
        if (!strstr(line, name)) continue;
        unsigned long start, end;
        char perms[8];
        sscanf(line, "%lx-%lx %4s", &start, &end, perms);
        if (strcmp(perms, "r-xp") == 0) {
            rx_start = start;
            *rx_end = end;
        }
    }
    fclose(f);
    return rx_start;
}

/* ---- 找 code cave ---- */
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

/* ---- ELF: 找 GOT 条目 ---- */
static uint64_t find_got_entry(pid_t pid, uint64_t base, const char *func_name)
{
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
            return base + r_offset;
        }
    }
    return 0;
}

/* 从 GOT 读取函数地址 */
static uint64_t read_func_addr(pid_t pid, uint64_t base, const char *name)
{
    uint64_t got = find_got_entry(pid, base, name);
    if (!got) return 0;
    uint64_t addr;
    if (mem_read(pid, got, &addr, 8) < 0) return 0;
    return addr;
}

/* ---- RIP-relative 辅助 ---- */
/* rel = target_buf_offset - (instr_buf_offset + 7) */
static int32_t rip_rel(size_t instr_off, size_t target_off)
{
    return (int32_t)((int64_t)target_off - (int64_t)(instr_off + 7));
}

static size_t emit_mov_rax_rip(uint8_t *buf, size_t p, int32_t rel)
{
    buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0x05;
    memcpy(buf + p, &rel, 4); p += 4;
    return p;
}

static size_t emit_call_rax(uint8_t *buf, size_t p)
{
    buf[p++] = 0xFF; buf[p++] = 0xD0;
    return p;
}

/*
 * 构建 fake_getLocation 函数
 *
 * 输入: rdi = napi_env, rsi = napi_callback_info
 * 输出: rax = napi_value (Promise)
 *
 * 逻辑:
 *   1. napi_create_promise(env, &deferred, &promise)
 *   2. napi_create_object(env, &obj)
 *   3. 对 lat/lon/alt/acc/spd:
 *      napi_create_double(env, value, &val)
 *      napi_set_named_property(env, obj, name, val)
 *   4. napi_resolve_deferred(env, deferred, obj)
 *   5. return promise
 *
 * mmap 内存布局:
 * [0x00] napi_create_promise     (8 bytes)
 * [0x08] napi_create_object      (8 bytes)
 * [0x10] napi_create_double      (8 bytes)
 * [0x18] napi_set_named_property (8 bytes)
 * [0x20] napi_resolve_deferred   (8 bytes)
 * [0x28] fake_lat  (double, 8 bytes)
 * [0x30] fake_lon  (double, 8 bytes)
 * [0x38] fake_alt  (double, 8 bytes)
 * [0x40] fake_acc  (double, 8 bytes)
 * [0x48] fake_spd  (double, 8 bytes)
 * [0x80] 代码入口 (16 字节对齐)
 * [0x180] 字符串 "latitude" "longitude" "altitude" "accuracy" "speed"
 */
#define DATA_START 0x00
#define CODE_START 0x80
#define STR_ADDR   0x300

static size_t build_fake_func(uint8_t *buf)
{
    size_t p = CODE_START;

    /* sub rsp, 0x58 */
    buf[p++] = 0x48; buf[p++] = 0x81; buf[p++] = 0xEC;
    buf[p++] = 0x58; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00;

    /* 保存 rdi(env) 到 [rsp+0x08] */
    buf[p++] = 0x48; buf[p++] = 0x89; buf[p++] = 0x7C; buf[p++] = 0x24; buf[p++] = 0x08;

    /*
     * 栈布局:
     * [rsp+0x30] deferred
     * [rsp+0x38] promise
     * [rsp+0x40] obj
     * [rsp+0x48] val
     */

    /* === napi_create_promise(env, &deferred, &promise) === */
    /* lea rsi, [rsp+0x30] */
    buf[p++] = 0x48; buf[p++] = 0x8D; buf[p++] = 0x74; buf[p++] = 0x24; buf[p++] = 0x30;
    /* lea rdx, [rsp+0x38] */
    buf[p++] = 0x48; buf[p++] = 0x8D; buf[p++] = 0x54; buf[p++] = 0x24; buf[p++] = 0x38;
    /* mov rdi, [rsp+0x08] = env */
    buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0x7C; buf[p++] = 0x24; buf[p++] = 0x08;
    /* call napi_create_promise */
    p = emit_mov_rax_rip(buf, p, rip_rel(p, 0x00)); p = emit_call_rax(buf, p);

    /* === napi_create_object(env, &obj) === */
    /* lea rsi, [rsp+0x40] */
    buf[p++] = 0x48; buf[p++] = 0x8D; buf[p++] = 0x74; buf[p++] = 0x24; buf[p++] = 0x40;
    /* mov rdi, [rsp+0x08] */
    buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0x7C; buf[p++] = 0x24; buf[p++] = 0x08;
    /* call napi_create_object */
    p = emit_mov_rax_rip(buf, p, rip_rel(p, 0x08)); p = emit_call_rax(buf, p);

    /*
     * 辅助: 设置一个属性
     * 需要: env(rdi), obj(rsi), name_str(rdx), val(rcx)
     *
     * napi_create_double(env, value_in_xmm0, &val):
     *   rdi=env, xmm0=value, rdx=&val
     * napi_set_named_property(env, obj, name, val):
     *   rdi=env, rsi=obj, rdx=name_str_ptr, rcx=val
     */
    #define EMIT_DOUBLE_AND_SET(name_off, data_off) do { \
        /* napi_create_double */ \
        buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0x7C; buf[p++] = 0x24; buf[p++] = 0x08; /* mov rdi, env */ \
        buf[p++] = 0xF2; buf[p++] = 0x0F; buf[p++] = 0x10; buf[p++] = 0x05; /* movsd xmm0, [rip+rel] */ \
        { int32_t _r = (int32_t)((int64_t)(data_off) - (int64_t)(p + 4)); memcpy(buf + p, &_r, 4); p += 4; } \
        buf[p++] = 0x48; buf[p++] = 0x8D; buf[p++] = 0x74; buf[p++] = 0x24; buf[p++] = 0x48; /* lea rsi, &val */ \
        p = emit_mov_rax_rip(buf, p, rip_rel(p, 0x10)); p = emit_call_rax(buf, p); /* call create_double */ \
        /* napi_set_named_property */ \
        buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0x7C; buf[p++] = 0x24; buf[p++] = 0x08; /* mov rdi, env */ \
        buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0x74; buf[p++] = 0x24; buf[p++] = 0x40; /* mov rsi, obj */ \
        buf[p++] = 0x48; buf[p++] = 0x8D; buf[p++] = 0x15; /* lea rdx, [rip+name] */ \
        { int32_t _r = (int32_t)((int64_t)(name_off) - (int64_t)(p + 4)); memcpy(buf + p, &_r, 4); p += 4; } \
        buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0x4C; buf[p++] = 0x24; buf[p++] = 0x48; /* mov rcx, val */ \
        p = emit_mov_rax_rip(buf, p, rip_rel(p, 0x18)); p = emit_call_rax(buf, p); /* call set_named */ \
    } while(0)

    /* 设置 latitude, longitude, altitude, accuracy, speed */
    EMIT_DOUBLE_AND_SET(STR_ADDR + 0,  0x28);  /* latitude */
    EMIT_DOUBLE_AND_SET(STR_ADDR + 9,  0x30);  /* longitude */
    EMIT_DOUBLE_AND_SET(STR_ADDR + 19, 0x38);  /* altitude */
    EMIT_DOUBLE_AND_SET(STR_ADDR + 28, 0x40);  /* accuracy */
    EMIT_DOUBLE_AND_SET(STR_ADDR + 37, 0x48);  /* speed */

    /* === napi_resolve_deferred(env, deferred, obj) === */
    buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0x7C; buf[p++] = 0x24; buf[p++] = 0x08; /* rdi = env */
    buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0x74; buf[p++] = 0x24; buf[p++] = 0x30; /* rsi = deferred */
    buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0x54; buf[p++] = 0x24; buf[p++] = 0x40; /* rdx = obj */
    p = emit_mov_rax_rip(buf, p, rip_rel(p, 0x20)); p = emit_call_rax(buf, p);

    /* return promise */
    buf[p++] = 0x48; buf[p++] = 0x8B; buf[p++] = 0x44; buf[p++] = 0x24; buf[p++] = 0x38;

    /* add rsp, 0x58 */
    buf[p++] = 0x48; buf[p++] = 0x81; buf[p++] = 0xC4;
    buf[p++] = 0x58; buf[p++] = 0x00; buf[p++] = 0x00; buf[p++] = 0x00;
    /* ret */
    buf[p++] = 0xC3;

    return p;
}

/* 构建字符串区 */
static void build_strings(uint8_t *buf)
{
    memcpy(buf + STR_ADDR + 0,  "latitude\0",  9);
    memcpy(buf + STR_ADDR + 9,  "longitude\0", 10);
    memcpy(buf + STR_ADDR + 19, "altitude\0",  9);
    memcpy(buf + STR_ADDR + 28, "accuracy\0",  9);
    memcpy(buf + STR_ADDR + 37, "speed\0",     6);
}

/* ---- mmap shellcode ---- */
static size_t build_mmap_sc(uint8_t *buf)
{
    size_t len = 0;
    buf[len++] = 0x48; buf[len++] = 0xC7; buf[len++] = 0xC0;
    buf[len++] = 0x09; buf[len++] = 0x00; buf[len++] = 0x00; buf[len++] = 0x00;
    buf[len++] = 0x48; buf[len++] = 0x31; buf[len++] = 0xFF;
    buf[len++] = 0x48; buf[len++] = 0xC7; buf[len++] = 0xC6;
    buf[len++] = 0x00; buf[len++] = 0x10; buf[len++] = 0x00; buf[len++] = 0x00;
    buf[len++] = 0x48; buf[len++] = 0xC7; buf[len++] = 0xC2;
    buf[len++] = 0x07; buf[len++] = 0x00; buf[len++] = 0x00; buf[len++] = 0x00;
    buf[len++] = 0x49; buf[len++] = 0xC7; buf[len++] = 0xC2;
    buf[len++] = 0x22; buf[len++] = 0x00; buf[len++] = 0x00; buf[len++] = 0x00;
    buf[len++] = 0x49; buf[len++] = 0xC7; buf[len++] = 0xC0;
    buf[len++] = 0xFF; buf[len++] = 0xFF; buf[len++] = 0xFF; buf[len++] = 0xFF;
    buf[len++] = 0x4D; buf[len++] = 0x31; buf[len++] = 0xC9;
    buf[len++] = 0x0F; buf[len++] = 0x05;
    buf[len++] = 0xCC;
    return len;
}

/* ---- inline hook patch: jmp [rip+0]; <addr>; nop nop ---- */
static void build_inline_patch(uint8_t *patch, uint64_t target)
{
    /* jmp [rip+0] — 读取紧跟的 8 字节作为跳转目标 */
    patch[0] = 0xFF; patch[1] = 0x25;
    patch[2] = 0x00; patch[3] = 0x00; patch[4] = 0x00; patch[5] = 0x00;
    /* 64-bit target address */
    memcpy(patch + 6, &target, 8);
    /* nop padding */
    patch[14] = 0x90; patch[15] = 0x90;
}

/* ---- 主函数 ---- */

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <pid>\n", argv[0]);
        return 1;
    }

    pid_t pid = atoi(argv[1]);
    fprintf(stderr, "[INJECT] === NAPI Inline Hook ===\n");
    fprintf(stderr, "[INJECT] PID=%d fake=(%.6f, %.6f)\n", pid, g_fake_lat, g_fake_lon);

    /* Attach */
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) < 0) die("ATTACH");
    int status;
    waitpid(pid, &status, 0);
    if (!WIFSTOPPED(status)) { ptrace(PTRACE_DETACH, pid, NULL, NULL); return 1; }

    struct user_regs_struct orig_regs;
    if (ptrace(PTRACE_GETREGS, pid, NULL, &orig_regs) < 0) die("GETREGS");
    fprintf(stderr, "[INJECT] Attached\n");

    /* 找 libentry.so 基址 */
    uint64_t entry_base = find_module_base(pid, "libentry.so");
    if (!entry_base) {
        fprintf(stderr, "[INJECT-ERR] libentry.so not found\n");
        goto fail;
    }
    fprintf(stderr, "[INJECT] libentry.so base=0x%lx\n", (unsigned long)entry_base);

    /* 找 ld-musl r-xp 段 */
    uint64_t ld_rx_end;
    uint64_t ld_rx = find_module_rx(pid, "ld-musl", &ld_rx_end);
    if (!ld_rx) {
        fprintf(stderr, "[INJECT-ERR] ld-musl not found\n");
        goto fail;
    }

    /* Step 1: 从 libentry.so GOT 读取 NAPI API 地址 */
    uint64_t addr_create_promise     = read_func_addr(pid, entry_base, "napi_create_promise");
    uint64_t addr_create_object      = read_func_addr(pid, entry_base, "napi_create_object");
    uint64_t addr_create_double      = read_func_addr(pid, entry_base, "napi_create_double");
    uint64_t addr_set_named_property = read_func_addr(pid, entry_base, "napi_set_named_property");
    uint64_t addr_resolve_deferred   = read_func_addr(pid, entry_base, "napi_resolve_deferred");

    if (!addr_create_promise || !addr_create_object || !addr_create_double ||
        !addr_set_named_property || !addr_resolve_deferred) {
        fprintf(stderr, "[INJECT-ERR] Failed to resolve NAPI API addresses\n");
        goto fail;
    }

    fprintf(stderr, "[INJECT] napi_create_promise      = 0x%lx\n", (unsigned long)addr_create_promise);
    fprintf(stderr, "[INJECT] napi_create_object       = 0x%lx\n", (unsigned long)addr_create_object);
    fprintf(stderr, "[INJECT] napi_create_double       = 0x%lx\n", (unsigned long)addr_create_double);
    fprintf(stderr, "[INJECT] napi_set_named_property  = 0x%lx\n", (unsigned long)addr_set_named_property);
    fprintf(stderr, "[INJECT] napi_resolve_deferred    = 0x%lx\n", (unsigned long)addr_resolve_deferred);

    /* NativeGetCurrentLocation 的绝对地址 */
    uint64_t target_func = entry_base + NATIVE_GET_LOCATION_OFFSET;
    fprintf(stderr, "[INJECT] NativeGetCurrentLocation = 0x%lx (base+0x%x)\n",
            (unsigned long)target_func, NATIVE_GET_LOCATION_OFFSET);

    /* 读取原始函数前 16 字节 (调试) */
    uint8_t orig_bytes[16];
    mem_read(pid, target_func, orig_bytes, 16);
    fprintf(stderr, "[INJECT] Original bytes: ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x ", orig_bytes[i]);
    fprintf(stderr, "\n");

    /* Step 2: mmap 分配可执行内存 */
    uint8_t mmap_sc[64];
    size_t mmap_sc_len = build_mmap_sc(mmap_sc);
    uint64_t cave = find_code_cave(pid, ld_rx, ld_rx_end, mmap_sc_len);
    if (!cave) { fprintf(stderr, "[INJECT-ERR] No cave\n"); goto fail; }

    uint8_t orig_cave[64];
    mem_read(pid, cave, orig_cave, mmap_sc_len);
    mem_write(pid, cave, mmap_sc, mmap_sc_len);

    struct user_regs_struct mmap_regs = orig_regs;
    mmap_regs.rip = cave;
    ptrace(PTRACE_SETREGS, pid, NULL, &mmap_regs);
    ptrace(PTRACE_CONT, pid, NULL, NULL);

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

    /* Step 3: 写入 fake_getLocation 到 mmap 区域 */
    uint8_t hook_buf[4096];
    memset(hook_buf, 0, sizeof(hook_buf));

    /* 数据区: NAPI API 地址 + 伪造坐标 */
    memcpy(hook_buf + 0x00, &addr_create_promise, 8);
    memcpy(hook_buf + 0x08, &addr_create_object, 8);
    memcpy(hook_buf + 0x10, &addr_create_double, 8);
    memcpy(hook_buf + 0x18, &addr_set_named_property, 8);
    memcpy(hook_buf + 0x20, &addr_resolve_deferred, 8);
    memcpy(hook_buf + 0x28, &g_fake_lat, 8);
    memcpy(hook_buf + 0x30, &g_fake_lon, 8);
    memcpy(hook_buf + 0x38, &g_fake_alt, 8);
    memcpy(hook_buf + 0x40, &g_fake_acc, 8);
    memcpy(hook_buf + 0x48, &g_fake_spd, 8);

    /* 代码区 + 字符串区 */
    size_t code_end = build_fake_func(hook_buf);
    build_strings(hook_buf);

    /* 写入到目标进程 */
    if (mem_write(pid, mmap_result, hook_buf, 4096) < 0) die("write hook");

    uint64_t fake_func_addr = mmap_result + CODE_START;
    fprintf(stderr, "[INJECT] fake_getLocation at 0x%lx (code end=0x%zx)\n",
            (unsigned long)fake_func_addr, code_end);

    /* 验证写入 */
    uint8_t verify[32];
    mem_read(pid, mmap_result, verify, 32);
    fprintf(stderr, "[INJECT] Verify mmap: ");
    for (int i = 0; i < 32; i++) fprintf(stderr, "%02x ", verify[i]);
    fprintf(stderr, "\n");

    /* Step 4: Inline hook — 覆盖 NativeGetCurrentLocation 前 16 字节 */
    uint8_t patch[16];
    build_inline_patch(patch, fake_func_addr);
    fprintf(stderr, "[INJECT] Inline patch: ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x ", patch[i]);
    fprintf(stderr, "\n");

    if (mem_write(pid, target_func, patch, 16) < 0) die("write inline hook");

    /* 验证 */
    uint8_t v_patch[16];
    mem_read(pid, target_func, v_patch, 16);
    fprintf(stderr, "[INJECT] Verify patch: ");
    for (int i = 0; i < 16; i++) fprintf(stderr, "%02x ", v_patch[i]);
    fprintf(stderr, "\n");

    /* 恢复寄存器并 detach */
    ptrace(PTRACE_SETREGS, pid, NULL, &orig_regs);
    ptrace(PTRACE_DETACH, pid, NULL, 0);

    fprintf(stderr, "[INJECT] === NAPI Inline Hook done! ===\n");
    fprintf(stderr, "[INJECT] NativeGetCurrentLocation at 0x%lx -> fake at 0x%lx\n",
            (unsigned long)target_func, (unsigned long)fake_func_addr);
    fprintf(stderr, "[INJECT] Location will be: lat=%.6f lon=%.6f\n", g_fake_lat, g_fake_lon);
    return 0;

fail:
    ptrace(PTRACE_DETACH, pid, NULL, NULL);
    return 1;
}
