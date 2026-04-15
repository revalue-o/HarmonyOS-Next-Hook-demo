# HarmonyOS Next 位置注入：PLT Hook 方法

## 概述

本文档描述了如何在 HarmonyOS Next (x86_64 模拟器) 上通过 PLT Hook 修改应用返回的位置信息。目标函数为 `OH_LocationInfo_GetBasicInfo`，通过 ptrace 注入修改 PLT stub，使函数返回伪造的经纬度。

## 环境

- **目标平台**: HarmonyOS Next x86_64 模拟器 (已 root)
- **工具链**: DevEco Studio 自带的 clang (`sdk/default/openharmony/native/llvm/bin/clang.exe`)
- **目标**: `--target=x86_64-linux-ohos`
- **通信**: hdc (HarmonyOS Device Connector)

## 技术原理

### 目标函数分析

应用 (`libentry.so`) 调用 `OH_LocationInfo_GetBasicInfo(Location_Info*)` 获取位置信息，该函数定义在 `liblocation_ndk.so` 中，通过 PLT/GOT 进行跨库调用。

调用约定 (x86_64 System V ABI，sret):
- `rdi` = 返回缓冲区指针 (隐式 sret 参数，因为 `Location_BasicInfo` > 16 字节)
- `rsi` = `Location_Info*` (实际参数)
- 函数将结果写入 `rdi` 指向的缓冲区

`Location_BasicInfo` 结构体布局:
```
offset  size  field
0x00    8     latitude   (double)
0x08    8     longitude  (double)
0x10    8     altitude   (double)
0x18    8     accuracy   (double)
0x20    8     speed      (double)
0x28    8     direction  (double)
0x30    8     timeForFix (int64_t)
0x38    8     timeSinceBoot (int64_t)
0x40    4     locationSourceType (int32_t)
```

### PLT Hook 原理

```
正常调用流程:
  libentry.so 代码 → call PLT_stub → jmp [GOT] → liblocation_ndk.so 函数

Hook 后的调用流程:
  libentry.so 代码 → call PLT_stub → jmp [hook_addr] → hook_trampoline
                                                    → call 原函数 (保存结果)
                                                    → 覆写 lat/lon
                                                    → ret
```

PLT stub 原始格式 (16 bytes):
```asm
ff 25 xx xx xx xx    ; jmp [rip+disp32] → 读 GOT → 跳到原函数
68 nn 00 00 00       ; push reloc_index (lazy binding fallback)
e9 xx xx xx xx       ; jmp PLT[0] (resolver)
```

替换为 (16 bytes):
```asm
ff 25 00 00 00 00    ; jmp [rip+0] → 读紧接的 8 字节
<hook_entry 8 bytes> ; 直接跳到 hook，不经过 GOT
90 90                ; nop 对齐
```

### Hook Trampoline 设计

hook trampoline 写入 mmap 分配的匿名可执行内存，布局如下:

```
offset  内容
0x00    orig_func 地址 (uint64_t)  — 原始函数地址
0x08    fake_lat     (double)      — 伪造纬度
0x10    fake_lon     (double)      — 伪造经度
0x20    代码入口 (16 字节对齐)
```

代码逻辑 (x86_64 汇编):
```asm
sub  rsp, 0x78              ; 建栈帧 (保持 16 字节对齐)
mov  [rsp+0x08], rdi        ; 保存 sret 缓冲区指针
mov  [rsp+0x10], rsi        ; 保存 Location_Info* 参数
mov  rax, [rip+rel]         ; 加载 orig_func 地址
call rax                    ; 调用原函数 (rdi/rsi 不变)
mov  rdi, [rsp+0x08]        ; 恢复 sret 缓冲区指针
mov  rax, [rip+rel]         ; 加载 fake_lat
mov  [rdi], rax             ; 覆写 latitude (offset 0)
mov  rax, [rip+rel]         ; 加载 fake_lon
mov  [rdi+8], rax           ; 覆写 longitude (offset 8)
add  rsp, 0x78
ret
```

## 关键实现细节

### RIP-relative 寻址

hook 代码使用 `mov rax, [rip+rel32]` 读取数据区中的常量。rel32 的正确计算公式为:

```
rel32 = data_offset - (instruction_buffer_offset + 7)
```

其中:
- `data_offset` = 数据在 buffer 中的偏移 (0 = orig_func, 8 = fake_lat, 16 = fake_lon)
- `instruction_buffer_offset` = `mov rax, [rip+...]` 指令在 buffer 中的偏移
- `+7` = 该指令长度 (3 字节前缀 + 4 字节 rel32)

**重要**: `p` 是指令在 buffer 中的绝对偏移 (从 buffer 起始位置算起)，不需要额外加上 `code_start`。之前的版本在这里有 bug，多加了一个 `code_start`(=32)，导致读取到 buffer 前 32 字节的无效内存，引发 SIGSEGV。

### 注入流程

```
1. ptrace ATTACH 目标进程
2. 解析 /proc/pid/maps 找到 libentry.so 和 ld-musl 的内存布局
3. 解析 libentry.so 的 ELF 动态节，找到 OH_LocationInfo_GetBasicInfo 的 GOT 条目
4. 在 libentry.so 的 r-xp 段中搜索跳转到该 GOT 的 PLT stub
5. 从 GOT 中读取原始函数地址
6. 在 ld-musl 的代码洞中执行 mmap syscall，分配匿名可执行内存
7. 将 hook trampoline 写入 mmap 区域
8. 将 PLT stub 替换为直接跳转到 hook 的指令
9. 恢复寄存器，ptrace DETACH
```

### ELF 解析要点

通过 `/proc/pid/mem` 读取远程进程内存，解析:
- ELF header → PT_DYNAMIC segment
- Dynamic section → DT_STRTAB, DT_SYMTAB, DT_JMPREL, DT_PLTRELSZ
- .rela.plt entries → 匹配 R_X86_64_JUMP_SLOT (type=7) + 符号名

注意: 对于共享库，strtab/symtab/jmprel 的 d_val 是相对于模块基址的虚拟地址偏移，需加上 `base`。

### PLT Stub 搜索

遍历 r-xp 段中的 `ff 25` (jmp [rip+disp32]) 指令，计算其跳转目标是否等于 GOT 条目地址:
```
target = stub_addr + 6 + (int64_t)disp32
if target == got_addr → 找到 PLT stub
```

### mmap Shellcode

通过 ptrace 修改 RIP 执行 syscall:
```asm
mov rax, 9          ; SYS_mmap
xor rdi, rdi        ; addr = NULL (内核选择地址)
mov rsi, 0x1000     ; length = 4096
mov rdx, 7          ; prot = PROT_READ|PROT_WRITE|PROT_EXEC
mov r10, 0x22       ; flags = MAP_PRIVATE|MAP_ANONYMOUS
mov r8, -1          ; fd = -1
xor r9, r9          ; offset = 0
syscall
int3                ; 触发 SIGTRAP 暂停
```

shellcode 写入 ld-musl 的代码洞 (code cave) 执行，执行后恢复原始内容。

### 内存写入持久性

所有内存修改通过 `pwrite(/proc/pid/mem)` 完成:
- 代码页 (r-xp): 写入触发 COW (Copy-On-Write)，创建进程私有脏页
- 脏页不会被内核丢弃 (动态链接器常驻内存)
- 匿名 mmap 内存: 进程生命周期内有效

## 编译与使用

### 编译

```bash
CLANG="C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/native/llvm/bin/clang.exe"
SYSROOT="C:/Program Files/Huawei/DevEco Studio/sdk/default/openharmony/native/sysroot"

"$CLANG" --target=x86_64-linux-ohos -O2 --sysroot="$SYSROOT" -o inject_v6 inject_v6.c
```

### 使用

```bash
# 1. 推送到设备
hdc file send inject_v6 /data/local/tmp/inject_v6

# 2. 启动目标应用
hdc shell aa start -a EntryAbility -b com.example.sys_verify

# 3. 获取 PID
hdc shell ps -ef | grep sys_verify

# 4. 执行注入
hdc shell /data/local/tmp/inject_v6 <PID>

# 5. 在应用中点击 "获取位置 (Native)" 按钮
#    应显示伪造坐标: lat=39.908700 lon=116.397500
```

### 修改伪造坐标

编辑 `inject_v6.c` 顶部的常量:
```c
static double g_fake_lat = 39.9087;   /* 纬度 */
static double g_fake_lon = 116.3975;  /* 经度 */
```

## 排查指南

### 检查崩溃日志

```bash
hdc shell "ls -lt /data/log/faultlog/faultlogger/ | head -5"
hdc shell "head -35 /data/log/faultlog/faultlogger/cppcrash-com.example.sys_verify-*"
```

### 常见问题

| 现象 | 可能原因 | 解决方法 |
|------|----------|----------|
| RIP=0 崩溃 | RIP-relative 偏移计算错误 | 检查 `build_hook_code` 中 rel32 公式 |
| GOT/PLT not found | 符号名不匹配 | 用 `readelf -r libentry.so` 确认符号名 |
| mmap failed | code cave 不足 | 扩大搜索范围或使用其他模块的代码洞 |
| 注入后无效果 | PLT stub 未被调用 | 检查是否修改了正确的 PLT 条目 |

### 验证注入状态

```bash
# 检查进程是否存活
hdc shell "ps -ef | grep sys_verify"

# 读取 GOT 值 (需要 root)
hdc shell "dd if=/proc/<PID>/mem bs=1 skip=<GOT_ADDR_DEC> count=8 2>/dev/null | xxd"
```

## 文件清单

```
inject/
├── inject_v6.c     # PLT Hook 实现 (当前版本，已修复)
├── inject_v5.c     # GOT overwrite + mmap (RIP-relative bug)
├── inject_v4.c     # 纯内存 GOT overwrite (同 bug)
├── inject_v3.c     # 早期 GOT overwrite
├── inject.c        # Shellcode 注入初版
├── hook.c          # libhook.so (dlopen 注入方式)
└── inject_v6       # 已编译的二进制 (x86_64)
```

## 局限性

1. 仅影响 Native 层 (`OH_LocationInfo_GetBasicInfo`)，不影响 ArkTS 层 (`geoLocationManager`)
2. 需要 root 权限 (ptrace + /proc/pid/mem 访问)
3. 仅在 x86_64 模拟器上测试通过
4. 应用重启后需要重新注入
5. 如果目标函数不通过 PLT 调用 (如内联或直接调用)，此方法无效
