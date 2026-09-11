# Inline Hook 经验（为 sus_path 的 syscall 层准备）

目标平台：OnePlus SM8550 / Linux 5.15.180 GKI，`CONFIG_LTO_CLANG` + `CONFIG_CFI_CLANG=y`
+ `CONFIG_ARM64_BTI_KERNEL=y` + `CONFIG_STRICT_KERNEL_RWX=y`，`CONFIG_FUNCTION_TRACER is not set`。

试点模块：`kernel/ih_probe_main.c`（只读探测）、`kernel/ih_hook_main.c` + `kernel/ih_hook_stub.S`（实做）。
两者都是**独立测试模块**，主模块 `susfs_guard_lkm` 未被改动。

---

## 1. 为什么考虑它

现有三层里两层的开销是"每次调用都付"：

| 层 | 机制 | 开销特征 |
|---|---|---|
| syscall 入口（8 个 `__arm64_sys_*`） | kprobe | arm64 kprobe 是 `brk` 异常，每次命中都要陷入+保存 pt_regs |
| getdents64 过滤 | `sys_exit` tracepoint | 挂在**所有** syscall 退出上 |
| LSM getattr/permission | 函数指针替换 | 接近零成本 |
| getname | kretprobe | 每次路径解析一次 |

"懒注册"只能做到**无规则零开销**；有规则时仍然每次付 kprobe 异常。inline hook 把代价
降到几条指令。

**`CONFIG_FUNCTION_TRACER is not set` 排除了 ftrace 这条路**（没有 `_mcount` 桩可改，也没有
`DYNAMIC_FTRACE_WITH_REGS`/IPMODIFY），所以只剩 kprobe 和改代码两条。

---

## 2. 先探测：哪些入口允许 patch（`ih_probe_test.ko`）

对 21 个候选入口读前 6 条指令，逐条分类（内核的 `aarch64_insn_is_*` 未导出，掩码照抄
`arch/arm64/kernel/insn.c`）。结果**全部一致**：

| 项目 | 实测值 |
|---|---|
| 首指令 | `d503233f` = **paciasp**（全部 21 个都是） |
| 我们窗口内的 PC 相对指令 | **无**（所以被覆盖的指令可以逐字复制进 trampoline） |
| 入口是否已是 BRK（被 kprobe/livepatch 占用） | **无** |
| 到模块 text 的距离 | **79–89MB** → 在 `B` 的 ±128MB 内 |

可解析的辅助符号：`set_memory_rw` / `set_memory_ro` / `set_memory_x` / `module_alloc` /
`aarch64_insn_patch_text` 都有；`text_poke`（x86 的）没有。

两个重要推论：

* `paciasp` **兼作 BTI landing pad**。入口被 syscall table（`blr`）间接调用，所以补丁必须
  自己提供 landing pad：补丁第一条写 `bti c`。
* 距离在 ±128MB 内 → 补丁可以只用 **8 字节**（`bti c ; b stub`）。但距离要**运行时校验**，
  不能假定；超范围时退化成 20 字节的 `bti c ; ldr x16,#8 ; ret x16 ; <addr>`。

---

## 3. 更重要的前提：哪些钩子点真的会被执行

这一条比"怎么 hook"更关键。五个看起来很合理的探针**注册全部成功、命中数为零**：

`inode_permission`、`generic_permission`、`walk_component`、`lookup_dcache`、`__lookup_slow`。

原因：GKI 的 full LTO 把它们内联进了调用者，kallsyms 里的符号只是**留给模块引用的 out-of-line
副本**。由此得到两条结论：

1. **对这些目标做 inline hook 同样无效** —— 会改到没人执行的代码。所以"用 jmp 代替 kprobe"
   之前，必须先确认目标被执行。
2. 在本内核上真正会命中的钩子点都是 **ABI 入口**或**跨编译单元/经函数指针调用**的函数：
   `__arm64_sys_*`、`vfs_open`、`vfs_getattr`、`show_map_vma`、`__arm64_sys_reboot`、
   `filename_lookup`、`getname`/`getname_flags`。
   反例：`do_filp_open` 被同文件的 `do_sys_openat2` 内联，探针零命中。

---

## 4. 机制

```
入口:   bti c                 ← 保留 landing pad（syscall table 用 blr 间接调用它）
        b <stub>              ← 8 字节；距离运行时校验
stub:   stp/stp ... 保存 x0-x18 + x30
        bl <decide>           ← C 判定，返回 1=隐藏 / 0=放行
        命中: 恢复 → mov x0,#-2 → ret
        放行: 恢复 → ret x16 → trampoline
tramp:  bti c                 ← 显式 landing pad
        <被覆盖的两条原指令>
        ldr x16, #8 ; ret x16 ; <entry+8>
```

细节与理由：

* **trampoline 必须放在 `module_alloc()` 的页里**，不能放模块自己的 `.text`：
  `ksu_patch_text()` 用 `phys_from_virt()`（走 `__pa` 语义）换算地址，对 vmalloc 区不成立。
  该页写完后再 `set_memory_ro` + `set_memory_x` 封存。
* **patch 内核 text 用 `ksu_patch_text()`**（它内部 `stop_machine` + icache flush）；
  **patch 模块自己的只读 text 用 `set_memory_rw` → 写 → `set_memory_ro`**。
* `bl decide` 之后必须**完整恢复 x0–x18**：放行路径要把原函数的参数原样交给它。
* 退出统一用 **`ret x16`**（`RET` 豁免 BTI 检查，`BR` 不豁免），trampoline 首部再加一条 `bti c`
  双保险。
* 卸载：恢复入口字节（`ksu_patch_text` 写回保存的原指令），trampoline 页**退役不释放**
  （可能有 CPU 还在里面执行）—— 与 open_redirect 的 retirement 同一思路。

---

## 5. 踩过的四个坑

按踩到的顺序，全部是**独立**问题：

### 5.1 寄存器：stub 调 C 函数后没有保存 x0–x18

AAPCS 下 x0–x18 是 caller-saved。第一次只保存了 x29/x30，于是放行路径把**被 C 函数破坏的
x0**（本应是指向 `pt_regs` 的指针）交给了原函数 → 崩。现象：panic 前日志只剩
`ih_hook: entry ...` 一行，之后全断。

**修**：`IH_SAVE_REGS`/`IH_RESTORE_REGS` 保存 x0–x18 + x30（`sub sp, sp, #160` 保持 16 字节对齐），
命中路径在**恢复之后**才写 x0 = -ENOENT。

### 5.2 kCFI：通过函数指针调用解析来的内核符号

```
Kernel panic - not syncing: CFI failure (target: module_alloc+0x0/0x120)
ih_patch+0x164/0x3a4 [ih_hook_test]
```

`module_alloc` / `set_memory_*` 是用 kallsyms 解析出地址后用函数指针调用的，kCFI 在**调用点**
校验目标的类型 hash。**内核源码里这类调用一律标 `__nocfi`**（KernelSU 的 `lsm_hook.c` 同样如此）。

**修**：涉及间接调用的三个函数加 `static __nocfi`。

### 5.3 BTI：`BR` 进 trampoline，而首指令不是 landing pad

自测目标（汇编函数）首指令是被复制的 `stp x29,x30,[sp,#-16]!` —— 不是 landing pad，
`br x16` 进去直接 branch target exception，位置在 `init_module`。内核入口恰好没暴露这个问题，
因为它们的 `paciasp` **兼作** landing pad。

**修**：① stub 出口改 `ret x16`（豁免）；② trampoline 首部显式 `bti c`。
两处独立，互不依赖。

### 5.4 环境陷阱：panic 之后 `/data/local/tmp` 的文件内容变成全 NUL

文件大小和元数据都在，内容却是 `\0`。`sh 一个全 NUL 的脚本` = 立刻结束、无输出、不报错，
于是被误判成"su -c 不执行脚本"。同一次崩溃还留下一个 40 字节全 NUL 的输出文件。

**教训**：设备 panic 后重新 push 并**校验**（`md5sum` 对比本地 / `head -c 60` 看内容），
push 后 `sync`。排查时先怀疑文件损坏，再怀疑逻辑。

### 5.5 附带发现：kCFI 下从 C 取函数地址拿到的是 `.cfi_jt` 桩

自测目标曾用 C 函数，`(unsigned long)func` 得到的地址前两条指令是 `bti c ; b`，即 kCFI 跳表
条目 —— patch 会打在桩上。探测输出：`prologue not understood: d503245f 17fffd7d ...`。

**修**：目标真实入口用汇编 `adrp/add` 计算。**内核符号不受影响**（kallsyms 给的是本体，
所以 `__arm64_sys_openat` 的探测结果是真正的 `paciasp`）。
副作用：`(unsigned long)ih_openat_stub` 拿到的也是桩，但桩本身就是合法跳转目标（`bti c`），
`b` 过去无害。

---

## 6. 实测结果

**Stage A：自测（hook 自己模块里的 `ih_test_target`，不碰系统热路径）**

```
step 1 baseline target(5) = 22
step 2 patch rc=0  tramp=ffffffd99af30000  saved=a9bf7bfd 910003fd   ← 真身，两条可复制指令
step 3 allow  -> target(5) = 22    ← 经 trampoline 放行，结果正确
step 4 hide   -> target(5) = -2    ← hook 命中
step 5 restored target(5) = 22     ← 恢复
STAGE A: PASS
```

**Stage B：真 hook `__arm64_sys_openat`**

| 场景 | 结果 |
|---|---|
| app 打开隐藏路径 | `No such file or directory`（由 inline hook 给出，非 kprobe） |
| root 打开同一路径 | 正常读到内容（门控只对 app） |
| rmmod 后 | 恢复 `EACCES` |
| 模块自身 dmesg | 只有 `hooked` / `answered ENOENT` / `restored`，**零 BUG/WARNING** |

---

## 7. 复现方式

```sh
ksud insmod /data/local/tmp/ih_hook_test.ko selftest=1 hook_syscall=0   # 只自测
ksud insmod /data/local/tmp/ih_hook_test.ko selftest=0 hook_syscall=1   # 真 hook
```

脚本：`t_ih3.sh`（自测未到 step 5 就**不动**真 syscall）、`t_ih.sh`（只读探测）、`t_lk*.sh`（dump 分析）。

环境注意：

* `su -c` **只接受一条命令**，多命令/引号会被吞 —— 一律写脚本文件再用 `su -c 'sh /path'`。
* 裸 `insmod` 会被 KernelSU 策略拒；用 `ksud insmod`。
* 设备 minidump 在 `/mnt/vendor/oplusreserve/media/log/minidump/SYSTEM_LAST_KMSG@...`，
  普通 adb 读不了，需 root `cp` 到 `/data/local/tmp` 再拉；里面的 kmsg 文本会被二进制块打断，
  用 `zcat | strings | grep`。

---

## 8. 未做 / 下一步

* **与 kprobe 互斥**：kprobe 会把入口首指令换成 `brk`，同一入口不能既挂 kprobe 又 inline hook。
  搬迁时必须同时摘掉对应的 kprobe。
* 把 syscall 层（8 个 `__arm64_sys_*`）从 kprobe 换成 inline hook；`getname` 与 getdents64 的
  过滤需要 **onLeave**（stub 先调 trampoline 进原函数、返回后再处理），比入口决策复杂。
* 性能对比：有/无 hook 的基准（kprobe 的实际开销尚未量化）。
* 主模块 `susfs_guard_lkm` 目前**尚未**使用 inline hook，保持 kprobe + 懒注册。
### 5.6 cpp 会把宏参数字符串化（本来只是 mov 的立即数）

IH_TAIL(idx) / SUSFS_IH_SYS_STUB(n, idx, argno) 展开后，汇编器报
invalid fixup for movz/movk。排查中先后误判为"符号取址"、"PLT"、"CRLF 让续行失效"，
全是错的：把**汇编器的真实输入**取出来看（clang -c -save-temps=obj），一眼就是

    mov w1, "1"        ; 宏体里写的是 mov w1, #argno
    mov w0, "0"        ; 宏体里写的是 mov w0, #idx

# 紧跟在宏参数前就是 **字符串化运算符**，参数被加上了引号，汇编器于是把字符串当地址去
movz/movk。mov x0, #-2 一直没事，正因为它的 # 后面不是宏参数。

**教训**：
- .S 的宏体里给立即数**不要写 #param**，写 mov w1, param 即可；
- clang -E -x assembler-with-cpp file.S 走的是**传统 cpp**，不展开函数式宏，
  输出只有十几行宏调用行 —— 拿它做诊断会被彻底带偏；
- 要诊断 .S，用 clang --target=... -c -save-temps=obj 保留中间 .s，并把它当构建
  产物导出；这一次就是靠它一次定位的。
### 5.7 判断 int 返回值只能看 w0

stub 里用 `cbz x0` 判断 C 判定函数（返回 `int`）是否为 0。AAPCS 只定义返回值的**低 32 位**，
高 32 位是寄存器里的残留。后果：**本该放行的 open 被判成隐藏**，表现为 `/dev/ptmx` 打不开 ——
adb 报 `failed to create pty master: No such file or directory`，注意是 ENOENT 而不是权限错误，
这正是"被我们的 hook 拒了"的指纹。改 `cbz w0` 即可。

**教训**：汇编 stub 判断 C 的语言级返回值时，寄存器宽度必须与类型匹配（int → w0，指针 → x0）。
这一条与 5.6 是同一类问题：**在汇编与 C 的边界上，寄存器宽度和 cpp 语义都要显式对齐，不能靠
"通常没问题"**。
