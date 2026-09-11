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

**Stage C：主模块 `susfs_guard_lkm`，修掉 5.8 的 LR 之后（SM8550 / 5.15.180 GKI）**

先逐条隔离（`ih_only=n ih_secs=12 no_extra=0`，其余层全在），`su 10123` 侧检查：
八条全部 `survived`，uptime 连续、`cpus=8` 全程不变，`/dev/ptmx` 始终 `PTMX_OK`。

再按生产形状一次装八条（`ih_enabled=1 ih_secs=25 no_extra=0`）：

| 检查 | 结果 |
|---|---|
| 安装 | `inline hooks armed (8 entries patched)`，八条 `hooked` 全成功 |
| app `cat`（openat） | `No such file or directory` |
| app `ls -l` / `stat`（newfstatat、statx） | `No such file or directory` |
| app `test -r`（faccessat） | `NOPE` |
| app 执行该文件（execve） | `inaccessible or not found` |
| app `/dev/ptmx` | `PTMX_OK`（放行路径正常，5.8 的直接反证） |
| root 四个 syscall | 全部正常可见（`7 -rw-------`） |
| 存活 | 8 CPU 全程在线，uptime 连续，无 BUG/WARNING |
| 25 s 定时回滚 | 八条依次 `restored`，随后 openat 回落到 LSM 层给 `Permission denied`（分层协作正确） |
| `rmmod` | 干净，app 回到 `Permission denied`，root 正常 |

脚本：`t_ihA.sh`（no_extra=1 的最小验证）、`t_ihAll.sh`（逐条 `1..8`）、`t_ihFull.sh`（八条一起）。

**Stage D：最终形状（九条入口，默认参数，全部层都在）**

第 9 条是 `getname_flags` 的 onLeave hook（见 5.11）；隐藏文件用 `0644`（见 5.12）。

| 检查 | 结果 |
|---|---|
| 安装 | `inline hooks armed (9 entries patched)`，九条 `hooked` 全成功 |
| 未被 ih 覆盖的层 | `path layer armed (filename_lookup=1 do_filp_open=1 user_path_at_empty=1)`、`32-bit syscall layer armed (2/7 compat probes)` —— 它们的目标符号不同，继续用 kprobe，不会被 ih 挤掉 |
| app `cat` / `ls -l` / `stat` / `test -r` / 执行该文件 | 全部 `No such file or directory` / `NOPE`（openat、newfstatat、statx、faccessat、execve 五条入口 + getname 层） |
| root | `secret`、`7 -rw-r--r--`，完全不受影响 |
| app 其它路径（`/dev/ptmx`、`ls /system/bin`） | `PTMX_OK` / `LS_OK`，放行路径正常 |
| 存活 | 8 CPU 全程在线，uptime 连续，ring buffer 里无 `CFI failure` / `BUG` / `WARNING` |
| 第二条规则 / 卸载再装 | 同一条热路径再来一次仍然正常 |
| `rmmod` | 干净恢复：app 又能读到 `secret`，`/dev/ptmx` 正常 |

脚本：`t_ihFinal.sh`（默认参数全量）、`t_ihName2.sh`（第 9 条 + 调用计数诊断）、`t_dump.sh` / `t_dump2.sh`（minidump 分析）。

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
  搬迁时必须同时摘掉对应的 kprobe。主模块里的做法：`sus_path_ih_register()` 只要有一条装不上，
  就整体回滚并改走 kprobe（`sus_path_hooks_arm()`）。
* **这批已经搬完**：8 个 `__arm64_sys_*`（openat / openat2 / newfstatat / statx / faccessat /
  faccessat2 / readlinkat / execve）现在默认走 inline hook（`ih_enabled=1`），
  加上 `getname_flags` 的 onLeave（第 9 条）。
* **有意留在 kprobe 上的**：`filename_lookup` / `do_filp_open` / `user_path_at_empty`
  （path 层）与 7 个 `__arm64_compat_sys_*`（32 位层）。它们的目标符号和 ih 那九条不同，
  不冲突，所以 ih 上线后它们照常注册 kprobe —— 32 位这一层尤其不能丢：32 位调用者的
  syscall 入口探针读不到用户路径（`-EFAULT`），getname 层才是它们的决策点。
* **卸载时的原子性**：入口的 8 字节是两次 4 字节写入（`bti c` 与 `b stub`）。目前
  `ksu_patch_text` 的 `stop_machine` 让"同时执行"不可能发生，但一个 CPU 恰好停在
  entry 的 4 字节中间被停住时，恢复后可能只执行第二条。彻底的做法是分两阶段写
  （装：先写 `b stub` 再写 `bti c`；卸：先写回 `orig[0]` 再写回 `orig[1]`），
  每一步之后各自跨核 flush，两个中间态都是可正确执行的组合。
* 性能对比：有/无 hook 的基准（kprobe 的实际开销尚未量化）。
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

### 5.8 放行路径丢了调用者的 LR（设备"装完就死"的真正原因）

这是主模块上一版**装完立刻卡死**的根因。`IH_SAVE()` 把原始 LR 存到了 `[sp, #160]`：

```
str x30, [sp, #160]
```

但放行路径的 `IH_TAIL()` 只调用了 `IH_RESTORE_ARGS()`（恢复 x0–x18 + NZCV），**没有恢复 x30**。
于是：

```
stub: bl susfs_ih_decide      -> x30 被改成 decide 的返回地址
      IH_TAIL: br x16         -> 进 trampoline 时 x30 还是那个返回地址
tramp: orig[0] = paciasp       -> 用错误的 LR + 当前 SP 做签名，压回栈
```

目标函数最后用**它自己的** `paciasp` 配对 `autiasp` 恢复 LR：进 trampoline 时 replay 的
`paciasp` 已经写好了签名值（签的是 `decide` 的返回地址），第二次 `paciasp` 再覆盖一次，
函数返回时 `autiasp` 校验的是"最后一次入栈的签名 LR"—— 栈上那条对应的是 192 字节帧下的
旧 SP，与函数内部的 SP 不一致，**校验必然失败**；即使不 panic，返回地址也已经不是调用者的
LR。命中隐藏的路径**没事**，因为 `IH_HIDE()` 一直都恢复了 x30 再 `ret`。

为什么测试模块从来没暴露：

* 测试模块 hook 的是自己模块内的 `ih_test_target`，只有显式调用时才走 stub；
* `__arm64_sys_openat` 是**全系统最热的入口之一**，`add_sus_path` 触发的安装刚返回，
  下一个毫秒就有别的进程走进 allow 路径 —— 所以现象是"install 日志打印完就死"，
  而不是"调用隐藏路径才死"。这也解释了为什么失败现场总是在离 openat 很远的地方
  （proc/tracepoint 注册路径）。

**教训**：

* "保存了"不等于"恢复了"。`IH_SAVE` 存 x0–x18 **和** x30、NZCV 共 20 个值，
  `IH_RESTORE_ARGS` 只负责 x0–x18 + NZCV，**每个消费点都要自己把 x30 取回来**；
  更稳的写法是把"必须恢复"的清单写在宏旁边，改 `IH_SAVE` 时同步核对。
* **热入口会把任何微小错误放大成崩溃**。同样一段 stub 挂在只调用一次的模块内函数上跑一万遍
  也不会有事，挂在 openat 上第一个毫秒就炸 —— 所以冷路径自测通过**不能**作为热路径可用的证据，
  隔离测试必须用真的热入口（`ih_only=1` 就是为此而留）。

### 5.9 `on_each_cpu` 不是符号，于是"跨核 flush"空转了一整个版本

代码写的是：

```c
pfn_on_each_cpu = find_kernel_symbol_exact("on_each_cpu");
...
if (!rc && pfn_on_each_cpu) { ...; pfn_on_each_cpu(susfs_ih_remote_flush, NULL, 1); }
```

5.15 的 `include/linux/smp.h` 里 `on_each_cpu()` 是 **static inline** 包一层
`on_each_cpu_cond_mask()`，**kallsyms 里根本没有这个符号**，所以解析永远返回 NULL，
`if` 永远不成立，跨核 flush 从加进去那天起就没执行过 —— 表现却是"看起来一切正常"：
只有 `ksu_patch_text` 的本核 flush 在起作用，其它核继续跑各自 I-cache 里的旧指令
（这甚至"侥幸安全"：它们看不到半更新的指令流）。

三条修正，缺一不可：

1. 用真实符号 `smp_call_function`（内核确有导出），它跑**其它** CPU，本核由调用者自己刷；
2. `susfs_ih_ready()` 把它列为**必需** —— 解析不到就安装失败，而不是静默降级成单核 flush；
3. **给调用它的函数加 `__nocfi`**（见 5.10）。

### 5.10 CFI failure：通过函数指针调用解析来的符号

修完 5.9 立刻吃到第一个 panic：

```
susfs_ih_install+0x2c0/0x4f4 [susfs_guard_lkm]
Kernel panic - not syncing: CFI failure (target: smp_call_function+0x0/0x8c)
```

`susfs_ih_flush_range_remote()` 通过函数指针调 `smp_call_function`，但没标 `__nocfi`：
kCFI 在该间接调用点校验目标前的类型哈希，而 `pfn_smp_call_function` 的类型是
`void (*)(...)`、真身是 `int (*)(...)`，哈希对不上 → panic。**这条路径以前从没执行过**
（5.9 的 `if` 恒假），所以从来没暴露。

**规则**：凡是"用解析出来的内核符号地址作函数指针调用"的函数都要 `__nocfi`（`susfs_ih_init_impl`、
`build_tramp`、`write`、`install_impl`、`uninstall_impl`、`flush_range_remote` 全部如此）。
反向的一条同样重要：**内核回调我们的函数**（`smp_call_function(func, ...)` 里的 `func`）
**不能**标 `__nocfi` —— 那样模块函数就没有类型哈希，内核在它的间接调用点上会读到垃圾而 panic。
回调签名必须与内核期望的类型一致（`void (*)(void *)`）。

顺带：`set_memory_*`、`module_alloc`、`synchronize_rcu_tasks` 在本内核 kallsyms 里都存在
（`on_each_cpu` 是唯一的例外），`synchronize_rcu_tasks` 用于卸载时的在途宽限。

### 5.11 符号存在 ≠ 会被执行：`getname` 与 `getname_flags`

把 getname 的 onLeave hook 接上去之后：安装成功、设备不崩、`after-handler` 的命中计数**恒为 0**，
app 拿到的还是 LSM/DAC 层的 `EACCES`。原因是 5.15 的

```c
struct filename *getname(const char __user *filename)
{ return getname_flags(filename, 0, NULL); }
```

在 LTO 下被内联进调用者，`getname` 这个符号在 kallsyms 里存在、但**没有任何调用点**，
patch 它等于 patch 一段死代码。真正执行的是 `getname_flags`（kallsyms 地址 `...c0614`，
非页对齐，正是函数本体而非 `.cfi_jt` 桩）。

诊断手段值得保留：在 after-handler 里对前几次调用无条件打印返回值与 `f->name`，
一眼就能区分"没被执行"和"执行了但没命中"：

```
sus_path: getname_flags returned ffffff80072be000 (name=/data/user/0/.../msf_lifecycle_monitor.xml)
```

换成 `getname_flags` 之后立刻命中：`uid 10123` 的 `cat` 得到 `No such file or directory`，
root 照常读到内容。

**教训**：这条内核上"入口是否真的被执行"必须实测（LTO 把 stderr 里的直觉全推翻了，
`inode_permission`/`generic_permission`/`walk_component`/`do_filp_open` 都是同一类符号）。

### 5.12 测试文件权限会掩盖结论

同一个 getname hook，隐藏文件是 `0600` 时 app 得到 `EACCES`（内核自己的 DAC 检查在
`security_inode_permission()` **之前**就拒了），是 `0644` 时才轮到我们的层说话、给出 `ENOENT`。
所以"onLeave 层是否生效"这类验证**必须用 DAC 放行的权限**（0644），否则看到的是 DAC 的答案。
