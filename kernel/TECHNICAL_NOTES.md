# SUSFS LKM 移植技术笔记

目标内核：OnePlus SM8550，5.15.180，Full LTO + CFI + BTI + PAC + SCS。
加载方式：`ksud insmod`（未导出符号走 kallsyms 重定位）。

## 一、LTO 内联是最大的坑

这个 GKI 内核把 `newfstatat` 整条链（`vfs_fstatat → vfs_statx → vfs_getattr →
vfs_getattr_nosec → cp_new_stat`）**全部 LTO 内联**进 syscall 入口。

实测逐层 kprobe 命中（`kstat_probe_test`）：
```
__arm64_sys_newfstatat: 命中
vfs_statx:              0   ← 内联
cp_new_stat:            0   ← 内联
vfs_getattr:            命中（但只覆盖 fstat/statx 等其它路径）
vfs_getattr_nosec:      0   ← 内联
generic_fillattr:       0
```

**结论**：要改文件系统类 syscall 的输出，只能 hook **syscall 层**（入口/出口），
VFS 层 kprobe 不可靠。

## 二、首选方案：sys_exit tracepoint

改 syscall 输出结果的标准模板：

```c
static void kstat_sys_exit(void *data, struct pt_regs *regs, long ret)
{
    unsigned long args[6];
    if (syscall_get_nr(current, regs) != __NR_newfstatat) return;
    if (ret != 0) return;
    syscall_get_arguments(current, regs, args);   // args[2] == statbuf
    /* copy_from_user 读原始值, 匹配规则, copy_to_user 改写 */
}
register_trace_sys_exit(kstat_sys_exit, NULL);
```

关键点：
- **`syscall_get_arguments()` 在 sys_exit 里仍能读回原始参数**（实测 MATCH=1），
  所以**不需要 per-cpu state、无竞态**，且只需 sys_exit 一个回调。
- 开销是 jump label，远轻于 kretprobe 的 BRK 断点 + 单步 + trampoline。
- tracepoint handler 运行在进程上下文，**可以安全 copy_to_user**。

## 三、kretprobe 作为后备

tracepoint 覆盖不到的路径（如 vfs_fstat 直接调 vfs_getattr），用 kretprobe 后备。
注意两个坑：

1. **syscall wrapper 不自动调整 regs**（本内核特有）：
   ```c
   /* regs->regs[0] 是 struct pt_regs* 参数，不是用户参数 */
   struct pt_regs *user = (struct pt_regs *)regs->regs[0];
   a->statbuf = user->regs[2];   /* 第 3 个用户参数 */
   ```
2. **kretprobe handler 在原子上下文**，但目标用户页面刚被原函数
   `copy_to_user` fault-in，所以二次 `copy_to_user` 不会 page fault（安全）。

## 四、结构体偏移

用户态 `struct stat`（arm64 `asm-generic/stat.h`）字段偏移：
```
st_dev=0  st_ino=8  st_mode=16  st_nlink=20  st_uid=24  st_gid=28
st_rdev=32  __pad1=40  st_size=48  st_blksize=56  __pad2=60  st_blocks=64
st_atime=72  st_atime_nsec=80  st_mtime=88  st_mtime_nsec=96
st_ctime=104  st_ctime_nsec=112
```

内核态 `struct kstat` 直接用字段名（`stat->ino` 等），无需硬编码。

**stat(1) 格式符陷阱**（验证 spoof 结果时极易看错）：
- `%o` = `st_blksize`（I/O 最优块大小，本机 4096）
- `%b` = `st_blocks`（512 字节块数）
- `%B` = **块单位**，恒为 512，**不是 st_blksize**
用 `%B` 判断 blksize spoof 会误报「没生效」。验证 blksize 用 `%o`。

## 五、/proc/susfs_kstat 接口（镜像原版 SUSFS 语义）

原版 SUSFS 的 kstat 是**按路径**的（不是按 ino 数字），且支持完整 12 字段
spoof + 每字段 `default` 保留原值 + flags 位图。LKM 用 proc 接口逐命令镜像：

```
add_sus_kstat <path>                         存当前 stat，flags=KSTAT_AUTO_SPOOF
add_sus_kstat_statically <path> <ino> <dev> <nlink> <size>
    <atime> <atime_nsec> <mtime> <mtime_nsec> <ctime> <ctime_nsec>
    <blocks> <blksize>                        每字段数字或 "default"
update_sus_kstat <path>                       只重解析 target_ino/dev
update_sus_kstat_full_clone <path>            同上 + NLINK|SIZE
del <path>  /  clear
```

实现要点：
- 规则 key 是 **(target_ino, target_dev)**，dev 存 **`new_encode_dev` 编码后**
  的值，使 tracepoint 热路径与用户 statbuf 的 `st_dev` 字段 1:1 比对，无需解码。
- 路径解析用 `kern_path(path, 0, &p)` + `d_backing_inode(p.dentry)`，
  需 `#include <linux/namei.h>` 和 `<linux/dcache.h>`。
- 填 spoof 值直接读 inode 字段（`i_ino/i_sb->s_dev/i_nlink/i_size/i_atime/...`），
  与 `generic_fillattr` 的映射一致；blksize 用 `1 << i_blkbits`。
- 上游 `KSTAT_SPOOF_CTIME_TV_SEC` 有个 typo（`1 < 8`），本移植修正为 `1 << 8`。
- `proc_create` 用 0666，但写操作要在 root 上下文执行；`su -c` 的重定向
  `>` 会被外层非 root shell 处理导致 Permission denied，正确姿势是
  `su -c 'sh -c "... > /proc/susfs_kstat"'` 或把命令写进脚本 `su -c 'sh 脚本'`。

## 六、open_redirect（vfs_open kprobe）

原版 hook `path_openat`（拿到 inode 后换 filename 重新 walk）。但用户 open 路径
上 `do_sys_openat2 → do_filp_open → path_openat` 全被 LTO 内联进 syscall 入口。
逐层探测（`open_probe_test.ko`）实测 `cat` 触发 123 次 openat 时各符号命中：

```
__arm64_sys_openat: 123   ← syscall 入口，可 hook
do_sys_open:        0     ← 内联
getname:            2     ← 只剩 shell 自己的调用
getname_flags:      0     ← 内联
do_filp_open:       0     ← 内联（用户路径不走它！）
vfs_open:           123   ← 唯一保留 out-of-line 副本的中间符号
do_dentry_open:     0     ← 内联
```

**教训**：kallsyms 里有 `T do_filp_open` 符号 ≠ 用户 open 路径经过它。它是留给
`exec.c` / `file_open_name` 的 out-of-line 副本；用户路径的 do_filp_open 被内联，
kprobe 挂上去 enter_count 恒 0。

**方案**：hook `vfs_open(path, file)`——inode 层，`path->dentry->d_inode` 已解析，
按 (target_ino, target_dev) 匹配（与原版一致）。

关键约束与设计：
- **kprobe pre_handler 跑在中断上下文（preempt disabled），不能 sleep**，所以不能
  在里面 `kern_path`。改为**在 add 规则时（proc write，进程上下文）就 kern_path
  解析并缓存 redirected 的 `struct path`**，pre_handler 只做纯内存操作。
- pre_handler 里 `regs->regs[0] = &cached_path`，vfs_open 会 `file->f_path = *path`
  拷贝，`do_dentry_open` 里 `path_get(&f->f_path)` 给 file 拿引用；entry 保留基引用，
  del/clear 时 `path_put`。**无需 kretprobe**。
- 引用计数：kern_path 拿 1 个引用（缓存基引用），do_dentry_open 的 path_get 给 file
  拿 1 个，两者独立，del 时只 path_put 基引用。
- uid_scheme 只有 0（non-app）可用；1..4 依赖 KernelSU 内部 su-domain/umount 状态，
  LKM 看不到，返回 -EOPNOTSUPP。

## 七、调试方法

1. **逐层 kprobe 计数**（`kstat_probe_test.ko` / `open_probe_test.ko`）：对调用链
   每层挂 kprobe + 计数器，定位 LTO 内联发生在哪一层。
2. **tracepoint 观察**（`syscall_test.ko`）：sys_enter/sys_exit 打印真实
   参数（filename/statbuf/返回值），看 syscall 到底在干什么。
3. 诊断日志**别用 `pr_info_ratelimited`**（5 秒 10 条，会吞掉关键输出）；
   用「命中才打印」的普通 `pr_info`。

## 七、avc spoofing（slow_avc_audit kprobe）

原版 hook `avc_audit_post_callback`（avc 日志里 target 是 su 域时把 tcontext 伪装
成 priv_app）。但实测该符号 kprobe enter 恒 0——它是 static，且 `common_lsm_audit`
（非导出）被 LTO 内联进 `slow_avc_audit`（noinline），函数指针常量传播后
`avc_audit_post_callback` 的调用点也被内联，kallsyms 里的 t 符号是残留。

**方案**：hook `slow_avc_audit(state, ssid, tsid, tclass, ...)`——它是 `noinline`
标记的 T 符号，必有 out-of-line 副本。tsid 是第 3 个参数（regs->regs[2]），直接
`regs->regs[2] = priv_app_sid` 即可，比改 sad 结构更简单，pre_handler 纯内存写。

**验证**：`su -c id` 显示当前 su 域是 `u:r:ksu:s0`（SukiSU），不是 KernelSU 官方的
`u:r:su:s0`——module_param `avc_su_ctx` 要按实际环境覆盖。sid 用 EXPORT_SYMBOL 的
`security_secctx_to_secid()` 在 init 时解析（进程上下文）。

**关键认知**：
- Android 的 avc denied **走 logcat（auditd），不进 dmesg**。验证 avc 功能要看
  `logcat -b all | grep avc`，不是 dmesg。
- avc spoofing 语义：隐藏 su 域**作为 target** 被访问的痕迹（`tcontext=u:r:ksu:s0`
  → priv_app）。su 域权限极高，日常几乎不产生 denied，hits=0 是正常的，不代表
  hook 没工作（用 enter 计数器确认 hook 命中即可）。

## 九、supercall ABI（reboot(2) 协议）

`ksu_susfs` 工具（和 SukiSU ksud）通过一个 reboot syscall 与内核通信：
```
syscall(SYS_reboot, 0xDEADBEEF, 0xFAFAFAFA, cmd_id, &mut payload)
```
内核写回 `payload.err`（0=成功，否则 errno 风格）。原版 SUSFS patch 了
`kernel/reboot.c` 的 SYSCALL_DEFINE4 分支进 `ksu_handle_sys_reboot()`；LKM 改 kprobe
`__arm64_sys_reboot` 自己匹配 magic。

关键约束：
- **arm64 syscall-wrapper quirk**：`__arm64_sys_reboot` 的 kprobe 里 `regs->regs[0]`
  是 `struct pt_regs *`（wrapper 的 `__regs` 参数），真实用户参数在
  `real_regs->regs[0..3]`（= SukiSU `PT_REAL_REGS()`）。
- **pre_handler 原子上下文不能 copy_from_user**，用 `task_work_add(TWA_RESUME)`
  延迟到进程上下文（SukiSU 同款）。
- handler 签名统一为上游 `void xxx(void __user **arg)`，`*arg` 是用户态 payload
  指针；handler 里 copy_from_user 读、copy_to_user 写 err 字段。
- SukiSU 内核已 hook reboot 但只处理 magic2=0xCAFEBABE（KSU 自己的），我们的
  0xFAFAFAFA 互不干扰，两个 kprobe 可共存。

验证方式：设备上 `ksud susfs version/status/features` 直接探测（返回 v2.3.0 /
true / 8 个 feature），功能命令用 no-libc 的 C 程序 `test_sc` 发 reboot syscall。

**A/B 陷阱**：上游 SUSFS_VERSION 是 "v2.3.0"、SUSFS_VARIANT 是 "GKI"（大写），
别照搬 sidex15 模块 README 里的 "1.5.2"（那是另一套 SUSFS 版本体系）。

## 十、ABI 对齐上游 builtin 的要点（含两项行为对齐）

ABI 必须与上游（susfs4ksu kernel_patches，即编译进内核的 builtin 版）逐字段一致，
否则用户态工具会读到错位数据。已对齐并通过三种独立方法验证（真实编译器逐字段
offset/size 断言、LP64 模型、Python packing 引擎）：

- **magic / CMD / 长度宏**全部一致；上游标记 deprecated 的 8 个 CMD 也已定义（不接
  handler）。
- **12 个 payload 结构体**字段序列完全一致。`sizeof`：sus_path 260、sus_map 260、
  sus_kstat 376（err@372）、uname 136（err@132）、log / avc / hide_sus_mnts 各 8、
  open_redirect 520（err@516）、cmdline 8196、version / variant 各 20、
  enabled_features 8196。
- 结构体名要与上游一致（`st_susfs_hide_sus_mnts_for_non_su_procs`）。
- uname 用 `__NEW_UTS_LEN+1`，不要硬编码 65。
- `KSTAT_SPOOF_CTIME_TV_SEC` 保持修正值 `(1 << 8)`；上游是 typo `(1 < 8)`，不要
  "同步"回去（用户态 ksu_susfs / ksud 用的都是正确的 bit 8）。

**行为**也要对齐，不只是布局：

1. **输入型命令只回写 `->err`**，不要 `copy_to_user` 整个结构体。上游 `fs/susfs.c`
   的 add/set 类 handler 只写 err 字段；回写整个结构体会越界写调用方的栈（调用方
   结构体可能更小或布局不同）。`show_*` 类命令才回写整个结构体（要返回字符串）。
2. **处理成功后 reboot(2) 应返回 0**。上游 patch 了 `kernel/reboot.c`：
   `ret = ksu_handle_sys_reboot(...); if (ret) goto orig_flow; return ret;`。
   LKM 不能 patch reboot.c，于是在 kprobe 里镜像：
   `regs->pc = regs->regs[30]; regs->regs[0] = 0; return 1;`（否则 reboot 会因为
   magic 非法而返回 -EINVAL）。

**验证工具说明**：sidex15 模块里预编译的 `ksu_susfs` 是很好的 ABI 消费者（能探测
`show version/variant/enabled_features` 并驱动各命令），但它对应 **SUSFS 1.5.x**
时代的 ABI——其 `st_susfs_sus_kstat` 字段顺序与 v2.3.0 不同（时间是 sec 三连排、
nsec 三连排，且 blksize 在 blocks 之前），因此它对 kstat/open_redirect 会报
`SUSFS operation not supported`。**这是工具版本问题，不是 LKM 的问题**：用与 v2.3.0
布局一致的调用方（SukiSU ksud，或本仓库的 `test_sc`）实测全部命令 err=0。

## 十一、sus_path 的匹配语义（2026-09-10 重写）

早期实现用一个 `hide_name` 字符串 + `strstr` 子串匹配，实测有三个严重缺陷（均已在设备上
复现）：

| 缺陷 | 现象 |
|---|---|
| 单条覆盖 | `add_sus_path A` 再 `add_sus_path B`，A 重新可见（B 覆盖了 A） |
| 子串误伤 | 添加 basename 为 `ksu` 的路径，连 `ksu_susfs`、`ksud-test` 一起被隐藏 |
| 全局同名误伤 | 添加 `/data/local/tmp/x`，全系统所有目录下名为 `x` 的条目都被隐藏 |

这三条合起来就是"我在路径隐藏里加了 `/data/local/tmp/susfs.ko`，但还能列出来"的直接原因：
路径管理器是按顺序逐条下发 `add_sus_path` 的，最后一条覆盖了 `susfs.ko`，于是它又可见了。

现在改为上游语义：

- `add_sus_path` 用 `kern_path(LOOKUP_FOLLOW)` 解析出 `inode`，记录
  `(i_sb->s_dev, i_ino, d_name)` 到一个**无上限链表**（去重、上限 8192 条）；
- getdents64 sys_exit 里用 `fdget(fd)` 取被列出目录所在 sb 的 `s_dev`，然后
  **按 `d_ino` 精确匹配 inode**，不再做子串匹配；
- 只对 `d_ino == 0` 的文件系统（罕见）退化为文件名精确 `strcmp` 兜底。

`CMD_SUSFS_ADD_SUS_PATH_LOOP` 直接走同一路径：上游 `_LOOP` 只是"zygote 起 app 后重新
打一次 inode flag"，本 LKM 的链表常驻、匹配无条件，两者天然等价。

与上游的唯一行为差异：上游 `susfs_is_inode_sus_path()` 有
`susfs_is_current_proc_umounted_app()` 门控，即**只有 app 进程**看不到该条目（root /
adb shell 仍看得到）。本 LKM 无条件隐藏，root 也看不到——对本 LKM 的使用场景更符合
直觉（用户就是要在自己的 root shell 里确认隐藏生效）。若将来需要严格对齐，把门控加回
`sus_path_is_hidden()` 入口即可。

调试用只读参数 `hide_list` 可打印当前所有已注册条目（`dev/ino/name`）。

### 与上游的能力鸿沟：上游会返回 -ENOENT，LKM 不会

**上游 `sus_path` 是双层的**，patch 了 `fs/namei.c` 三处（见
`kernel_patches/50_add_susfs_in_gki-android13-5.15.patch`）：

1. `link_path_walk()`：路径中间组件命中 sus_path 时
   `return -ENOENT;`（注释原文 "walking the sub path of sus path"）；
2. `__lookup_slow()` / `lookup_open()`：命中时不返回已找到的 dentry，而是
   `d_alloc_parallel(dir, &susfs_fake_qstr_name, &wq)` 重走一次查找，让文件系统
   因为 `..5.u.S` 不存在而**自然**返回 ENOENT（这就是 `susfs_fake_qstr_name` 的用途）；
3. 门控：`susfs_is_inode_sus_path()` 首行即 `susfs_is_current_proc_umounted_app()`，
   外加 `is_i_uid_not_allowed()` —— 只对 app 进程生效，root 仍可访问。

所以上游的效果是：**列目录看不到 + `stat`/`open`/`exec` 全部 ENOENT**。

**本 LKM 做不到这一点**：`fs/namei.c` 已编译进内核，无法 patch。我们只在
`getdents64` 出口过滤 dirent，因此**按已知路径的 `stat`/`open` 仍然成功**。
这是 builtin 版与 LKM 版最本质的能力差距，不要误以为"上游设计如此"。

要在 LKM 里补上，可行的替代是给路径类 syscall 的 wrapper 挂 kprobe，命中时短路：
`regs->pc = regs->regs[30]; regs->regs[0] = -ENOENT; return 1;`
（与本仓库 supercall 让 reboot 返回 0 用的是同一招，已在本内核验证可行）。
设备上 `__arm64_sys_newfstatat` / `_statx` / `_openat` / `_faccessat` /
`_readlinkat` / `_execve` / `_openat2` 符号均存在，具备实现条件。局限：只能拦绝对路径
（pre_handler 里拿不到 dfd），且只能做字符串比较，不解析 `..` 与符号链接。

**推论（安全建议不变）**：把 root 工具放在 `/data/local/tmp`
（`shell_data_file`，appdomain 被允许 `file read`）在**本 LKM** 下永远不安全——正确做法是
放 `/data/adb`（`adb_data_file`，appdomain 完全无权访问）。

## 十二、LSM hook 让路径访问返回 ENOENT（已实测可用）

上面那条 LKM 能力差距**已经补上了**，方案不是枚举 syscall，而是替换两个 LSM hook。
实测（`kernel/selinux_hide_probe_main.c`，本内核 android13-5.15）：

| hook | 替换目标 | 覆盖 |
|---|---|---|
| `inode_getattr` | `selinux_inode_getattr` | `stat` / `fstatat` / `statx` |
| `inode_permission` | `selinux_inode_permission` | `open` / `exec` / `unlink` / `chmod` / 列目录 … |

`vfs_getattr()` 在碰 inode 之前就先调 `security_inode_getattr()`，所以 stat 必过此路；
而 `inode_permission` 是所有路径操作的门。**无需枚举任何 syscall。**

匹配用 **inode 指针**，因此下列绕过**全部实测失效（都返回 ENOENT）**：
直接路径、`//`、`./`、相对路径、符号链接（`stat -L`）、**硬链接**（同 inode）、
`/proc/self/root/...`。对照组文件与目录列表完全正常。

实测能力：`ls -l` / `cat` / `>> 追加写` / `chmod` / `test -e` 全部 ENOENT；
`disarm` 后立即恢复；性能零影响（`ls /system/bin` 0.02s）。

### kCFI 教训（用两次内核 panic 换来的）

**replacement 函数的签名必须与 hook 类型逐字匹配，而且绝对不能加 `__nocfi`。**

本内核用 **kCFI 做跨模块检查**：调用点比对被调函数的类型哈希。

- 签名不匹配 → `CFI failure (target: ...cfi_jt)` → **panic**
- 加 `__nocfi` → 函数根本不生成类型哈希 → `__cfi_check_fail` → **同样 panic**

panic 现场形如：

```
Kernel panic - not syncing: CFI failure
  (target: susfs_test_inode_permission.cfi_jt+0x0/0x8 [selinux_hide_probe])
__cfi_check_fail+0x54/0x58 [selinux_hide_probe]
__cfi_slowpath_diag+0x110/0x4d0
cfi_module_add+0x0/0x2c
```

`lsm_hook.c` 注释里 "an __nocfi replacement" 的说法照搬自 KernelSU，**在本内核不成立**。
`inode_getattr` 一开始就能用，恰恰是因为它**没加** `__nocfi` 且签名正好匹配。

### 用编译期断言代替猜签名

内核自己暴露了权威类型，不要靠打印或推断：

```c
#define LSM_HOOK_FN_TYPE(member) typeof(((union security_list_options *)0)->member)

static_assert(__builtin_types_compatible_p(LSM_HOOK_FN_TYPE(inode_permission),
                                           typeof(&susfs_test_inode_permission)),
              "inode_permission hook signature mismatch");
```

两个坑：

1. 必须取地址 `typeof(&fn)`。hook 字段是**函数指针**类型，而 `typeof(函数名)` 是
   函数类型，`__builtin_types_compatible_p` 判定二者**永不相等**——写错时会打印出
   两个**完全相同**的类型却报 mismatch，极具迷惑性。
2. 5.15 的真实类型是 `int (*)(const struct path *)` 与
   `int (*)(struct inode *, int)`——`mnt_userns` 参数是 **6.3** 才进 LSM hook 的，
   别按新内核写。

这样签名错误会变成**编译失败**，而不是又一次重启。

## 十三、测试工具链陷阱（这里浪费了最多轮次）

1. **`adb shell` 的 stdout 是管道，全缓冲**。脚本被中断时，已打印的内容**全部丢失**，
   看起来像"卡在第一步"，实际早已跑完。→ 测试脚本一律
   `exec > /data/local/tmp/out.txt 2>&1`，再单独 `cat` 该文件。
2. **PowerShell 包 `adb` 的长命令会"假死"**：adb 客户端超时断开后，设备端 shell 变成
   **ppid=1 的 R 状态孤儿**，卡在写已经没人读的 stdout 上。**命令其实已经执行了**
   （dmesg / 模块状态可证）。→ 判断是否真的执行要看 dmesg 和模块状态，
   **不要只看 stdout**。
3. 这些孤儿进程持有 `/proc/<模块>` 文件的引用，会让后续 `rmmod` 卡在
   `proc_remove()` 上**永远等下去**。→ **rmmod 前先 kill 它们**（`ps -A -o pid,args`
   找 `sh -c ...` 的孤儿）。
4. 写 `/proc` 的 `single_open` 开关时，`echo x > /proc/...` 与后续命令放同一条
   `su -c '...'` 里更容易触发上面第 2 条的假死。→ 分步、独立执行。

## 十四、已踩过的坑

- `module_param(var)` 注册的参数名是变量名，要 `module_param_named(name, var, ...)`。
- 5.15 的 dcache flush 用 `dcache_clean_inval_poc` / `caches_clean_inval_pou`，
  不是旧的 `__flush_dcache_area`。
- `phys_from_virt` 必须保留 `pmd_leaf`/`pud_leaf`/`p4d_leaf` 大页检查，
  否则 2MB section 映射会被当成页表解引用。
- 内核 KBuild 默认 `-Werror`，需加 SukiSU 同款 `-Wno-declaration-after-statement
  -Wno-int-conversion` 等。
- SELinux 私有头路径：`-I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
  -I$(objtree)/security/selinux`（flask.h 是生成头，在 objtree）。
- **`init` 有条件注册、`exit` 无条件 unregister 会 panic**（unregister 一个从未
  register 的 kretprobe/kprobe → NULL 解引用）。每个功能都要用
  `static bool *_registered` 标志配对 register/unregister。
- 一个 `.ko` 里多文件（`susfs-objs := a.o b.o ...`）时，只有主文件可以有
  `module_init/module_exit`；其余文件的 init/exit 必须是**非 static** 的普通函数
  （供主文件调用），否则 duplicate symbol 或链接失败。
- **`gh run download` 参数错误会静默失败**，stderr 只弹 usage/Flags，且 `--dir`
  指向的旧文件仍在，于是把旧 `.ko` 推到设备反复测试「没生效」。下载后务必比对
  `.ko` 大小/字符串（新 commit 的格式化字符串是否在里面）再推送。
- **sys_exit tracepoint 里 `regs->regs[0]` 已经是返回值**，不是第一个参数。想拿
  原始参数只能用 `args[1]` 及之后（`sus_path` 的 getdents 过滤依赖这一点）。
- `module_param_custom(name, ops, perm)` 在 DDK 头文件里不可用（clang 报
  `expected identifier`），换 `module_param_cb(name, &ops, NULL, perm)`。
- 给同一模块重复 `arm` 时，`kern_path` 拿到的 inode 要 `ihold` 住，否则 dentry 释放后
  inode 可能被回收导致指针悬空。
