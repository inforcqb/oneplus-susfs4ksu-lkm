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

## 八、已踩过的坑

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
