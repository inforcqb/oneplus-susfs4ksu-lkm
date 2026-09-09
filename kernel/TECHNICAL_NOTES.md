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
```

内核态 `struct kstat` 直接用字段名（`stat->ino` 等），无需硬编码。

## 五、调试方法

1. **逐层 kprobe 计数**（`kstat_probe_test.ko`）：对调用链每层挂 kprobe +
   计数器，定位 LTO 内联发生在哪一层。
2. **tracepoint 观察**（`syscall_test.ko`）：sys_enter/sys_exit 打印真实
   参数（filename/statbuf/返回值），看 syscall 到底在干什么。
3. 诊断日志**别用 `pr_info_ratelimited`**（5 秒 10 条，会吞掉关键输出）；
   用「命中才打印」的普通 `pr_info`。

## 六、已踩过的坑

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
