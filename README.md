# susfs4ksu-lkm

SUSFS 的**可加载内核模块（LKM）移植版**：让锁定 bootloader、只能漏洞 root 的 GKI 设备（CFI + PAC + BTI + SCS 全开）用上 SUSFS 的 root 隐藏能力，而不必重编译内核或刷 boot 镜像。

## 背景

上游 [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu) 是 KernelSU 的内核补丁，v2.0 起采用**编译期内联**（直接改内核源码树），要求能刷自定义内核。本仓库把它移植成一个独立 `.ko`：

- **构建**：用 Android DDK 预构建内核头（`ghcr.io/ylarod/ddk-min`），不需要完整内核源码树；CI 为每个 GKI 变体各出一份产物。
- **符号解析**：模块直接 `extern` 引用未导出符号，由加载器（`susfs_insmod` 或 KernelSU 的 `ksud`）在装载时把 kallsyms 里的运行时地址填进去。
- **hook 方式**：kprobe（入口/出口）+ `patch_memory`（改写只读内核内存与 fixmap）+ `lsm_hook`（LSM 挂载本身）。

## 功能

- **kprobe / kretprobe**：挂非导出内核符号的入口与出口（`/proc/mounts`、`/proc/<pid>/mountinfo`、`getdents64`、`statx` 等）。
- **`patch_memory`**：改写只读内核内存与 fixmap（文本补丁原语）。
- **`lsm_hook`**：LSM 挂载本身，两条路：
  - `sus_path` 的 13 个 hook 走**头插** —— 把自己的 `struct security_hook_list` 节点插到 `security_hook_heads`
    对应链表的**头部**（在 SELinux 之前），返回 0 让内核链继续调用 SELinux。因此不需要解析、也不需要回调
    SELinux 的原函数，也就不依赖各版本 CFI 方案下那个槽位里放的是什么（5.10/5.15 的 `.cfi_jt` 蹦床、6.1+ 的 kCFI hash）；
    插入的 hook 只可能增加拒绝，不会吞掉其它 LSM 的结论。
  - 其余 hook 走"替换槽位 + 保存原函数回调"（`hook->insert` 未置位时）。
  - 两条路都用 `__nocfi` 包住本模块发起的间接调用。
- **`symbol_resolver`**：运行期按名字解析内核符号（kallsyms 遍历 + kprobe 自举），所以模块可以直接引用未导出符号。
- **`sus_path`**：按路径隐藏（inode 层 + dirent 层 + name 操作），支持 `add` / `del` / `clear`；身份键为 `(dev, ino)`，
  inode 指针只作快路径缓存；注册时把目标 inode 放宽到 0777，删除时恢复。
- **`hide_modules`**：按名字把其它内核模块从 `/proc/modules`、`/sys/module/<名字>`、`/proc/kallsyms` 去掉。
- **`hide_mounts`**：可配置的挂载前缀表（决定哪些挂载算"我们的"），配合 `hide_sus_mnts_for_non_su_procs` 对非 su 进程隐藏。
- **`sus_mount`**：`statx` / `fdinfo` 的 `mnt_id` 改写、挂载表过滤、跨命名空间同步。
- **`sus_map`**：映射层（`maps` / `smaps` / `pagemap`）。
- **`sus_kstat`**、**`open_redirect`**、**`spoof_cmdline`**、**`avc_spoof`**、**`uname`**：对应上游各特性。
- **控制面**：`/proc/susfs_*` 节点 + 同名 sysfs 参数 + KernelSU 超调用；节点由模块自隐藏，非 root 一律 `ENOENT`。
- **六份 GKI 产物**：`android12-5.10` / `android13-5.10` / `android13-5.15` / `android14-5.15` / `android14-6.1` /
  `android15-6.6`，每棵树的 hook 原型与 API 差异按版本门控。
- **自带用户态加载器** `susfs_insmod`：不需要 KernelSU，也不需要内核补丁。

两个必须知道的取舍：

- **隐藏 ≠ 访问控制。** 本模块让路径名不可见（`ENOENT`），但不拦不经过路径名的通道：已经打开的 fd、注册规则之前
  持有的引用、注册前的硬链接/bind mount、以及按 `(dev, ino)` 工作的接口（`map_files`、`maps` 的 inode 面）。
  **不要用它保护真正敏感的数据。** 门控是 `uid >= 10000 且不是文件属主`：root、system(1000)、shell(2000) 本来就能看到
  全部隐藏路径，这是上游语义，不是漏洞。
- **隐藏路径的"存在性"仍可被测出。** 我们的拒绝发生在 DAC/SELinux 之前，返回耗时接近"路径存在"那一类；这个差值
  主要来自内核本身（正 dentry 比负 dentry 贵），但它仍给出 1 bit："这个我猜得到名字的路径存在、只是被拒了"。

## 加载

`.ko` 要选与设备内核对应的那一份，例如 5.15 设备用 `susfs_guard_lkm-android13-5.15.ko`。

**KernelSU 设备**：

```sh
ksud insmod /data/adb/loader/susfs_guard_lkm.ko
```

**非 KernelSU 设备**：用 release 附带的加载器 `susfs_insmod`（不需要 KernelSU，也不需要内核补丁）：

```sh
susfs_insmod /data/adb/loader/susfs_guard_lkm.ko
```

卸载：

```sh
rmmod susfs_guard_lkm
```

## 接口文档

全部 `/proc` 控制节点（读回格式、写命令、错误契约、以及它们共同遵守的三条规则：0777 让 DAC 让路、open/write 都查 uid、
由 sus_path 自隐藏给出 ENOENT）、`hide_modules` / `hide_mounts` 的命令、相关 sysfs 参数，以及加载与判断模块是否已加载的
注意事项，见 **[PROC_INTERFACES.md](PROC_INTERFACES.md)**。

换设备或换内核变体后，用 **[tools/verify-gki.sh](tools/verify-gki.sh)** 在那台设备上过一遍全部功能
（能否加载、13 个 hook 是否头插成功、计数是否增长、各隐藏面是否仍对 2000/10000 返回 ENOENT、普通规则是否仍只对 app 生效、
重载是否零告警、挂载层三条探针是否都挂上）：

```sh
adb push tools/verify-gki.sh susfs_guard_lkm-android14-6.1.ko susfs_insmod /data/local/tmp/
adb shell "su -c 'mkdir -p /data/adb/loader && cp /data/local/tmp/susfs_guard_lkm-android14-6.1.ko /data/adb/loader/susfs_guard_lkm.ko'"
adb shell "su -c 'sh /data/local/tmp/verify-gki.sh'"
```

## License

GPL-3.0，见 [LICENSE](LICENSE)。移植来源：[susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu)（功能逻辑与 hook 点）、
[SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra)（`patch_memory` / `lsm_hook` / `symbol_resolver`）。

## 免责声明

仅用于技术研究与学习。在自担风险的前提下使用。
