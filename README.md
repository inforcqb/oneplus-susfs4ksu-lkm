# susfs4ksu-lkm

SUSFS 的**可加载内核模块（LKM）移植版**，目标是让锁定 bootloader、只能漏洞 root 的 GKI 设备（CFI + PAC + BTI + SCS 全开）也能用上 SUSFS 的 root 隐藏能力，而无需重编译内核或刷 boot 镜像。

## 背景

上游 [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu) 是 KernelSU 的内核补丁，v2.0 起采用**编译期内联**（直接 patch 内核源码树），要求能刷自定义内核。本仓库把它移植为独立 `.ko`：

- **构建**：用 Android DDK 预构建内核头（`ghcr.io/ylarod/ddk-min`），无需完整内核源码树。
- **符号解析**：模块直接 `extern` 引用未导出符号，由 `ksud insmod` 加载时通过 kallsyms 重定位。
- **hook 方式**：kprobe（入口/出口） + `patch_memory`（改只读内存/fixmap） + `lsm_hook`（LSM 挂载本身）。
  `lsm_hook` 现在有两条路：`sus_path` 的 13 个 hook 走**头插**——把自己的 `struct security_hook_list` 节点插到
  `security_hook_heads` 对应链表的**头部**（在 SELinux 之前），返回 0 就让内核链继续调用 SELinux，因此函数指针仍由我们写、
  但**不再需要解析并回调 SELinux 的原函数**（也就不再依赖各版本 CFI 方案下的符号形态：5.10/5.15 的 `.cfi_jt` 或 6.1+ 的 kCFI hash）；
  其余仍走"替换槽位 + 保存原函数回调"的路径（`hook->insert` 未置位时）。两条路都用 `__nocfi` 包住我们发起的间接调用。

## 已验证的能力（在目标 GKI 设备上实测）

| 能力 | 结论 |
|---|---|
| kprobe/kretprobe hook 非导出符号 | ✅ |
| 读/写 SELinux 私有结构体（`selinux_state`） | ✅ 偏移精确匹配 |
| `ksud insmod` 重定位未导出符号 | ✅ |
| patch 只读内存 + 改 LSM 函数指针（CFI 穿透） | ✅ |
| **13 个 sus_path hook 头插进 `security_hook_heads`** | ✅ 实测：13/13 条 `inserted <hook> as the first node of its list (head …, before …, replacement …)`，`before` 指向的正是 SELinux 自己的节点；一次 `rmmod` 对应 13 条 `removed … node from its list`；随后 3 轮 `rmmod`+重载中 `BUG:/WARNING:/Oops/CFI failure/list corruption/general protection` 计数为 0，且 `hide_list` 计数在非 root 探测时照常增长（钩子确实在跑） |

## 构建

```sh
# 在 GitHub Actions 里（推荐）
# .github/workflows/build-ddk.yml 使用 ddk-min 镜像

# 本地（需有 DDK 内核头目录 $KDIR）
make -C $KDIR M=$PWD/kernel ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules
```

## 加载

**推荐：用本仓库自己的加载器，不需要 KernelSU。** 从 release 取对应变体的 `.ko` 与 `susfs_insmod`：

```sh
# 内核版本对应的那一份，例如 5.15 设备用 susfs_guard_lkm-android13-5.15.ko
susfs_insmod /data/adb/loader/susfs_guard_lkm.ko
# 卸载
rmmod susfs_guard_lkm
```

也可以继续用 KernelSU 的加载器（两者等价，任选）：

```sh
ksud insmod /data/adb/loader/susfs_guard_lkm.ko
```

**为什么不能直接用裸 `insmod`。** 实测（OnePlus SM8550 / 5.15 vendor 内核），同一个文件：

```
# toybox insmod /data/adb/loader/susfs_guard_lkm.ko
insmod: failed to load ...: No such file or directory        ← 这是内核模块加载器返回的 -ENOENT，不是文件不存在
dmesg: 10 行 "Unknown symbol ... (err -2)"
  init_mm / kallsyms_lookup_name / strnlen_user / saved_boot_config / task_work_add /
  security_secctx_to_secid / __set_fixmap / copy_to_kernel_nofault /
  dcache_clean_inval_poc / kallsyms_lookup

# susfs_insmod /data/adb/loader/susfs_guard_lkm.ko
undefined symbols: 96 → resolved 96/96; unresolved 0
loaded → OK: /sys/module/susfs_guard_lkm exists            ← rc=0，模块起来，功能照常
```

原因分两类，都被实测过：

- **命名空间导入**：`kern_path` / `ihold` / `override_creds` / `revert_creds` 在 GKI 构建里是
  `EXPORT_SYMBOL_NS(…, ANDROID_GKI_VFS_EXPORT_ONLY)`，而各树的 `Makefile` 会在编译前把这个名字改写成那个长串。
  不导入**改写后的串**就会被内核拒绝（`… but does not import it` → `Unknown symbol … (err -22)`）。源码里已经加了
  `MODULE_IMPORT_NS(VFS_internal_I_am_really_a_filesystem_and_am_NOT_a_driver)`，CI 还会断言它真的进了产物的 `.modinfo`。
- **导出表里根本没有的符号**（上面列的那 10 个）：直接 ELF 引用**永远**解析不了，任何加载器都救不了 ——
  除非像 `susfs_insmod`（和 KernelSU 的 `ksud`）那样，在用户态把每个未定义符号就地改写成
  **`SHN_ABS` + `/proc/kallsyms` 里的运行时地址**再调 `init_module(2)`。内核的 `simplify_symbols()` 只对 `SHN_UNDEF`
  做解析，`SHN_ABS` 直接跳过 ⇒ `Unknown symbol`、命名空间检查、CRC 校验全都不适用。这条路**不需要任何内核补丁**，
  只要 root + 可读 `/proc/kallsyms`；作为非 root（或 `kptr_restrict=2` 且改不动 sysctl）时它会看到全零地址并**拒绝加载**。

顺带：DDK 构建出来的 vermagic 是 `5.15.202-…` 而设备跑 `5.15.180-…`，这**不**是障碍 ——
本模块的 `__versions` 段存在（大小为 0）会让 `same_magic()` 只比较第一个空格之后的尾巴。加载器仍保留"内核真的抱怨
vermagic 时，从 `/dev/kmsg` 读出期望值、就地改写 `.modinfo` 后重试一次"的兜底（已用改坏的副本验证过）。

### 怎么判断它是否已经加载（**不要用 `lsmod`**）

模块会把自己的那一行从 `/proc/modules` 里去掉，而且**对所有调用者都一样，root 也不例外**——上游 builtin 内根本没有"模块条目"这回事，只对非 root 隐藏的话，root 的 `lsmod` 仍会留下 builtin 不存在的痕迹。因此：

```sh
lsmod | grep susfs            # 永远是 0 行，不代表没加载
ls -d /sys/module/susfs_guard_lkm   # ← 这个才代表已加载（root 可见）
ls /sys/module/susfs_guard_lkm/parameters/   # 参数节点在，也说明已加载
```

重复 `insmod` 会因为模块已在内存里而失败（`init_module failed: File exists (os error 17)`，即 `-EEXIST`）；想重载就先 `rmmod susfs_guard_lkm`。

**模块没加载时，`ksu_susfs add_*` 会报"不支持"而不是"没加载"**：

```
[-] CMD: '0x555c0', SUSFS operation not supported, please enable it in kernel
```

原因：内核若没有接管 reboot supercall，`reboot(2)` 直接返回 `-EINVAL`，而工具只看 `payload.err` ——
它自己预置的 `126`（`ERR_CMD_NOT_SUPPORTED`）原封不动，于是"没人应答"被显示成"内核不支持"。
判断办法同上（先确认 `/sys/module/susfs_guard_lkm`），必要时看 dmesg 里有没有
`susfs_guard_lkm: loaded.` 这一行。

`add_open_redirect` 需要**三个**参数（工具自己的 usage 少印了第三个）：

```sh
ksu_susfs add_open_redirect <target> <redirected> <uid_scheme>   # uid_scheme: 0..4
```

## hide_modules：按名字隐藏其它内核模块

`/proc/modules` 是 0444、任何进程都能读，而且按名字列出**每一个**已加载模块——所以一个读它的检查器能看到全部，包括正在做隐藏的那个模块。`hide_modules` 维护一份**模块名列表**，把列表里的名字从这些地方去掉：

| 面 | 效果 |
|---|---|
| `/proc/modules` | 该模块的行被过滤掉，**对所有读者都一样，root 也不例外**（检查器很可能就是 root，而它比对的就是这份列表）；计数在控制接口里可读 |
| `/sys/module/<名字>` | 以 sus_path 的 `self_protect` 规则注册 ⇒ 非 root 调用者的 stat/open/readdir 得到 `ENOENT`；root 仍可见（那是模块参数所在的地方）——这是唯一需要知道的不对称 |
| `/proc/kallsyms` | `module_name` 匹配的那些行同样被过滤（对所有读者） |

### 控制接口（两个前端、同一份列表）

```sh
# /proc 节点：只接受命令（root），其它调用者得到 ENOENT
echo "add kernelsu"            > /proc/susfs_hide_modules   # 加一个名字
echo "del kernelsu"            > /proc/susfs_hide_modules   # 去掉一个
echo "set kernelsu frida"      > /proc/susfs_hide_modules   # 整份替换
echo clear                     > /proc/susfs_hide_modules   # 一个都不隐藏（调试模式）
cat /proc/susfs_hide_modules                                # 看状态：列表 + 计数

# 模块参数：同样的命令，另外还接受裸列表（insmod 就是这么传值的）
ksud insmod susfs_guard_lkm.ko hide_modules=kernelsu,frida
echo "add frida" > /sys/module/susfs_guard_lkm/parameters/hide_modules
```

节点遵循本项目其它控制节点的约定：**0777**（这样 DAC 会让路，唯一给出回答的是 sus_path 的隐藏集合 ⇒ `ENOENT`，与"没有这个文件"无法区分），并在 `open()` **和** `write()` 里都做 uid 检查（传出去的 fd 不能成为入口），同时登记在 sus_path 的自隐藏集合里：非 root 的 `cat` 与 `>` 重定向都是 `No such file or directory`（已在设备上验证）。

默认列表只有**本模块自己**：builtin 版 SUSFS 没有模块条目，留一个下来就是上游没有的痕迹。`clear` 是排查用的模式（`lsmod` 会重新列出本模块）。

**另一个边界（实测）**：只过滤"这个模块自己的那一行"。如果别的模块**依赖**它，`/proc/modules` 的"used by"列里仍会出现它的名字，例如隐藏 `explorer` 之后：

```
camera 10440704 35 explorer, Live 0x0000000000000000 (OE)
```

要连这一列一起抹掉，需要在 `m_show` 的**返回**处改写那一行（本模块在别处已有这类改写工具），代价是新加一个 kretprobe 与缓冲改写；当前版本不做，按"只有被依赖的模块才会漏"记在这里。
已知边界：给一个**尚未加载**的模块名时，`/proc/modules` 的行照样会被过滤，但 `/sys/module/<名字>` 此刻还不存在，那条 sus_path 规则加不上——节点里会记 `failed=` 并写出原因，模块加载后重新 `add` 一次即可（或用 `add_sus_path_loop /sys/module/<名字>` 让路径层等它出现）。

## hide_mounts：哪些挂载算"我们的"

上游 builtin SUSFS 识别自己的挂载靠的是 **KSU 范围内的 mnt_id**（`mnt_id >= 2000000000`）：KernelSU 在创建挂载时就分配了这种 id，所以 builtin 只要比一个数就能认出来。LKM 加载时这些挂载早就存在了，于是我们**在加载时扫描命名空间、给匹配的挂载补分配这种 id**（`ida_alloc_min(&mnt_id_ida, ...)`，与内核 `mnt_free_id()` 配对，不是自己编一个数字）。

"匹配"的判据是一份**前缀列表**，默认只有一个：`/data/adb/`（KernelSU 的模块镜像就在那里）。运行期可改，这正是为了容器：

```sh
# 容器（proot/chroot）在 /data/local/tmp/ubuntu2/ 下挂了 tmpfs/proc/sysfs/devpts
echo 'add /data/local/tmp/'  > /proc/susfs_hide_mounts
echo 'set /data/adb/ /data/local/tmp/' > /proc/susfs_hide_mounts   # 或整表替换
echo 'del /data/local/tmp/'  > /proc/susfs_hide_mounts
echo reset                   > /proc/susfs_hide_mounts             # 回到默认 /data/adb/
# insmod 时也可以：susfs_guard_lkm.ko hide_mounts=/data/adb/,/data/local/tmp/
```

改动列表会**立即重扫当前命名空间**（`mount prefixes: 2/8, rescans=1`），已经在挂的路径不用重新启用；此后新建的挂载由 `attach_recursive_mnt` 的 kretprobe 现挂现记。前缀是**锚定比较**（`strncmp`），不是子串搜索——`/mnt/media_rw/x/data/adb/y` 这种源串不算我们的（实测过，按子串匹配会误伤无关挂载）。

隐藏本身仍按上游的开关，默认**关**：

```sh
ksu_susfs hide_sus_mnts_for_non_su_procs 1
```

实测（OnePlus SM8550，prefix 加上 `/data/local/tmp/` 后启用，读者＝真实 adb shell，uid 2000、`u:r:shell:s0`）：

| 文件 | 启用前 | 启用后 |
|---|---|---|
| `/proc/self/mountinfo` 里 `ubuntu2` 的行数 | 4 | **0** |
| `/proc/mounts` | 4 | **0** |
| `/proc/self/mountstats` | 4 | **0** |
| su 侧（对照，只对非 su 隐藏） | 4 | 4 |

`mount_stat` 里能读到这件事的状态：

```
idmap=15/15  ident=5/5  hide=1 su_domain=1
show_probes=3/3 (show_vfsstat/show_mountinfo/show_vfsmnt)
```

三条 `show_*` 探针各管一个文件（`show_vfsstat`→mountstats、`show_mountinfo`→mountinfo、`show_vfsmnt`→/proc/mounts），现在**各自独立注册**：某一条挂不上不会带走另外两条，log 里会点名是哪一条、`show_probes` 会显示实际挂上了几条（`3/3` 才是一切正常）。只有三条全挂不上才算启用失败并回 `-EINVAL`。

## 使用前必读：隐藏 ≠ 访问控制


`sus_path` 隐藏一个路径时，会**把这个 inode 的权限位放宽到 0777**。这不是疏忽，是必须的：

`inode_permission()` 先做 DAC 再进 LSM 链，所以一个 0600 的目标在 DAC 层就被回 `EACCES`——"这文件存在，只是你没权限"——LSM 层根本没有机会把它变成 `ENOENT`。实测过：`ls -l` 得到 `No such file or directory`（`inode_getattr` 生效），而 `cat` 得到 `Permission denied`，且 perm 计数保持 0。所以只能让 DAC 放行，把唯一的判断留给 LSM 层。

由此带来几个**必须知道**的后果：

- **"隐藏"＝ 路径名不可见 + LSM 拦截，不是权限控制。** 不经过路径名的通道都不受影响：已经打开的 fd（`/proc/<pid>/fd/N`）、注册规则**之前**已经持有的引用、注册前的硬链接/bind mount、以及按 `(dev, ino)` 而不是按路径工作的接口（本项目里 `/proc/<pid>/map_files`、`maps`/`smaps` 的 inode 面就是这类）。**不要用它保护真正敏感的数据。**
- 权限改写**只发生在内存里的 inode 上**，磁盘上的 mode 从未被改动；`rmmod`、以及规则被 `del`/`clear` 删除时会恢复。但**崩溃或强杀不会**执行恢复——那种情况下重启即可（重启后是磁盘上的原值）。
- 门控是 `uid >= 10000 且不是文件属主`（上游 `TIF_PROC_UMOUNTED` 的近似）。也就是说 **root、system(1000)、shell(2000) 本来就能看到全部隐藏路径**——以这些身份运行的检查器不受影响。这是移植取舍，不是漏洞，但也意味着"只有 app 被隐藏"。
- 规则此前只能加不能删（一条误加的 `add_sus_path` 会让该路径整机不可见，直到卸载模块）。现在可以撤销，删掉的同时会把放宽的权限恢复回去：

  ```sh
  echo "del /data/adb/xxx" > /sys/module/susfs_guard_lkm/parameters/hide_list   # 单条
  echo clear              > /sys/module/susfs_guard_lkm/parameters/hide_list   # 全部
  ```

  `hide_list` 是 0600（只读时是隐藏路径清单，不能让 app 读到），列表超过一页会截断并标注 `(truncated)`。

## 另一个需要知道的取舍：被隐藏的路径"更快"

我们的拒绝发生在 DAC/SELinux **之前**，所以隐藏路径的耗时接近"路径存在"那一类。实测（配对采样，`tools/susfs_bench.c -p`，一批 200 次调用、120 个样本）：

| 对比 | 结果 |
|---|---|
| 被隐藏 vs 真正不存在（都返回 ENOENT） | 阈值判 0 的分类正确率 95–99%，差值 0.3–1.4 µs |
| **模块完全没加载时**：存在 vs 不存在 | 97–100%，差值 0.25–1.35 µs |

也就是说这个信号**几乎全是内核固有的**（正 dentry 比负 dentry 贵），本模块只把差值改了 ±0.2 µs，`openat`/`statx` 甚至更快。它只给出 1 bit："这个我猜得到名字的路径存在、只是被拒了"，拿不到内容、也不能用来扫描。想关掉这个面，只能让查找阶段本身就失败（需要重做一层入口拦截）或把 dentry 摘出缓存——两者代价都更大，属设计取舍。

## 接口文档

全部 `/proc` 控制节点（读回格式、写命令、错误契约、以及它们共同遵守的三条规则：0777 让 DAC 让路、open/write 都查 uid、由 sus_path 自隐藏给出 ENOENT）与相关 sysfs 参数，见 **[PROC_INTERFACES.md](PROC_INTERFACES.md)**。

## 移植参考

- [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu) — SUSFS 功能逻辑与 hook 点（GPL-3.0）
- [SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra) — `patch_memory` / `lsm_hook` / `symbol_resolver`（GPL-3.0）

## License

GPL-3.0，见 [LICENSE](LICENSE)。

## 免责声明

仅用于技术研究与学习。在自担风险的前提下使用。
