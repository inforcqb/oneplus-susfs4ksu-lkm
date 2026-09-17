# /proc 控制接口

本模块（`susfs_guard_lkm`）的全部 `/proc` 节点。它们是**手工/脚本接口**；KernelSU 的 `ksu_susfs` 走的是另一条通道（`reboot(2)` 超调用），两者操作的是同一批内部状态。

所有节点都遵守同一套约定，这些约定是刻意的、不是随手写的：

| 约定 | 原因 |
|---|---|
| 节点属性是 **0777** | `inode_permission()` 先做 DAC 再进 LSM 链。若设成 0600，非 root 调用者会在 DAC 层拿到 `EACCES`＝"这文件存在，只是你没权限"，而 sus_path 根本没有机会把它变成 `ENOENT`。**实测过**：`ls -l /proc/susfs_kstat` 得到 `No such file or directory`（getattr 生效）而 `cat` 得到 `Permission denied`。 |
| `open()` **和** `write()` 都查 `current_uid() != 0 → -ENOENT` | 0777 让 DAC 不设防，所以 handler 必须自己拦；只在 `open()` 查不够 —— root 打开后把 fd 传出去就绕过了，这正是 /proc 控制面最常见的失守方式（审计报告 F-3）。Answer 用 `ENOENT` 是为了与隐藏集合给出的答案一致。 |
| 每个节点都登记在 sus_path 的自隐藏集合里 | 非 root 调用者（含 system/shell，不只是 app）看到的是 `No such file or directory`，拿不到节点名这条线索。root 仍可管理。 |
| 写命令**成功返回 `len`，失败返回负 errno** | 命令没生效却回 `len`，脚本无法区分"成功"与"半成功"——这正是本项目反复踩过的"静默失败"类问题。 |

**一句自查**：节点属从非 root shell 读它就是 `No such file or directory`；如果读到内容或 `Permission denied`，说明保护没生效。

```sh
# root：读状态
cat /proc/susfs_hide_modules
# 非 root（例如 adb shell，uid 2000）：必须得到 ENOENT
cat /proc/susfs_hide_modules            # -> No such file or directory
```

## 节点一览

| 节点 | 作用 | 写命令 |
|---|---|---|
| [`/proc/susfs_kstat`](#procsusfs_kstat) | `stat()`/`maps` 结果伪装 | `add_sus_kstat` / `add_sus_kstat_statically` / `update_sus_kstat` / `update_sus_kstat_full_clone` / `del` / `clear` |
| [`/proc/susfs_open_redirect`](#procsusfs_open_redirect) | `open()` 重定向（含反向面：`d_path`/`statfs`/`maps`/`fdinfo`） | `add_open_redirect` / `del` / `clear` |
| [`/proc/susfs_enable_log`](#procsusfs_enable_log) | 运行期日志开关 | `0` / `1` |
| [`/proc/susfs_avc_spoof`](#procsusfs_avc_spoof) | 隐藏 SELinux AVC 审计日志 | `0` / `1` |
| [`/proc/susfs_hide_modules`](#procsusfs_hide_modules) | 按名字把**其它内核模块**从 `/proc/modules` 去掉 | `add <名字>` / `del <名字>` / `set <名字>…` / `clear` |
| [`/proc/susfs_hide_mounts`](#procsusfs_hide_mounts) | 哪些挂载算"我们的"（决定隐藏的挂载集合） | `add <前缀>` / `del <前缀>` / `set <前缀>…` / `reset` / `clear` |

节点只在 sus_path 的 LSM 层装上时才创建（`expose_proc=1` 且 LSM 生效），所以"0777 的世界可写节点 + 没有保护"这个组合不可能出现；`expose_proc=0` 则完全不创建。

---

## /proc/susfs_kstat

登记一个路径，让 app 看到的 `stat()`/`statx()`/`maps` 里的 inode 与时间戳变成登记时的值（`add_sus_kstat` 用"登记那一刻的真实值"作为伪装值）。

**读**：每条规则一行，外加两组计数器。

```
/data/local/tmp/procdoc/target ino=981881 dev=65099 flags=0xff3 [ino=981881 dev=65099 nlink=1 size=2 atime=1789400211.918607439 mtime=1789400211.930607439 ctime=1789400211.946607439 blocks=8 blksize=4096]
maps: armed=1 hits=0 rewrites=0
vfs_getattr fallback: gattr_hits=6 gattr_spoofs=0
```

外层是登记目标，方括号里是伪装值。`maps:` 是 `maps` 行改写探针（`armed` 装上了没、`hits/rewrites` 真的命中/改写了没）；`vfs_getattr fallback:` 是"内核内部调用者"那条回退路径的命中数。

**写**（`ksu_susfs` 走超调用，这里是手工形式）：

```sh
echo "add_sus_kstat /data/local/tmp/x"                       > /proc/susfs_kstat
echo "add_sus_kstat_statically /data/local/tmp/x 1 2 3 4 5 6 7 8 9 10 11 12" > /proc/susfs_kstat
echo "update_sus_kstat /data/local/tmp/x"                    > /proc/susfs_kstat
echo "update_sus_kstat_full_clone /data/local/tmp/x"         > /proc/susfs_kstat
echo "del /data/local/tmp/x"                                 > /proc/susfs_kstat
echo clear                                                   > /proc/susfs_kstat
```

`add_sus_kstat_statically` 后面跟 12 个十进制数：`ino dev nlink size atime_sec atime_nsec mtime_sec mtime_nsec ctime_sec ctime_nsec blocks blksize`。参数个数不对或路径解析失败 → 返回负 errno，不再假装成功。

---

## /proc/susfs_open_redirect

把一次 `open()` 重定向到另一个文件，并且把**能反查出真实路径的那些面**（`readlink`（`d_path`）、`statfs`、`maps`、`fdinfo`）一并伪装，使被重定向的调用者看到的是它打开的那个文件。

**读**：每条规则一行，空表时 `(empty)`；随后是各探针的命中计数（用来判断"注册成功"不等于"真的生效"）。

```
(empty)
hooks: open=0 dpath=0 statfs=0 maps=0 fdinfo=0 | rev hits: dpath=0 statfs=0 maps=0/0/0 fdinfo=0/0 | su_sid=2907
```

**写**：

```sh
echo "add_open_redirect <目标> <被重定向到的文件> <uid_scheme>" > /proc/susfs_open_redirect
echo "del <目标>"                                               > /proc/susfs_open_redirect
echo clear                                                      > /proc/susfs_open_redirect
```

`uid_scheme` 取值 `0..4`（决定哪些调用者的 `open` 被重定向）。注意 `ksu_susfs add_open_redirect` 的 usage 少印了第三个参数，三个都要给。

---

## /proc/susfs_enable_log

运行期日志开关（默认开）。只接受 1 个字节：`0` 或 `1`，其它字节返回 `-EINVAL`（旧版本接受任意字节并照样回 `len`，一个笔误与成功无法区分）。

```
1
```

无论开关如何，加载成功那一行 `susfs_guard_lkm: loaded.` 始终会打印——它是"模块起来了"的唯一证据。

---

## /proc/susfs_avc_spoof

隐藏 `avc: denied` 审计日志里的 KernelSU 痕迹（改写记录里的 `tsid`）。打开时会解析 su 与 priv_app 的 sid。

```
0 (su_sid=2907 priv_app_sid=2504 enter=0 hits=0)
```

前面的 `0/1` 是开关状态，括号里是解析到的 sid 与探针计数（`enter`/`hits` 都动说明真的在改写）。写 `1` 装上探针、写 `0` 卸掉；`su_sid == 0`（解析失败）时不会匹配任何记录。

---

## /proc/susfs_hide_modules

维护一份**模块名列表**，把列表里的名字从 `/proc/modules` 的那一行去掉（对所有读者生效，root 也不例外）、把 `/sys/module/<名字>` 从非 root 调用者眼前隐掉、并过滤 `/proc/kallsyms` 里 `module_name` 匹配的行。默认列表只有 `susfs_guard_lkm` 自己（builtin 版 SUSFS 没有模块条目，留下它就是上游没有的痕迹）。

**读**：

```
hide_modules: 1/16 name(s), /sys/module rules=1 (failed=0), /proc/modules lines removed=0, kallsyms lines removed=0
names: susfs_guard_lkm
```

计数分别是：`/sys/module/<名字>` 规则装了 `rules` 条、失败 `failed` 次（模块未加载时该目录不存在，属正常）；`/proc/modules` 被跳过的行数、被跳过的 kallsyms 行数——两者会动才说明过滤真的在跑。

**写**：

```sh
echo "add kernelsu"            > /proc/susfs_hide_modules   # 加一个名字
echo "del kernelsu"            > /proc/susfs_hide_modules   # 去掉一个（未列出 -> -ENOENT）
echo "set kernelsu frida"      > /proc/susfs_hide_modules   # 整份替换
echo clear                     > /proc/susfs_hide_modules   # 一个都不隐藏（调试模式，lsmod 会重新列出本模块）
```

节点**只接受命令**：`set` 才是替换列表的形式，别的字串返回 `-EINVAL`（早先的版本把不认识的整串当新列表，一个笔误就静默替换掉列表）。同名模块参数 `hide_modules` 用同一份实现，另外**接受裸列表**，因为它要支持 `insmod` 的传值方式：

```sh
ksud insmod susfs_guard_lkm.ko hide_modules=kernelsu,frida
echo "add frida" > /sys/module/susfs_guard_lkm/parameters/hide_modules
```

已知边界：只过滤"模块自己那一行"。别的模块若**依赖**它，`/proc/modules` 的 used-by 列里仍会出现该名字（实测隐藏 `explorer` 后仍有 `camera 10440704 35 explorer, Live …`）。

---

## /proc/susfs_hide_mounts

决定**哪些挂载算"我们的"**，也就是挂载隐藏（`ksu_susfs hide_sus_mnts_for_non_su_procs 1`）实际会隐藏哪些行。默认前缀只有一个 `/data/adb/`（KernelSU 的模块镜像位置）；容器这类场景要自己加：

```sh
# root：读回
cat /proc/susfs_hide_mounts
# mount prefixes: 2/8, rescans=1, recorded=0, hidden_by_identity=0, learned_ids=0
# prefixes: /data/adb/ /data/local/tmp/

# 写命令
echo 'add /data/local/tmp/'                 > /proc/susfs_hide_mounts
echo 'del /data/local/tmp/'                 > /proc/susfs_hide_mounts
echo 'set /data/adb/ /data/local/tmp/'      > /proc/susfs_hide_mounts
echo 'reset'                                > /proc/susfs_hide_mounts   # 回到默认
echo 'clear'                                > /proc/susfs_hide_mounts   # 空前缀表
```

| 行为 | 说明 |
|---|---|
| 非 root 读到什么 | `No such file or directory`——它和别的 `/proc` 控制节点一样登记在自隐藏集合里，且属 `self_protect`（对**所有**非 root 调用者隐藏，不只是 app） |
| 前缀怎么比 | **锚定** `strncmp`，不是子串搜索。`/mnt/media_rw/x/data/adb/y` 不算我们的 |
| 改列表之后 | 立刻重扫当前命名空间（`rescans` +1），已经在挂的路径不用重新启用；之后新建的挂载由 `attach_recursive_mnt` 的 kretprobe 现挂现记 |
| 上限 | 8 条前缀，每条 128 字节；`add` 重复项返回 0（幂等），`del` 不存在的项返回 `-ENOENT`，表满返回 `-ENOSPC` |
| 同名 sysfs 参数 | `hide_mounts`（0600），同样命令，另外接受裸列表用于 `insmod ... hide_mounts=/a/,/b/` |

实测（OnePlus SM8550；prefix 加上 `/data/local/tmp/` 后启用；读者＝真实 adb shell，uid 2000、`u:r:shell:s0`）：`/proc/self/mountinfo`、`/proc/mounts`、`/proc/self/mountstats` 里 `ubuntu2` 的行数**各从 4 变 0**，su 侧仍是 4（只对非 su 隐藏）。

挂载层挂了三 kprobe（`show_vfsstat` / `show_mountinfo` / `show_vfsmnt`），各自独立注册，`mount_stat` 的 `show_probes=<n>/3` 显示实际挂上了几条——`3/3` 才是一切正常；只有三条全挂不上才算启用失败。

---

## 相关：sysfs 参数（同一类接口）

`/sys/module/susfs_guard_lkm/parameters/` 下的参数也是控制面，而且整个目录被 sus_path 自隐藏覆盖（非 root 看不到）。常用的几个：

| 参数 | 权限 | 作用 |
|---|---|---|
| `hide_list` | 0600 | sus_path 的规则视图与**撤销**入口：读=规则+计数（超过一页会截断并标注），写 `clear` 或 `del <路径>`，删除时会把被放宽的权限恢复回去 |
| `hide_modules` | 0600 | 同 `/proc/susfs_hide_modules`，另接受裸列表 |
| `expose_proc` | 0600 | 是否创建 `/proc` 节点（默认 1）；`0` 时节点根本不存在 |
| `enable_log` | 0444（只读视图） | 日志开关的状态；用 `/proc/susfs_enable_log` 或超调用改 |
| `mount_stat` / `map_stat` | 0400 | `/proc/modules` 之外的诊断：挂载层的身份表/编号表/失效计数、映射层的探针计数 |
| `su_ctx` / `min_mnt_id` / `map_ino` | 0644 | 加载期参数（su 的 SELinux 上下文、KSU 编号段下限、初始映射规则） |
| `walk_dbg` / `mount_dbg` / `hide_name` / `hide_from_apps` / `no_extra` | 0644 | 诊断与隔离开关 |
| `fail_layer` | 0644 | 诊断：强制指定层初始化失败，用来验证"加载失败不留残留"的回滚路径 |
| `sus_path_probe` | 0600 | 诊断：`echo <路径> > sus_path_probe` 解析该路径，读回它看到的 inode 指针/`(dev,ino)`/是否在隐藏集合内，以及**每条同 (dev,ino) 规则**自己的 inode 指针、`ptr_equal`、两个 gate 的答案。用于回答"规则登记了、别的规则钩子也在工作、但这个路径仍然可见"——否则只能上内核调试器 |

**匹配键是身份，不是对象**（`sus_path_inode_hidden()`）：inode 指针只是缓存，权威判定是 `(dev, i_ino)`，与挂载层身份表同一套键（`s_dev` + 根 inode 号）。三级：

| 级 | 条件 | 说明 |
|---|---|---|
| 快路径 | `e->inode == inode` | 命中的就是规则当初解析的那个对象，不可能错 |
| 身份（权威） | `e->dev == i_sb->s_dev && e->ino == inode->i_ino` | 指针落空时的判定；适用于所有规则 |
| 跨实例（仅 `self_protect`） | 同文件系统类型 + 同 `i_ino` | 同一文件系统的**另一份实例** inode 号相同、`s_dev` 不同（实测容器 `/proc`：同 `4026535268`，dev `1048754` vs 主 `/proc` 的 `20`）；procfs 的 inode 号来自全局分配器，所以这个组合在模块加载期间只可能是本模块的节点。普通规则不给这一级：同类型的两份挂载里同一个 inode 号确实可能代表两个不同文件 |

为什么指针不能单独作为键（两个实测场景）：

- 容器（proot/chroot）挂自己的 `/proc`：不按身份匹配时，节点在容器里 `stat`/`cat` 可见、而列表里名字已被过滤——"列表里没有却打得开"。实测修复后容器里 uid 2000 得到 ENOENT。
- **快速 `rmmod` + `insmod`**（`ihold()` 只保证 inode 不被释放，**不保证它还挂在 inode hash 上**）：规则可能持有一个读者再也见不到的对象，而同一 `(dev, ino)` 已由新对象承担。实测过一次：`sus_path_probe` 显示 `ptr_equal=0`、`hide_list` 的 `identity` 计数增加，此时节点对 uid 2000 重新可见（`ls -la /proc/susfs_hide_modules` 直接列出文件）。这是 `rmmod`/`insmod` 窗口里的竞态，不是每次都能复现（3 秒间隔或再重载一次即恢复正常）。

`hide_list` 里的 `identity: N hit(s)` 就是**指针未命中、由身份判定回答**的次数——它不是告警（身份是权威键），而是"规则持有的对象已不是读者拿到的那一个"的观测面；稳定增长才值得看。

## 另见

- 另一条通道（超调用，KernelSU 的 `ksu_susfs` 用它）见 [README](README.md) 的加载/判断小节。
- 被隐藏路径为什么会被放宽到 0777、以及"隐藏 ≠ 访问控制"的完整说明：见 [README](README.md) 的"使用前必读"。
