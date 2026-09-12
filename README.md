# susfs4ksu-lkm

SUSFS 的**可加载内核模块（LKM）移植版**，目标是让锁定 bootloader、只能漏洞 root 的 GKI 设备（CFI + PAC + BTI + SCS 全开）也能用上 SUSFS 的 root 隐藏能力，而无需重编译内核或刷 boot 镜像。

## 背景

上游 [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu) 是 KernelSU 的内核补丁，v2.0 起采用**编译期内联**（直接 patch 内核源码树），要求能刷自定义内核。本仓库把它移植为独立 `.ko`：

- **构建**：用 Android DDK 预构建内核头（`ghcr.io/ylarod/ddk-min`），无需完整内核源码树。
- **符号解析**：模块直接 `extern` 引用未导出符号，由 `ksud insmod` 加载时通过 kallsyms 重定位。
- **hook 方式**：kprobe（入口/出口） + `patch_memory`（改只读内存/fixmap） + `lsm_hook`（改 SELinux 函数指针），在 CFI 下用 `__nocfi` replacement 穿透。

## 已验证的能力（在目标 GKI 设备上实测）

| 能力 | 结论 |
|---|---|
| kprobe/kretprobe hook 非导出符号 | ✅ |
| 读/写 SELinux 私有结构体（`selinux_state`） | ✅ 偏移精确匹配 |
| `ksud insmod` 重定位未导出符号 | ✅ |
| patch 只读内存 + 改 LSM 函数指针（CFI 穿透） | ✅ |

## 构建

```sh
# 在 GitHub Actions 里（推荐）
# .github/workflows/build-ddk.yml 使用 ddk-min 镜像

# 本地（需有 DDK 内核头目录 $KDIR）
make -C $KDIR M=$PWD/kernel ARCH=arm64 CC=clang LLVM=1 LLVM_IAS=1 modules
```

## 加载

```sh
ksud insmod /data/local/tmp/susfs_guard_lkm.ko
# 卸载
rmmod susfs_guard_lkm
```

### 怎么判断它是否已经加载（**不要用 `lsmod`**）

模块会把自己的那一行从 `/proc/modules` 里去掉，而且**对所有调用者都一样，root 也不例外**——上游 builtin 内根本没有"模块条目"这回事，只对非 root 隐藏的话，root 的 `lsmod` 仍会留下 builtin 不存在的痕迹。因此：

```sh
lsmod | grep susfs            # 永远是 0 行，不代表没加载
ls -d /sys/module/susfs_guard_lkm   # ← 这个才代表已加载（root 可见）
ls /sys/module/susfs_guard_lkm/parameters/   # 参数节点在，也说明已加载
```

重复 `insmod` 会因为模块已在内存里而失败（`init_module failed: File exists (os error 17)`，即 `-EEXIST`）；想重载就先 `rmmod susfs_guard_lkm`。

## 移植参考

- [susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu) — SUSFS 功能逻辑与 hook 点（GPL-3.0）
- [SukiSU-Ultra](https://github.com/SukiSU-Ultra/SukiSU-Ultra) — `patch_memory` / `lsm_hook` / `symbol_resolver`（GPL-3.0）

## License

GPL-3.0，见 [LICENSE](LICENSE)。

## 免责声明

仅用于技术研究与学习。在自担风险的前提下使用。
