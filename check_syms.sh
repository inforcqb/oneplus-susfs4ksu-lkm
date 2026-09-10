#!/system/bin/sh
for s in __arm64_sys_newfstatat __arm64_sys_statx __arm64_sys_openat __arm64_sys_faccessat __arm64_sys_readlinkat __arm64_sys_execve __arm64_sys_openat2 close_fd ksys_close filp_close __close_fd vfs_statx do_filp_open vfs_open security_inode_permission inode_permission; do
  line=$(grep -w "$s" /proc/kallsyms 2>/dev/null | head -1)
  if [ -n "$line" ]; then echo "OK   $s"; else echo "MISS $s"; fi
done
echo
echo "=== kptr_restrict / kallsyms 可读性 ==="
cat /proc/sys/kernel/kptr_restrict 2>/dev/null
head -3 /proc/kallsyms
