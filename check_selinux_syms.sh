#!/system/bin/sh
for s in selinux_inode_getattr selinux_inode_permission selinux_file_permission selinux_inode_follow_link selinux_dentry_open avc_has_perm inode_doinit_with_dentry inode_permission vfs_getattr vfs_getattr_nosec security_inode_getattr getattr; do
  if grep -qw "$s" /proc/kallsyms; then
    echo "OK   $s   $(grep -w $s /proc/kallsyms | head -1)"
  else
    echo "MISS $s"
  fi
done
echo
echo "=== SELinux 状态 ==="
getenforce 2>/dev/null
cat /sys/fs/selinux/enforce 2>/dev/null
