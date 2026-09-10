#!/system/bin/sh
exec > /data/local/tmp/diag_or.txt 2>&1

echo "=== is the vfs_open kprobe registered? ==="
if [ -r /sys/kernel/debug/kprobes/list ]; then
  grep -E "vfs_open|show_vfsmnt|show_mountinfo|show_vfsstat|s_show" /sys/kernel/debug/kprobes/list
else
  echo "no readable kprobes list"
fi
echo
echo "=== does vfs_open exist in kallsyms? ==="
grep -w vfs_open /proc/kallsyms
echo
echo "=== reload and test redirect, watching dmesg ==="
rmmod susfs_guard_lkm 2>/dev/null
ksud insmod /data/local/tmp/susfs_guard_lkm.ko expose_proc=1
sleep 1
echo SRC-CONTENT > /data/local/tmp/or_src
echo DST-CONTENT > /data/local/tmp/or_dst
printf 'add_open_redirect /data/local/tmp/or_src /data/local/tmp/or_dst 0' > /proc/susfs_open_redirect
echo "-- rule --"
cat /proc/susfs_open_redirect
echo "-- dmesg after add --"
dmesg | grep -i open_redirect | tail -5
echo "-- read src --"
cat /data/local/tmp/or_src
echo "-- dmesg after read --"
dmesg | grep -i open_redirect | tail -5
echo
echo "=== try running as uid 10378 (scheme 0 means non-app, so root should match) ==="
id -u
echo
echo "=== compare: does the file open via the cached path at all? ==="
ls -l /data/local/tmp/or_dst
echo DONE
