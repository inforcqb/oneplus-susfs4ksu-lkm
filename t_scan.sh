#!/system/bin/sh
rmmod susfs_guard_lkm 2>/dev/null
dmesg -c >/dev/null 2>&1
ksud insmod /data/local/tmp/susfs.ko
sleep 1
echo "--- sus_mount lines ---"
dmesg | grep -E 'sus_mount' | tail -24
echo "--- mount order as the kernel sees it ---"
grep -n '/data/adb' /proc/mounts
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
