#!/system/bin/sh
K=/data/local/tmp/susfs.ko
M=/data/adb/modules/zz_susfs_test

rmmod susfs_guard_lkm 2>/dev/null
umount $M 2>/dev/null
rm -rf $M
dmesg -c >/dev/null 2>&1

echo "== mount ids for the /data/adb rows right now =="
grep '/data/adb' /proc/self/mountinfo | cut -c1-60

echo
echo "== create a fresh disposable mount whose mountpoint matches =="
mkdir -p $M
mount -t tmpfs none $M
echo "mount rc=$?"
grep 'zz_susfs_test' /proc/self/mountinfo | cut -c1-60

echo
echo "== insmod: the scan should mark the fresh one =="
ksud insmod $K
echo "insmod rc=$?"
sleep 1
dmesg | grep -E 'scan stats|marked mnt_id|KSU mount\(s\) marked|0 KSU' | tail -6
echo "--- ids after ---"
grep -E 'zz_susfs_test|meta-overlayfs' /proc/self/mountinfo | cut -c1-60

echo
echo "== visibility of the freshly marked mount =="
echo "root data_adb rows: $(grep -c '/data/adb' /proc/mounts)"
echo "app  data_adb rows: $(su 10123 -c 'cat /proc/mounts' | grep -c '/data/adb')"
echo "u1000 data_adb rows: $(su 1000 -c 'grep -c /data/adb /proc/mounts')"

echo
echo "== umount a mount that WAS marked from the real ida =="
umount $M
echo "umount rc=$?"
sleep 1
echo "--- ida_free / WARN (must be empty) ---"
dmesg | grep -iE 'ida_free|WARNING|Call trace|BUG' | tail -6
echo "--- (end) ---"
rmdir $M 2>/dev/null

echo
echo "== module still healthy =="
echo "uptime: $(cat /proc/uptime | cut -d' ' -f1)  cpus: $(grep -c processor /proc/cpuinfo)"
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "### done"
