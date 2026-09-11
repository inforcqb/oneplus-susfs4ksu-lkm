#!/system/bin/sh
# sus_mount: marking + domain gate + the unmount WARN regression.
#
# The mount we test on is a tmpfs we create under /data/adb ourselves, so it is
# disposable and reversible - the alternative (unmounting meta-overlayfs' real
# loop mount) would disturb KernelSU.
K=/data/local/tmp/susfs.ko
SC=/data/local/tmp/susfs_sc
M=/data/adb/testmnt

rmmod susfs_guard_lkm 2>/dev/null
umount $M 2>/dev/null
rm -rf $M
dmesg -c >/dev/null 2>&1

echo "== create a disposable mount under /data/adb =="
mkdir -p $M
mount -t tmpfs none $M
echo "mount rc=$?"
grep -c '/data/adb' /proc/mounts
echo "before marking: $(grep '/data/adb/testmnt' /proc/self/mountinfo | cut -c1-40)"

echo
echo "== insmod + enable hide_sus_mnts_for_non_su_procs =="
ksud insmod $K
echo "insmod rc=$?"
dmesg | grep -E 'sus_mount' | tail -4
$SC 0x55561 0100000000000000
echo "supercall rc=$?"
dmesg | grep -E 'sus_mount' | tail -8

echo
echo "== after marking: is the id from the real ida? =="
grep '/data/adb/testmnt' /proc/self/mountinfo | cut -c1-40

echo
echo "== visibility =="
echo "root rows (data_adb): $(grep -c '/data/adb' /proc/mounts)"
echo "root rows (mounts)   : $(grep -c '' /proc/mounts)"
echo "app  rows (data_adb) : $(su 10123 -c 'cat /proc/mounts' | grep -c '/data/adb')"
echo "app  domain          : $(su 10123 -c 'cat /proc/self/attr/current' 2>/dev/null)"
echo "root domain          : $(cat /proc/self/attr/current 2>/dev/null)"
echo "u1000 rows           : $(su 1000 -c 'grep -c /data/adb /proc/mounts')"
echo "mountinfo app        : $(su 10123 -c 'grep -c /data/adb /proc/self/mountinfo')"

echo
echo "== THE REGRESSION: unmount a marked mount =="
umount $M
echo "umount rc=$?"
sleep 1
echo "--- any ida_free / WARN? (must be empty) ---"
dmesg | grep -iE 'ida_free|WARNING|BUG|Call trace' | tail -6
echo "--- (end) ---"
rmdir $M 2>/dev/null

echo
echo "== the mount is gone, and the module is still healthy =="
echo "uptime: $(cat /proc/uptime | cut -d' ' -f1)  cpus: $(grep -c processor /proc/cpuinfo)"
echo "root rows now: $(grep -c '' /proc/mounts)"

echo
echo "== disable + rmmod =="
$SC 0x55561 0000000000000000 >/dev/null 2>&1
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
dmesg | grep -iE 'BUG:|WARNING:|Call trace|CFI failure' | tail -4
echo "### done"
