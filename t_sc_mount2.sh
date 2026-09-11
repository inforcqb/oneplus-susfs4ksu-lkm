#!/system/bin/sh
# sus_mount: the threshold fix should actually hide the KSU mount, and the domain
# gate should keep it visible to the su domain (upstream hides only from
# non-su processes).
#
# The interesting rows are the ones carrying /data/adb (on this device one:
# /dev/block/loop48 -> /data/adb/modules/meta-overlayfs/mnt).
K=/data/local/tmp/susfs.ko
SC=/data/local/tmp/susfs_sc

rmmod susfs_guard_lkm 2>/dev/null
dmesg -c >/dev/null 2>&1

echo "== domains before =="
echo "root shell domain : $(cat /proc/self/attr/current 2>/dev/null)"
echo "su -c domain      : $(su -c 'cat /proc/self/attr/current' 2>/dev/null)"
echo "app10123 domain   : $(su 10123 -c 'cat /proc/self/attr/current' 2>/dev/null)"

echo
echo "== insmod + enable hide_sus_mnts_for_non_su_procs =="
ksud insmod $K
echo "insmod rc=$?"
dmesg | grep -E 'sus_mount' | tail -4
$SC 0x55561 0100000000000000
echo "supercall client rc=$?"
echo "--- what got marked ---"
dmesg | grep -E 'sus_mount|marked' | tail -10

echo
echo "== /proc/mounts: the /data/adb rows =="
echo "root total        : $(grep -c '' /proc/mounts)"
echo "root data_adb rows: $(grep -c '/data/adb' /proc/mounts)"
echo "su -c data_adb    : $(su -c 'cat /proc/mounts' | grep -c '/data/adb')"
echo "app  data_adb     : $(su 10123 -c 'cat /proc/mounts' | grep -c '/data/adb')"
echo "app  total        : $(su 10123 -c 'cat /proc/mounts' | grep -c '')"

echo
echo "== /proc/self/mountinfo (same rows, other writer) =="
echo "root data_adb     : $(grep -c '/data/adb' /proc/self/mountinfo)"
echo "app  data_adb     : $(su 10123 -c 'cat /proc/self/mountinfo' | grep -c '/data/adb')"

echo
echo "== the loop device still works for everyone =="
echo "root ls  : $(ls -d /data/adb/modules 2>&1)"
echo "app  ls  : $(su 10123 -c 'ls -d /data/adb/modules' 2>&1)"
echo "app cat /proc/mounts works: $(su 10123 -c 'head -1 /proc/mounts' | wc -c) bytes"

echo
echo "== disable + rmmod =="
$SC 0x55561 0000000000000000 >/dev/null 2>&1
dmesg | grep sus_mount | tail -2
rmmod susfs_guard_lkm
echo "rmmod rc=$?  app data_adb: $(su 10123 -c 'cat /proc/mounts' | grep -c '/data/adb')"
dmesg | grep -iE 'BUG:|WARNING:|Call trace|CFI failure' | tail -4
echo "### done"
