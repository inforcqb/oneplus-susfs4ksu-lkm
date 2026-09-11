#!/system/bin/sh
# Baseline for sus_mount: does the supercall client work, and does the module
# currently hide anything?  (Expected before the fix: nothing is hidden, because
# the mnt_id threshold can never match on this kernel.)
K=/data/local/tmp/susfs.ko
SC=/data/local/tmp/susfs_sc

rmmod susfs_guard_lkm 2>/dev/null
dmesg -c >/dev/null 2>&1
ksud insmod $K
echo "insmod rc=$?"
dmesg | tail -3

echo
echo "== baseline /proc/mounts =="
echo "root lines   : $(wc -l < /proc/mounts)"
echo "app  lines   : $(su 10123 -c 'cat /proc/mounts' | wc -l)"
echo "root data_adb: $(grep -c '/data/adb' /proc/mounts)"
echo "app  data_adb: $(su 10123 -c 'cat /proc/mounts' | grep -c '/data/adb')"

echo
echo "== send CMD_SUSFS_HIDE_SUS_MNTS_FOR_NON_SU_PROCS (0x55561) enabled=1 =="
$SC 0x55561 0100000000000000
echo "client rc=$?"
echo "--- dmesg ---"
dmesg | grep -E 'sus_mount|supercall|unsupported' | tail -6

echo
echo "== after enabling =="
echo "root lines   : $(wc -l < /proc/mounts)"
echo "app  lines   : $(su 10123 -c 'cat /proc/mounts' | wc -l)"
echo "root data_adb: $(grep -c '/data/adb' /proc/mounts)"
echo "app  data_adb: $(su 10123 -c 'cat /proc/mounts' | grep -c '/data/adb')"
echo "mountinfo root: $(grep -c '/data/adb' /proc/self/mountinfo)"
echo "mountinfo app : $(su 10123 -c 'cat /proc/self/mountinfo' | grep -c '/data/adb')"

echo
echo "== disable again =="
$SC 0x55561 0000000000000000
dmesg | grep sus_mount | tail -3

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "### done"
