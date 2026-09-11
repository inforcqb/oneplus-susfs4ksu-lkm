#!/system/bin/sh
# sus_mount, end to end:
#   - marking comes from the real ida (verified separately)
#   - the hide actually happens once the supercall enables it
#   - the su domain keeps seeing the mounts, everyone else does not
#
# Every process we can spawn here lives in the KernelSU domain (u:r:ksu:s0), so
# the "su domain" side is tested by pointing su_ctx at a domain nobody is in -
# that makes our own shell the non-su case - and the other side by leaving the
# default.  Same rules, opposite verdicts.
K=/data/local/tmp/susfs.ko
SC=/data/local/tmp/susfs_sc
M=/data/adb/modules/zz_susfs_test
OR=/proc/susfs_open_redirect

rmmod susfs_guard_lkm 2>/dev/null
umount $M 2>/dev/null
rm -rf $M
dmesg -c >/dev/null 2>&1

echo "domains: root=$(cat /proc/self/attr/current) app=$(su 10123 -c 'cat /proc/self/attr/current')"
mkdir -p $M
mount -t tmpfs none $M
echo "test mount created: $(grep zz_susfs_test /proc/self/mountinfo | cut -c1-40)"
echo "data_adb rows before: $(grep -c '/data/adb' /proc/mounts)"

echo
echo "############ CASE 1: su_ctx points at a domain nobody is in ############"
ksud insmod $K su_ctx=u:r:shell:s0
echo "insmod rc=$?"
$SC 0x55561 0100000000000000 >/dev/null 2>&1
echo "enabled. $(dmesg | grep -c 'sus_mount: hide (supercall)') hide call(s)"
dmesg | grep -E 'scan stats|marked mnt_id' | tail -4
echo "root data_adb rows: $(grep -c '/data/adb' /proc/mounts)   (expect 0 - we are not in the configured su domain)"
echo "app  data_adb rows: $(su 10123 -c 'cat /proc/mounts' | grep -c '/data/adb')   (expect 0)"
echo "u1000 data_adb rows: $(su 1000 -c 'grep -c /data/adb /proc/mounts')   (expect 0)"
echo "root total rows   : $(grep -c '' /proc/mounts)"
echo "app  total rows   : $(su 10123 -c 'cat /proc/mounts' | grep -c '')"
echo "mountinfo root    : $(grep -c '/data/adb' /proc/self/mountinfo)"
rmmod susfs_guard_lkm

echo
echo "############ CASE 2: default su_ctx (u:r:ksu:s0) = our own domain ############"
ksud insmod $K
echo "insmod rc=$?"
$SC 0x55561 0100000000000000 >/dev/null 2>&1
dmesg | grep -E 'su ctx|scan stats' | tail -3
echo "root data_adb rows: $(grep -c '/data/adb' /proc/mounts)   (expect 2 - su domain is exempt)"
echo "app  data_adb rows: $(su 10123 -c 'cat /proc/mounts' | grep -c '/data/adb')   (expect 2 - same domain)"
echo "root total rows   : $(grep -c '' /proc/mounts)"

echo
echo "== cleanup =="
$SC 0x55561 0000000000000000 >/dev/null 2>&1
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
umount $M
echo "umount rc=$?"
sleep 1
rmdir $M 2>/dev/null
echo "--- WARN check after unmounting the marked mount ---"
dmesg | grep -iE 'ida_free|WARNING|Call trace' | tail -5
echo "--- (end) ---"
echo "data_adb rows now: $(grep -c '/data/adb' /proc/mounts)"
echo "### done"
