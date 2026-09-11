#!/system/bin/sh
# Supercall semantics after the unknown-command fix:
#   - a command the module handles still short-circuits reboot(2) to 0
#   - a command it does NOT handle must fall through, so reboot(2) reports the
#     kernel's own -EINVAL and payload.err keeps the caller's sentinel (126) --
#     that sentinel is how the C tool detects "not supported".
K=/data/local/tmp/susfs.ko
SC=/data/local/tmp/susfs_sc

rmmod susfs_guard_lkm 2>/dev/null
dmesg -c >/dev/null 2>&1
ksud insmod $K
echo "insmod rc=$?"

echo
echo "== handled command: show_version (0x555e1), payload 16B version + 4B err =="
# 20 bytes of zeroes: the kernel fills version and writes err=0
$SC 0x555e1 0000000000000000000000000000000000000000
echo "client rc=$?  (0 = syscall returned 0)"

echo
echo "== unhandled command: 0x99999, err pre-seeded with 126 =="
$SC 0x99999 7e00000000000000
echo "client rc=$?  (1 = syscall returned non-zero, i.e. -EINVAL as upstream)"
echo "payload tail should still read 0x7e (126):"
dmesg | grep -E 'unsupported cmd' | tail -3

echo
echo "== handled command again, to be sure nothing got poisoned =="
echo "features: $(ksud susfs features 2>&1 | head -3)"
echo "version : $(/data/adb/ksu/bin/ksu_susfs show version 2>&1 | tail -2)"

echo
echo "== hide_sus_mnts still works (0x55561) =="
$SC 0x55561 0100000000000000 >/dev/null 2>&1
dmesg | grep sus_mount | tail -2
$SC 0x55561 0000000000000000 >/dev/null 2>&1
dmesg | grep sus_mount | tail -1

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
dmesg | grep -iE 'BUG:|WARNING:|Call trace' | tail -3
echo "### done"
