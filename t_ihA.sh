#!/system/bin/sh
# Non-interactive verification of the LR-restore fix on the allow path.
#
# The hooked entry is __arm64_sys_openat (entry #1), which is called on every
# process on the box many times a second, so if the allow path still corrupts
# anything the device goes down within milliseconds of the install - no special
# trigger needed.
#
# no_extra=1 keeps the LSM / DAC / tracepoint layers out of the picture, and the
# rule is added through the supercall (that is what arms the hooks).
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
D=/data/local/tmp/dac_probe
T=$D/f600

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 600 $T
dmesg -c >/dev/null 2>&1

echo "== insmod ih_only=1 ih_secs=20 no_extra=1 =="
ksud insmod $K ih_only=1 ih_secs=20 no_extra=1
echo "insmod rc=$?"
lsmod | grep susfs
dmesg | tail -8

echo
echo "== add_sus_path - the hook is installed here =="
$KT add_sus_path $T
echo "add rc=$?"
dmesg | tail -12
echo "uptime: $(cat /proc/uptime)"

echo
echo "== 3 s later, all CPUs still there? =="
sleep 3
echo "uptime: $(cat /proc/uptime)"
echo "cpus: $(grep -c processor /proc/cpuinfo)"

echo
echo "== app side (uid 10123): stat and ptmx =="
su 10123 -c "cat $T" 2>&1
su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1
echo "root cat: $(cat $T 2>&1)"

echo
echo "== hold 6 s with the hook live =="
sleep 6
echo "uptime: $(cat /proc/uptime)"
su 10123 -c "cat $T" 2>&1
su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1

echo
echo "== wait out ih_secs=20 so the kernel restores the entry itself =="
sleep 14
echo "uptime: $(cat /proc/uptime)"
dmesg | tail -12

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "uptime: $(cat /proc/uptime)"
echo "root cat: $(cat $T 2>&1)   (expect: secret)"
echo "app  cat: $(su 10123 -c "cat $T" 2>&1)   (expect: Permission denied)"
echo "ptmx: $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
echo "### done"
