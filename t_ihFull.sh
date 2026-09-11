#!/system/bin/sh
# Production shape: ih_enabled=1 (all eight entries at once), every other layer
# present, timed restore after 25 s.
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
D=/data/local/tmp/dac_probe
T=$D/f600
L=$D/link600
UP=/data/local/tmp/.up

up() { cat /proc/uptime | cut -d' ' -f1; }

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 600 $T
ln -sf $T $L
dmesg -c >/dev/null 2>&1

echo "== insmod ih_enabled=1 ih_secs=25 no_extra=0 =="
ksud insmod $K ih_enabled=1 ih_secs=25 no_extra=0
echo "insmod rc=$?  uptime $(up)"

echo
echo "== supercall: arm + one rule (hooks install here) =="
$KT add_sus_path $T
echo "add rc=$?"
dmesg | grep -E 'susfs_ih|sus_path: (inline|hooks armed|hidden|syscall)' | tail -20

echo
echo "== 2 s: every CPU alive? =="
sleep 2
echo "uptime $(up)  cpus=$(grep -c processor /proc/cpuinfo)"

echo
echo "== syscall coverage, uid 10123 =="
echo "openat      : $(su 10123 -c "cat $T" 2>&1)"
echo "fstatat     : $(su 10123 -c "ls -l $T" 2>&1)"
echo "stat(coreut): $(su 10123 -c "stat $T" 2>&1)"
echo "faccessat   : $(su 10123 -c "test -r $T && echo READABLE || echo NOPE" 2>&1)"
echo "readlinkat  : $(su 10123 -c "readlink $L" 2>&1)"
echo "execve      : $(su 10123 -c "$T" 2>&1)"
echo "ptmx        : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
echo "ls /system  : $(su 10123 -c 'ls /system/bin >/dev/null 2>&1 && echo LS_OK || echo LS_FAIL' 2>&1)"

echo
echo "== root still sees it =="
echo "root cat    : $(cat $T 2>&1)"
echo "root ls -l  : $(ls -l $T 2>&1)"
echo "root stat   : $(stat -c '%s %A' $T 2>&1)"

echo
echo "== hold 8 s with all eight entries patched =="
sleep 8
echo "uptime $(up)  cpus=$(grep -c processor /proc/cpuinfo)"
echo "ptmx        : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
echo "openat again: $(su 10123 -c "cat $T" 2>&1)"

echo
echo "== wait out ih_secs=25 so the kernel restores all eight itself =="
sleep 18
echo "uptime $(up)"
dmesg | grep -E 'susfs_ih|no longer hooking' | tail -12
echo "openat after restore: $(su 10123 -c "cat $T" 2>&1)   (LSM layer should still say denied)"

echo
echo "== counter check: how often did the stub actually decide? =="
dmesg | grep -c 'susfs_ih'

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?  uptime $(up)"
echo "root cat: $(cat $T 2>&1)"
echo "app  cat: $(su 10123 -c "cat $T" 2>&1)"
echo "ptmx: $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
echo "### done"
