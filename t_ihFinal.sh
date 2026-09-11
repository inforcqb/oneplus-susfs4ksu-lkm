#!/system/bin/sh
# Final shape: default parameters (nine patched entries: the eight native
# syscall wrappers plus the getname_flags onLeave hook), every layer present,
# no timed rollback - rmmod has to put it all back.
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
D=/data/local/tmp/dac_probe
T=$D/open600
L=$D/link600

up() { cat /proc/uptime | cut -d' ' -f1; }

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 644 $T
ln -sf $T $L
dmesg -c >/dev/null 2>&1

echo "== baseline =="
echo "app cat : $(su 10123 -c "cat $T" 2>&1)"

echo
echo "== insmod, no parameters =="
ksud insmod $K
echo "insmod rc=$?  uptime $(up)"
$KT add_sus_path $T
echo "add rc=$?"
dmesg | grep -E 'susfs_ih: (hooked|trying)|inline hooks armed|layer armed' | tail -16
echo "uptime $(up)  cpus=$(grep -c processor /proc/cpuinfo)"

echo
echo "== 2 s: uid 10123 =="
sleep 2
echo "openat   : $(su 10123 -c "cat $T" 2>&1)"
echo "fstatat  : $(su 10123 -c "ls -l $T" 2>&1)"
echo "statx    : $(su 10123 -c "stat $T" 2>&1)"
echo "faccessat: $(su 10123 -c "test -r $T && echo READABLE || echo NOPE" 2>&1)"
echo "execve   : $(su 10123 -c "$T" 2>&1)"
echo "readlink : $(su 10123 -c "readlink $L" 2>&1)"
echo "ptmx     : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
echo "ls /sys  : $(su 10123 -c 'ls /system/bin >/dev/null 2>&1 && echo LS_OK || echo LS_FAIL' 2>&1)"

echo
echo "== root =="
echo "cat  : $(cat $T 2>&1)"
echo "stat : $(stat -c '%s %A' $T 2>&1)"

echo
echo "== hold 5 s =="
sleep 5
echo "uptime $(up)  cpus=$(grep -c processor /proc/cpuinfo)"
echo "app cat : $(su 10123 -c "cat $T" 2>&1)"
echo "ptmx    : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"

echo
echo "== second rule, hot path again =="
printf 'secret2\n' > $D/g601
chmod 644 $D/g601
$KT add_sus_path $D/g601
sleep 2
echo "uptime $(up)"
echo "g601 app: $(su 10123 -c "cat $D/g601" 2>&1)"
echo "f600 app: $(su 10123 -c "cat $T" 2>&1)"
echo "ptmx    : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?  uptime $(up)"
echo "--- anything alarming in the ring buffer? ---"
dmesg | grep -iE 'CFI failure|BUG:|WARNING:|Unable to handle|Call trace|panic' | tail -6
echo "app cat : $(su 10123 -c "cat $T" 2>&1)   (expect: secret again)"
echo "root cat: $(cat $T 2>&1)"
echo "ptmx    : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
echo "### done"
