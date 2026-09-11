#!/system/bin/sh
# The shipped default: no ih_* parameters at all, no timed rollback - just
# insmod, one rule (which installs the eight entries), the usual checks, then
# rmmod.  This is what a user gets.
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
D=/data/local/tmp/dac_probe
T=$D/f600
UP=/data/local/tmp/.up

up() { cat /proc/uptime | cut -d' ' -f1; }

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 600 $T
dmesg -c >/dev/null 2>&1

echo "== insmod with defaults (no ih_* parameters) =="
ksud insmod $K
echo "insmod rc=$?  uptime $(up)"

echo
echo "== add_sus_path: the eight entries install here =="
$KT add_sus_path $T
echo "add rc=$?"
dmesg | grep -E 'susfs_ih|sus_path: (inline|hooks armed|syscall)' | tail -14

echo
echo "== 3 s later =="
sleep 3
echo "uptime $(up)  cpus=$(grep -c processor /proc/cpuinfo)"

echo
echo "== uid 10123 =="
echo "openat   : $(su 10123 -c "cat $T" 2>&1)"
echo "fstatat  : $(su 10123 -c "ls -l $T" 2>&1)"
echo "statx    : $(su 10123 -c "stat $T" 2>&1)"
echo "faccessat: $(su 10123 -c "test -r $T && echo READABLE || echo NOPE" 2>&1)"
echo "execve   : $(su 10123 -c "$T" 2>&1)"
echo "ptmx     : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
echo "ls system: $(su 10123 -c 'ls /system/bin >/dev/null 2>&1 && echo LS_OK || echo LS_FAIL' 2>&1)"

echo
echo "== root =="
echo "root cat : $(cat $T 2>&1)"
echo "root stat: $(stat -c '%s %A' $T 2>&1)"

echo
echo "== second rule (hot path again, with a rule already installed) =="
printf 'secret2\n' > $D/g601
chmod 600 $D/g601
$KT add_sus_path $D/g601
sleep 2
echo "uptime $(up)"
echo "g601 app : $(su 10123 -c "cat $D/g601" 2>&1)"
echo "f600 app : $(su 10123 -c "cat $T" 2>&1)"

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?  uptime $(up)"
dmesg | grep -iE 'susfs_ih|BUG|WARNING|Unable to handle' | tail -8
echo "app  cat : $(su 10123 -c "cat $T" 2>&1)   (expect Permission denied)"
echo "root cat : $(cat $T 2>&1)"
echo "ptmx     : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
echo "### done"
