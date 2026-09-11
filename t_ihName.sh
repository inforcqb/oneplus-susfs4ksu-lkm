#!/system/bin/sh
# entry #9 = getname, the onLeave hook.
#
# getname is on every path lookup, so the install itself is the stress test: if
# the LEAVE stub got the SP/LR hand-off wrong the box dies the moment the entry
# is patched.  The hidden-path check then tells us whether the after-handler
# really replaced the returned struct filename.
#
#   sh /data/local/tmp/t_ihName.sh [no_extra]
NOE=${1:-0}
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
D=/data/local/tmp/dac_probe
T=$D/f600

up() { cat /proc/uptime | cut -d' ' -f1; }

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 600 $T
dmesg -c >/dev/null 2>&1

echo "== insmod ih_only=9 ih_secs=12 no_extra=$NOE =="
ksud insmod $K ih_only=9 ih_secs=12 no_extra=$NOE
echo "insmod rc=$?  uptime $(up)"

echo
echo "== add_sus_path: getname is patched here =="
$KT add_sus_path $T
echo "add rc=$?"
dmesg | grep -E 'susfs_ih|sus_path: (inline|hooks armed|hidden|getname)' | tail -10

echo
echo "== 2 s =="
sleep 2
echo "uptime $(up)  cpus=$(grep -c processor /proc/cpuinfo)"

echo
echo "== uid 10123 =="
echo "openat   : $(su 10123 -c "cat $T" 2>&1)"
echo "fstatat  : $(su 10123 -c "ls -l $T" 2>&1)"
echo "ptmx     : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
echo "ls system: $(su 10123 -c 'ls /system/bin >/dev/null 2>&1 && echo LS_OK || echo LS_FAIL' 2>&1)"
echo "root cat : $(cat $T 2>&1)"

echo
echo "== hold 6 s (every process is doing getname) =="
sleep 6
echo "uptime $(up)  cpus=$(grep -c processor /proc/cpuinfo)"
echo "openat   : $(su 10123 -c "cat $T" 2>&1)"
echo "getname log: $(dmesg | grep -c 'getname hit')"

echo
echo "== wait out ih_secs=12 =="
sleep 8
echo "uptime $(up)"
dmesg | grep -E 'susfs_ih|no longer hooking' | tail -4
echo "openat   : $(su 10123 -c "cat $T" 2>&1)   (falls back to the kprobe layers)"

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?  uptime $(up)"
dmesg | grep -iE 'BUG|WARNING|Unable to handle|Call trace' | tail -5
echo "app  cat : $(su 10123 -c "cat $T" 2>&1)"
echo "ptmx     : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
echo "### done"
