#!/system/bin/sh
# Is the patched onLeave entry reached at all?
#
# The hidden file is 644 on purpose: with 600 the kernel's own DAC check answers
# EACCES before any of our layers get a say, which hides whatever the getname
# layer did.  With 644 only our layers can deny it, so the answer is either
# ENOENT (the after-handler fired) or the content (it did not).
NOE=${1:-0}
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
D=/data/local/tmp/dac_probe
T=$D/open600

up() { cat /proc/uptime | cut -d' ' -f1; }

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 644 $T
dmesg -c >/dev/null 2>&1

echo "== baseline: can the app read it before any hook exists? =="
echo "app cat  : $(su 10123 -c "cat $T" 2>&1)   (expect: secret)"

echo
echo "== insmod ih_only=9 ih_secs=15 no_extra=$NOE =="
ksud insmod $K ih_only=9 ih_secs=15 no_extra=$NOE
echo "insmod rc=$?  uptime $(up)"
$KT add_sus_path $T
echo "add rc=$?"
dmesg | grep -E 'susfs_ih|sus_path: (inline|hooks armed|hidden)' | tail -6
echo "uptime $(up)  cpus=$(grep -c processor /proc/cpuinfo)"

echo
echo "== 2 s, then the app tries again =="
sleep 2
echo "app cat  : $(su 10123 -c "cat $T" 2>&1)   (ENOENT = the onLeave hook answered)"
echo "app ls   : $(su 10123 -c "ls $T" 2>&1)"
echo "root cat : $(cat $T 2>&1)"
echo "ptmx     : $(su 10123 -c 'exec 3<>/dev/ptmx && echo PTMX_OK || echo PTMX_FAIL' 2>&1)"
echo "getname log lines:"
dmesg | grep -E 'getname_flags returned' | head -12

echo
echo "== hold 5 s then look at the counters =="
sleep 5
echo "uptime $(up)"
dmesg | grep -cE 'getname_flags returned'
echo "path hits: $(dmesg | grep -c 'path hit')"

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?  uptime $(up)"
echo "app cat  : $(su 10123 -c "cat $T" 2>&1)"
echo "### done"
