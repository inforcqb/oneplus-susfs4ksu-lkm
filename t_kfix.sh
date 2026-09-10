#!/system/bin/sh
# kstat fix verification: hooks armed with expose_proc=0 (default), supercall-only
# functionality, table race stress, sus_path getdents regression.
K=/data/local/tmp/susfs.ko
T=/data/local/tmp/kt_fix
D=/data/local/tmp/kfix_dir
KT=/data/adb/ksu/bin/ksu_susfs
exec > /data/local/tmp/kfix_out.txt 2>&1

echo "### cleanup"
rmmod susfs_guard_lkm 2>/dev/null
rmmod susfs 2>/dev/null
lsmod | grep -c "susfs"

echo "### insmod with DEFAULT params (expose_proc=0)"
ksud insmod $K
echo "insmod rc=$?"
lsmod | grep susfs

echo "### dmesg: expect 'kstat armed: 0 rules (tp=1 krp=1 proc=0)'"
dmesg | grep -E "susfs_guard_lkm: init|kstat armed|not created|hook" | tail -12

echo "### control nodes must be absent"
ls -l /proc/susfs_kstat 2>&1
ls -l /proc/susfs_open_redirect 2>&1

echo "### kstat functional test through the SUPERcall only"
rm -f $T
printf 'aaaaaaaaa' > $T
echo "real before      : $(stat -c 'size=%s ino=%i' $T)"
$KT add_sus_kstat $T
echo "add_sus_kstat rc=$?"
printf 'bbbbbb' >> $T
echo "real after append: $(stat -c 'size=%s' $T)   (real size is 15)"
echo "stat via hooks   : $(stat -c 'size=%s ino=%i' $T)   [expect size=9]"

echo "### statically spoof ino/dev/size through the supercall"
$KT add_sus_kstat_statically $T 11111 22222 default 4242 default default default default default default default default
echo "stat: $(stat -c 'ino=%i dev=%d size=%s' $T)   [expect ino=11111 dev=22222 size=4242]"

echo "### race: spoof churn (add/update) while stat() hammers the table"
rm -f /data/local/tmp/kfix_done
(
  i=0
  while [ $i -lt 300 ]; do
    $KT add_sus_kstat_statically $T $((1000+i)) $((2000+i)) default $((3000+i)) default default default default default default default default >/dev/null 2>&1
    $KT update_sus_kstat $T >/dev/null 2>&1
    i=$((i+1))
  done
  echo done > /data/local/tmp/kfix_done
) &
CH=$!
n=0
while [ ! -f /data/local/tmp/kfix_done ] && [ $n -lt 20000 ]; do
  stat -c "%i %s" $T >/dev/null 2>&1
  n=$((n+1))
done
wait $CH
echo "stats performed: $n (churn: 300 add+update rounds)"
echo "stat after churn: $(stat -c 'ino=%i size=%s' $T)"
echo "kernel complaints during churn:"
dmesg | grep -cE "BUG:|WARNING:|Call trace|Unable to handle|panic"
dmesg | tail -8

echo "### sus_path getdents regression (uid>=10000 gate)"
rm -rf $D
mkdir -p $D
chmod 755 $D
touch $D/aaa_visible $D/zzz_hidden
$KT add_sus_path $D/zzz_hidden
echo "add_sus_path rc=$?"
echo "root ls (uid 0, above the gate is for apps only): $(ls $D | tr '\n' ' ')"
echo "app  ls (uid 10123, expect only aaa_visible): $(su 10123 -c "ls $D" | tr '\n' ' ')"
echo "app  stat hidden (expect ENOENT): $(su 10123 -c "cat $D/zzz_hidden" 2>&1)"

echo "### rmmod"
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
lsmod | grep -c susfs_guard_lkm
echo "### end"
