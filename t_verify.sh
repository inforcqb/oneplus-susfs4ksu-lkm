#!/system/bin/sh
# Verify this round: the ln that used to crash, hiding still working with the
# in-place name rewrite, hide_syms landing on the right s_show, and open_redirect
# add/del churn (the or_del NULL-path oops).
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
D=/data/local/tmp/dac_probe
T=$D/open600
R=$D/rel
OR=/proc/susfs_open_redirect

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 644 $T
dmesg -c >/dev/null 2>&1

echo "== kallsyms before =="
echo "  susfs_/ksu_ matches: $(grep -cE 'susfs_|ksu_' /proc/kallsyms)"

ksud insmod $K
echo "insmod rc=$?"
sleep 1
echo "  hide_syms: $(dmesg | grep -o 'susfs_hide_syms: armed.*' | tail -1)"
echo "  susfs_/ksu_ matches after: $(grep -cE 'susfs_|ksu_' /proc/kallsyms)"

echo
echo "== 1) the operation that crashed the kernel before =="
echo "  $(su 10123 -c "sh /data/local/tmp/t_ln.sh $T $R" 2>&1 | tr '\n' ' ')"
echo "  uptime: $(cat /proc/uptime | cut -d' ' -f1)  cpus: $(grep -c processor /proc/cpuinfo)"

echo
echo "== 2) hiding still works (name is rewritten in place now) =="
$KT add_sus_path $T >/dev/null 2>&1
sleep 1
echo "  app abs path : $(su 10123 -c "cat $T" 2>&1)"
echo "  app relative : $(su 10123 -c "cd $D && cat open600" 2>&1)"
echo "  app symlink  : $(su 10123 -c "ln -sf $T $D/l600; cat $D/l600" 2>&1)"
echo "  app list     : [$(su 10123 -c "ls $D" 2>&1 | tr '\n' ' ')]"
echo "  root cat     : $(cat $T 2>&1)"
echo "  root list    : [$(ls $D 2>&1 | tr '\n' ' ')]"

echo
echo "== 3) open_redirect add/del churn (previously a NULL-path oops) =="
printf 'RD\n' > $R
chmod 644 $R
i=0
while [ $i -lt 6 ]; do
	echo "add_open_redirect $T $R 0" > $OR 2>&1
	su 10123 -c "cat $R" >/dev/null 2>&1
	echo "del $T" > $OR 2>&1
	su 10123 -c "cat $R" >/dev/null 2>&1
	echo "clear" > $OR 2>&1
	su 10123 -c "cat $R" >/dev/null 2>&1
	i=$((i+1))
done
echo "  churn finished, uptime: $(cat /proc/uptime | cut -d' ' -f1)"
echo "  root still reads: $(cat $R 2>&1)"

echo
echo "== 4) survivors =="
echo "  cpus: $(grep -c processor /proc/cpuinfo)   ptmx: $(su 10123 -c 'exec 3<>/dev/ptmx && echo OK || echo FAIL')"
echo "  app other path: $(su 10123 -c 'ls /system/bin | head -1' 2>&1)"

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "app cat after rmmod: $(su 10123 -c "cat $T" 2>&1)"
echo "--- alarming lines ---"
dmesg | grep -iE 'BUG:|WARNING:|Call trace|CFI failure|Oops|Unable to handle' | tail -6
echo "--- (end) ---"
echo "### done"
