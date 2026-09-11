#!/system/bin/sh
# Do we still need the LSM layer now that the syscall entries are inline-hooked?
#
# The inline hooks match the caller's path STRING (absolute, exact or /-prefixed),
# so they cannot see the same file reached another way.  The LSM layer matches the
# inode, so it can.  Run the same probe twice: once with every layer, once with
# no_extra=1 (LSM/DAC/tracepoint off, inline hooks on).
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
D=/data/local/tmp/dac_probe
T=$D/open600
L=$D/link600
R=$D/rel

run_case() {
	NOE=$1
	rmmod susfs_guard_lkm 2>/dev/null
	rm -rf $D
	mkdir -p $D
	printf 'secret\n' > $T
	chmod 755 $D
	chmod 644 $T
	ln -sf $T $L
	dmesg -c >/dev/null 2>&1
	ksud insmod $K no_extra=$NOE >/dev/null 2>&1
	$KT add_sus_path $T >/dev/null 2>&1
	sleep 2
	echo "  --- no_extra=$NOE (layers: $([ $NOE = 1 ] && echo 'inline hook only' || echo 'inline hook + LSM + DAC + tracepoint')) ---"
	echo "  abs path   : $(su 10123 -c "cat $T" 2>&1)"
	echo "  symlink    : $(su 10123 -c "cat $L" 2>&1)   <- string layer never sees this path"
	echo "  relative   : $(su 10123 -c "cd $D && cat open600" 2>&1)   <- same, relative"
	echo "  dotdot     : $(su 10123 -c "cat $D/../dac_probe/open600" 2>&1)"
	echo "  /proc/self/root : $(su 10123 -c "cat /proc/self/root$T" 2>&1)"
	echo "  hardlink   : $(su 10123 -c "sh /data/local/tmp/t_ln.sh $T $R" 2>&1 | tr '\n' ' ')"
	echo "  rename     : $(su 10123 -c "mv $T ${T}.moved" 2>&1)"
	echo "  chmod      : $(su 10123 -c "chmod 600 $T" 2>&1)"
	echo "  dir list   : [$(su 10123 -c "ls $D" 2>&1 | tr '\n' ' ')]"
	echo "  root abs   : $(cat $T 2>&1)"
	rmmod susfs_guard_lkm
}

echo "=== A: every layer present ==="
run_case 0
echo
echo "=== B: inline hooks only (no_extra=1) ==="
run_case 1
echo
echo "### done"
