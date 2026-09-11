#!/system/bin/sh
# Does a 32-bit (compat) caller see ENOENT for a hidden path?
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
D=/data/local/tmp/dac_probe
B=/data/local/tmp/test_compat_open
exec > /data/local/tmp/kfix5_out.txt 2>&1

rmmod susfs_guard_lkm 2>/dev/null
ksud insmod $K
dmesg | grep -E "syscall layer armed" | tail -2

rm -rf $D
mkdir -p $D
printf 'secret\n' > $D/f600
chmod 755 $D
chmod 600 $D/f600
chmod 755 $B

echo "### baseline, no rule"
echo "64-bit: $(su 10123 -c "cat $D/f600" 2>&1)"
echo "32-bit: $(su 10123 -c "$B" 2>&1)"

echo
echo "### after registering $D/f600"
$KT add_sus_path $D/f600
sleep 1
echo "64-bit: $(su 10123 -c "cat $D/f600" 2>&1)"
echo "32-bit: $(su 10123 -c "$B" 2>&1)"

echo
echo "### and a 0755 path, 32-bit"
touch $D/vis
chmod 644 $D/vis
$KT add_sus_path $D/vis
sleep 1
echo "32-bit program always tests f600, so also check with ls: $(su 10123 -c "ls $D/vis" 2>&1)"

echo
echo "### dmesg"
dmesg | grep -E "path hit|compat" | tail -8

rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "### end"
