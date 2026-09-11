#!/system/bin/sh
# stage 0: which entry points can actually be patched?
exec > /data/local/tmp/ih_out.txt 2>&1

rmmod ih_probe_test 2>/dev/null
ksud insmod /data/local/tmp/ih_probe_test.ko
echo "insmod rc=$?"
lsmod | grep ih_probe

echo "=== report ==="
dmesg | grep ih_probe | tail -70

rmmod ih_probe_test
echo "rmmod rc=$?"
echo "=== end ==="
