#!/system/bin/sh
# sus_map read gate: apps must lose the line, root and system must keep it.
#
# The target has to be the file the reader actually maps.  On Android 13 that is
# the APEX libc (/apex/com.android.runtime/lib64/bionic/libc.so), not the
# /system/lib64 stub - registering the stub silently matches nothing.
K=/data/local/tmp/susfs.ko

rmmod susfs_guard_lkm 2>/dev/null
dmesg -c >/dev/null 2>&1

LIB=$(su 10123 -c 'grep -m1 libc.so /proc/self/maps' | awk '{print $NF}')
INO=$(stat -c %i "$LIB")
echo "target: $LIB ino=$INO"

count() { su "$1" -c "grep -c libc.so /proc/self/maps"; }
total() { su "$1" -c "grep -c '' /proc/self/maps"; }

echo
echo "== baseline (no module) =="
echo "app(10123) libc : $(count 10123)   total: $(total 10123)"
echo "root       libc : $(count 0)   total: $(total 0)"
echo "system1000 libc : $(count 1000)"

echo
echo "== insmod map_ino=$INO =="
ksud insmod $K map_ino=$INO
echo "insmod rc=$?"
dmesg | grep -E 'sus_map|kstat' | tail -4

echo
echo "== with the rule registered =="
echo "app(10123) libc : $(count 10123)   (expect 0)"
echo "app(10123) total: $(total 10123)   (expect baseline - mapped lines)"
echo "app can still read maps: $(su 10123 -c 'head -1 /proc/self/maps' | wc -c) bytes"
echo "root       libc : $(count 0)   (expect unchanged -- the gate)"
echo "root       total: $(total 0)"
echo "system1000 libc : $(count 1000)   (expect unchanged -- the gate)"
echo "shell2000  libc : $(su 2000 -c 'grep -c libc.so /proc/self/maps')"

echo
echo "== gate log =="
dmesg | grep -E 'sus_map' | tail -5

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "app(10123) libc : $(count 10123)   (expect back to baseline)"
echo "root       libc : $(count 0)"
dmesg | grep -iE 'BUG:|WARNING:|Call trace|CFI failure' | tail -4
echo "### done"
