#!/system/bin/sh
# Two-stage inline-hook test: the self-test first (crashes only this module's own
# call if it is wrong), then the real syscall hook.
exec > /data/local/tmp/ih3_out.txt 2>&1

D=/data/local/tmp/dac_probe
T=$D/f600

rmmod susfs_guard_lkm 2>/dev/null
rmmod ih_hook_test 2>/dev/null

rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 600 $T

echo "### stage A: self-test only (hook_syscall=0)"
ksud insmod /data/local/tmp/ih_hook_test.ko selftest=1 hook_syscall=0
echo "insmod rc=$?"
dmesg | grep -e ih_selftest -e ih_hook | tail -12
echo "module still alive: $(lsmod | grep -c ih_hook_test)"
echo "system alive: $(su 10123 -c 'ls /data' 2>&1 | tr '\n' ' ' | cut -c1-40)"
rmmod ih_hook_test 2>/dev/null
echo "rmmod rc=$?"

echo
echo "### stage B: real hook (hook_syscall=1)"
echo "before: $(su 10123 -c "cat $T" 2>&1)"
ksud insmod /data/local/tmp/ih_hook_test.ko selftest=0 hook_syscall=1
echo "insmod rc=$?"
dmesg | grep -e ih_hook | tail -4
echo "app on hidden path (expect ENOENT): $(su 10123 -c "cat $T" 2>&1)"
echo "root on hidden path (expect file) : $(cat $T)"
echo "app other paths (trampoline must work): $(su 10123 -c 'ls /system/bin | head -3' 2>&1 | tr '\n' ' ')"
echo "stress: $(su 10123 -c 'ls -R /system/bin >/dev/null 2>&1; echo rc=$?')"
echo "dmesg complaints: $(dmesg | grep -c -e 'BUG:' -e 'WARNING:' -e 'Unable to handle' -e 'Call trace')"
rmmod ih_hook_test
echo "rmmod rc=$?"
echo "after unhook (expect EACCES): $(su 10123 -c "cat $T" 2>&1)"
echo "### end"
