#!/system/bin/sh
# stage 1: does the inline-hooked __arm64_sys_openat (a) hide the path and
# (b) still let every other open through the trampoline?
exec > /data/local/tmp/ih2_out.txt 2>&1

D=/data/local/tmp/dac_probe
T=$D/f600

rmmod susfs_guard_lkm 2>/dev/null
rmmod ih_hook_test 2>/dev/null

rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 600 $T

echo "### before the hook (expect EACCES for the app)"
echo "app 64-bit : $(su 10123 -c "cat $T" 2>&1)"
echo "root       : $(cat $T)"

ksud insmod /data/local/tmp/ih_hook_test.ko
echo "insmod rc=$?"
lsmod | grep ih_hook

echo
echo "### after the hook"
echo "app 64-bit on the hidden path (expect ENOENT from the inline hook):"
echo "   $(su 10123 -c "cat $T" 2>&1)"
echo "root on the hidden path (gate is apps only, expect the file):"
echo "   $(cat $T)"
echo "app 64-bit on other paths (trampoline must keep them working):"
echo "   ls /data/local/tmp -> $(su 10123 -c "ls /data/local/tmp" 2>&1 | tr '\n' ' ' | cut -c1-60)"
echo "   cat /system/build.prop -> $(su 10123 -c "head -c 40 /system/build.prop" 2>&1 | tr '\n' ' ')"
echo "   cat on the same path as root-owned 0644 file: $(su 10123 -c "cat $D/../dac_probe/../dac_probe/f600" 2>&1)"

echo
echo "### stress: lots of opens through the trampoline"
su 10123 -c "ls -R /system/bin >/dev/null 2>&1"
su 10123 -c "ls -R /system/framework >/dev/null 2>&1"
su 10123 -c "ls -R /apex >/dev/null 2>&1"
ls -R /system/bin >/dev/null 2>&1
echo "stress rc=$?"
echo "dmesg complaints: $(dmesg | grep -c -e 'BUG:' -e 'WARNING:' -e 'Call trace' -e 'panic')"

echo
echo "### unhook"
rmmod ih_hook_test
echo "rmmod rc=$?"
echo "app 64-bit after unhook (expect EACCES again): $(su 10123 -c "cat $T" 2>&1)"

echo
echo "### dmesg"
dmesg | grep -e ih_hook -e ih_probe | tail -12
echo "### end"
