#!/system/bin/sh
# Verify the cbz w0 fix: with ih_enabled=1 the patched entries must not break
# /dev/ptmx (that was the pty symptom) and must still hide registered paths.
exec > /data/local/tmp/ih4_out.txt 2>&1

K=/data/local/tmp/susfs.ko
D=/data/local/tmp/dac_probe
T=$D/f600
KT=/data/adb/ksu/bin/ksu_susfs

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'secret\n' > $T
chmod 755 $D
chmod 600 $T

ptmx_test() { exec 3<>/dev/ptmx && echo "ptmx open-ok" || echo "ptmx FAILED"; }

echo "### baseline (module not loaded)"
echo "app  ptmx: $(su 10123 -c 'exec 3<>/dev/ptmx && echo open-ok || echo failed' 2>&1)"
echo "app  cat : $(su 10123 -c "cat $T" 2>&1)"

echo
echo "### insmod ih_enabled=1"
ksud insmod $K ih_enabled=1
echo "insmod rc=$?"
dmesg | tail -25 | grep -a -e susfs_ih -e "inline hooks" | tail -12

echo
echo "### after the patches are armed"
echo "app  ptmx: $(su 10123 -c 'exec 3<>/dev/ptmx && echo open-ok || echo failed' 2>&1)"
echo "root ptmx: $(su 0 -c 'exec 3<>/dev/ptmx && echo open-ok || echo failed' 2>&1)"
echo "app  ls /: $(su 10123 -c 'ls /' 2>&1 | tr '\n' ' ' | cut -c1-50)"

echo
echo "### register a hidden path and check both sides"
$KT add_sus_path $T
sleep 1
echo "app  on hidden path (expect ENOENT): $(su 10123 -c "cat $T" 2>&1)"
echo "root on hidden path (expect secret): $(cat $T 2>&1)"
echo "app  ptmx again: $(su 10123 -c 'exec 3<>/dev/ptmx && echo open-ok || echo failed' 2>&1)"

echo
echo "### stress (trampoline must let everything through)"
su 10123 -c "ls -R /system/bin >/dev/null 2>&1; echo rc=$?"
su 10123 -c "ls -R /apex >/dev/null 2>&1; echo rc=$?"
ls -R /system >/dev/null 2>&1; echo "root rc=$?"
echo "complaints: $(dmesg | tail -200 | grep -c -a -e 'BUG:' -e 'WARNING:' -e 'Unable to handle')"

echo
echo "### rmmod"
rmmod susfs_guard_lkm
echo "rc=$?"
echo "app on hidden path after rmmod (expect EACCES): $(su 10123 -c "cat $T" 2>&1)"
echo "app  ptmx after rmmod: $(su 10123 -c 'exec 3<>/dev/ptmx && echo open-ok || echo failed' 2>&1)"
echo "### end"
