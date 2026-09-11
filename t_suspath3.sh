#!/system/bin/sh
# sus_path DAC layer: does a hidden path answer ENOENT even when the caller is
# denied by DAC (the /data/adb case reported from the device)?
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
exec > /data/local/tmp/kfix3_out.txt 2>&1

err() { "$@" 2>&1; echo "   -> rc/errno=$?"; }

echo "### load"
rmmod susfs_guard_lkm 2>/dev/null
ksud insmod $K
dmesg | grep -E "DAC layer|getdents64 filter|hook armed" | tail -6

echo
echo "### baseline as app 10123 (no rule yet)"
err su 10123 -c "ls -la /data/adb/service.d"
err su 10123 -c "ls -la /data/adb"

echo
echo "### rule for service.d only (the reported case)"
$KT add_sus_path /data/adb/service.d
sleep 1
err su 10123 -c "ls -la /data/adb/service.d"

echo
echo "### now also register the parent /data/adb"
$KT add_sus_path /data/adb
sleep 1
err su 10123 -c "ls -la /data/adb"
err su 10123 -c "ls /data/adb/service.d"
err su 10123 -c "cat /data/adb/susfs4ksu/module.prop"

echo
echo "### root unaffected"
echo "root ls /data/adb:   $(ls /data/adb | tr '\n' ' ' | cut -c1-70)"
echo "root stat:           $(stat -c '%n %i' /data/adb)"

echo
echo "### 0755 path (DAC allows) still hidden for the app"
mkdir -p /data/local/tmp/kf3dir
chmod 755 /data/local/tmp/kf3dir
touch /data/local/tmp/kf3dir/zz_hidden
$KT add_sus_path /data/local/tmp/kf3dir/zz_hidden
sleep 1
err su 10123 -c "ls /data/local/tmp/kf3dir/zz_hidden"
echo "readdir of the dir itself: $(su 10123 -c 'ls /data/local/tmp/kf3dir')"

echo
echo "### rmmod, app sees everything again"
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
err su 10123 -c "ls -la /data/adb"
echo "### end"
