#!/system/bin/sh
# Does the DAC layer actually get called?  A 0600 root-owned file is the clean
# test: DAC denies the app, so the LSM layer can never be reached - ENOENT means
# the inode_permission kprobe ran, EACCES means it did not.
K=/data/local/tmp/susfs.ko
KT=/data/adb/ksu/bin/ksu_susfs
D=/data/local/tmp/dac_probe
exec > /data/local/tmp/kfix4_out.txt 2>&1

err() { "$@" 2>&1; echo "   -> rc/errno=$?"; }

rmmod susfs_guard_lkm 2>/dev/null
ksud insmod $K

rm -rf $D
mkdir -p $D/sub
printf 'secret\n' > $D/f600
printf 'secret\n' > $D/f644
printf 'secret\n' > $D/sub/deep
chmod 755 $D
chmod 600 $D/f600
chmod 644 $D/f644
chmod 700 $D/sub
echo "modes: $(stat -c '%a %n' $D/pwd 2>/dev/null; ls -ld $D $D/f600 $D/f644 $D/sub | tr -s ' ')"

echo "### baseline (no rules): app must get EACCES on the 0600 file"
err su 10123 -c "cat $D/f600"
err su 10123 -c "ls $D/sub"

echo
echo "### register the 0600 file: ENOENT => the DAC hook ran"
$KT add_sus_path $D/f600
sleep 1
err su 10123 -c "cat $D/f600"
err su 10123 -c "stat $D/f600"

echo
echo "### register the 0700 dir: ENOENT => the DAC hook covers directory MAY_EXEC"
$KT add_sus_path $D/sub
sleep 1
err su 10123 -c "ls $D/sub"
err su 10123 -c "cat $D/sub/deep"
err su 10123 -c "stat $D/sub"

echo
echo "### root is unaffected"
echo "root cat f600: $(cat $D/f600)"
echo "root ls sub:   $(ls $D/sub)"

rmmod susfs_guard_lkm
echo "rmmod rc=$?"
err su 10123 -c "cat $D/f600"
echo "### end"
