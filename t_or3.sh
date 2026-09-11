#!/system/bin/sh
# Reverse disguise, second attempt: the first one could not work because `exec
# 3<file` sets close-on-exec, so the readlink child never saw fd 3.
#
# Upstream's reverse surface includes the NAME column of /proc/<pid>/maps, which
# is rendered through d_path - so run a copy of the shell under the redirected
# path and look at what maps calls it.
K=/data/local/tmp/susfs.ko
OR=/proc/susfs_open_redirect
D=/data/local/tmp/dac_probe
T=$D/target_sh
R=$D/redir_sh

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
cp /system/bin/sh $T
cp /system/bin/sh $R
chmod 755 $T $R
echo "target: $(ls -i $T | cut -d' ' -f1)  redirected: $(ls -i $R | cut -d' ' -f1)"

ksud insmod $K expose_proc=1
sleep 1

echo
echo "== baseline: what does the app's maps call the redirected binary? =="
su 10123 -c "sh /data/local/tmp/t_vma.sh $R" 2>&1

echo
echo "== rule: target=$T redirected=$R scheme 0 =="
echo "add_open_redirect $T $R 0" > $OR
sleep 1
grep -E 'hooks|rev hits' $OR

echo
echo "== app runs the redirected binary again =="
su 10123 -c "sh /data/local/tmp/t_vma.sh $R" 2>&1
echo "--- counters ---"
grep -E 'rev hits' $OR

echo
echo "== root runs it (outside the reverse gate, expect the real name) =="
sh /data/local/tmp/t_vma.sh $R 2>&1
grep -E 'rev hits' $OR

echo
echo "== statfs surface: target on /data, redirected on tmpfs =="
printf 'x\n' > $D/t2
: > /dev/t2
echo "add_open_redirect $D/t2 /dev/t2 3" > $OR
sleep 1
echo "app  stat -f /dev/t2 : $(su 10123 -c 'stat -f -c %T /dev/t2' 2>&1)   (expect the data fs type)"
echo "root stat -f /dev/t2 : $(stat -f -c %T /dev/t2 2>&1)"
echo "app  stat -f target  : $(su 10123 -c "stat -f -c %T $D/t2" 2>&1)"
grep -E 'rev hits' $OR

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
su 10123 -c "sh /data/local/tmp/t_vma.sh $R" 2>&1
dmesg | grep -iE 'BUG:|WARNING:|Call trace|CFI failure' | tail -4
echo "### done"
