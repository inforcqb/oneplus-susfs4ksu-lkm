#!/system/bin/sh
# Diagnostic for the reverse disguise: is the readlink surface reachable at all,
# and does the d_path hook see it?
D=/data/local/tmp/dac_probe
T=$D/target.txt
R=$D/redir.txt
OR=/proc/susfs_open_redirect
K=/data/local/tmp/susfs.ko

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'TA\n' > $T
printf 'RD\n' > $R
chmod 644 $T $R

echo "== WITHOUT the module: does the helper work? =="
echo "app : $(su 10123 -c "sh /data/local/tmp/t_app_rd.sh $R" 2>&1)"
echo "root: $(sh /data/local/tmp/t_app_rd.sh $R 2>&1)"

echo
echo "== with the module, scheme 0 rule =="
ksud insmod $K expose_proc=1
sleep 1
echo "add_open_redirect $T $R 0" > $OR
sleep 1
grep -E 'hooks|rev hits' $OR

echo
echo "-- app readlink (expect the target path if the hook fires) --"
OUT=$(su 10123 -c "sh /data/local/tmp/t_app_rd.sh $R" 2>&1)
echo "$OUT"
echo "raw rc: $?"
echo
echo "-- root readlink (expect the redirected path) --"
echo "$(sh /data/local/tmp/t_app_rd.sh $R 2>&1)"

echo
echo "== counters after those two reads =="
grep -E 'rev hits' $OR

echo
echo "== does the d_path kprobe see anything at all? (any d_path call) =="
dmesg | grep -iE 'open_redirect|d_path' | tail -6

echo
echo "== control: kstat's maps path uses d_path too -- read maps as app =="
echo "app maps lines: $(su 10123 -c 'grep -c "" /proc/self/maps')"
grep -E 'rev hits' $OR

rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "### done"
