#!/system/bin/sh
# open_redirect: the five uid_scheme levels and the reverse disguise.
#   add_open_redirect <target> <redirected> <uid_scheme>
K=/data/local/tmp/susfs.ko
OR=/proc/susfs_open_redirect
D=/data/local/tmp/dac_probe
T=$D/target.txt
R=$D/redir.txt
RD="sh /data/local/tmp/t_app_rd.sh"

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
printf 'TA\n' > $T
printf 'RD\n' > $R
chmod 644 $T $R

ksud insmod $K expose_proc=1
echo "insmod rc=$?"
sleep 1
echo "domain root: $(cat /proc/self/attr/current 2>/dev/null)"
echo "domain su  : $(su -c 'cat /proc/self/attr/current' 2>/dev/null)"
echo "domain app : $(su 10123 -c 'cat /proc/self/attr/current' 2>/dev/null)"
echo "--- node ---"
head -4 $OR

echo
echo "== scheme 0 (UID_NON_APP_PROC) =="
echo "add_open_redirect $T $R 0" > $OR
sleep 1
dmesg | grep -iE 'open_redirect' | tail -3
head -4 $OR
echo "root cat target: $(cat $T)   (expect RD - non-app)"
echo "app  cat target: $(su 10123 -c "cat $T")   (expect TA - app is not matched)"

echo
echo "== reverse disguise (readlink of an fd on the redirected path) =="
echo "app  sees: $(su 10123 -c "$RD $R")   (expect $T)"
echo "root sees: $(sh /data/local/tmp/t_app_rd.sh $R)   (expect $R)"
echo "--- hits ---"
grep -E 'rev hits|hooks' $OR

echo
echo "== scheme 1 (UID_ROOT_PROC_EXCEPT_SU_PROC) =="
echo "add_open_redirect $T $R 1" > $OR
sleep 1
echo "root cat target: $(cat $T)   (expect TA if root shell counts as su domain)"
echo "app  cat target: $(su 10123 -c "cat $T")   (expect TA)"

echo
echo "== scheme 2 (UID_NON_SU_PROC) =="
echo "add_open_redirect $T $R 2" > $OR
sleep 1
echo "su   cat target: $(su -c "cat $T")   (expect TA if this shell is the su domain)"
echo "root cat target: $(cat $T)"
echo "app  cat target: $(su 10123 -c "cat $T")   (expect RD)"
echo "u1000 cat      : $(su 1000 -c "cat $T")"
echo "root domain now: $(cat /proc/self/attr/current)"

echo
echo "== scheme 3 (UID_UMOUNTED_APP_PROC, uid>=10000 proxy) =="
echo "add_open_redirect $T $R 3" > $OR
sleep 1
echo "app  cat target: $(su 10123 -c "cat $T")   (expect RD)"
echo "root cat target: $(cat $T)   (expect TA)"
echo "su   cat target: $(su -c "cat $T")   (expect TA)"

echo
echo "== scheme 4 (UID_UMOUNTED_PROC, same proxy on this kernel) =="
echo "add_open_redirect $T $R 4" > $OR
sleep 1
echo "app  cat target: $(su 10123 -c "cat $T")   (expect RD)"
echo "root cat target: $(cat $T)"

echo
echo "== bad scheme =="
echo "add_open_redirect $T $R 9" > $OR
echo "rc=$?"

echo
echo "== table shape =="
head -6 $OR

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "app cat target: $(su 10123 -c "cat $T")   (expect TA again)"
dmesg | grep -iE 'BUG:|WARNING:|Call trace|CFI failure' | tail -4
echo "### done"
