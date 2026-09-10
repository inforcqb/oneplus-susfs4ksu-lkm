#!/system/bin/sh
# kstat: uid gate + /proc/<pid>/maps coverage, and the stat/maps cross-check.
K=/data/local/tmp/susfs.ko
T=/data/local/tmp/kt_fix
KT=/data/adb/ksu/bin/ksu_susfs
LIBC=/apex/com.android.runtime/lib64/bionic/libc.so
exec > /data/local/tmp/kfix2_out.txt 2>&1

echo "### load (expose_proc=0 default)"
rmmod susfs_guard_lkm 2>/dev/null
ksud insmod $K
echo "insmod rc=$?"
dmesg | grep -E "kstat armed|maps hook" | tail -5

echo
echo "### stat path + uid gate"
rm -f $T
printf 'aaaaaaaaa' > $T
chmod 644 $T
$KT add_sus_kstat_statically $T 11111 22222 default 4242 default default default default default default default default
echo "rule: $(dmesg | tail -1)"
echo "root stat (uid 0, above=nothing, expect REAL): $(stat -c 'ino=%i dev=%d size=%s' $T)"
echo "app  stat (uid 10123, expect SPOOFED)       : $(su 10123 -c "stat -c 'ino=%i dev=%d size=%s' $T")"

echo
echo "### maps coverage (libc.so ino spoofed to 33333)"
ls -l $LIBC
$KT add_sus_kstat_statically $LIBC 33333 default default default default default default default default default default default
echo "app  stat libc (expect ino=33333): $(su 10123 -c "stat -c 'ino=%i' $LIBC")"
echo "root stat libc (expect real ino) : $(stat -c 'ino=%i' $LIBC)"
echo "root  maps libc.so lines: $(grep -c 'libc.so' /proc/self/maps)   [expect >0]"
echo "app   maps libc.so lines: $(su 10123 -c "grep -c 'libc.so' /proc/self/maps" 2>/dev/null)   [expect 0]"
echo "app   maps total lines  : $(su 10123 -c "wc -l < /proc/self/maps")"
echo "root  maps total lines  : $(wc -l < /proc/self/maps)"

echo
echo "### unwrap: app sees libc again after rmmod"
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "app   maps libc.so lines: $(su 10123 -c "grep -c 'libc.so' /proc/self/maps" 2>/dev/null)   [expect >0]"
echo "### end"
