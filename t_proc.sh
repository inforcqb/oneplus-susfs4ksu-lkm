#!/system/bin/sh
# Are the module's /proc nodes resident?  Default is expose_proc=0.
K=/data/local/tmp/susfs.ko

rmmod susfs_guard_lkm 2>/dev/null
dmesg -c >/dev/null 2>&1

nodes() {
	echo "  ls /proc | grep susfs : [$(ls /proc 2>/dev/null | grep susfs | tr '\n' ' ')]"
	echo "  stat the four nodes   : [$(ls -d /proc/susfs_kstat /proc/susfs_open_redirect /proc/susfs_enable_log /proc/susfs_avc_spoof 2>&1 | tr '\n' ' ')]"
}
visibility() {
	echo "  /proc/modules         : [$(grep -c susfs /proc/modules 2>/dev/null) line(s)]"
	echo "  /sys/module           : [$(ls /sys/module 2>/dev/null | grep susfs | tr '\n' ' ')]"
	echo "  kallsyms susfs_       : $(grep -c -e susfs -e sus_path /proc/kallsyms 2>/dev/null) matching symbols"
}

echo "== A) default insmod (expose_proc defaults to 0) =="
ksud insmod $K
echo "insmod rc=$?"
nodes
visibility
echo "--- module's own log ---"
dmesg | grep -E 'node not created|proc ready|self-hide' | tail -6
echo "--- userland still works without any node? ---"
/data/adb/ksu/bin/ksu_susfs show version 2>&1 | tail -2
rmmod susfs_guard_lkm
echo "rmmod rc=$?"

echo
echo "== B) expose_proc=1 =="
dmesg -c >/dev/null 2>&1
ksud insmod $K expose_proc=1
echo "insmod rc=$?"
sleep 1
nodes
echo "--- module's own log ---"
dmesg | grep -E 'node not created|proc ready|self-hide|hidden (built-in)' | tail -10
echo "--- modes ---"
ls -l /proc/susfs_kstat /proc/susfs_open_redirect /proc/susfs_enable_log /proc/susfs_avc_spoof 2>&1

echo
echo "== C) app view of those nodes (expose_proc=1) =="
echo "  app ls /proc | grep susfs : [$(su 10123 -c 'ls /proc' | grep susfs | tr '\n' ' ')]"
echo "  app cat /proc/susfs_kstat : $(su 10123 -c 'cat /proc/susfs_kstat' 2>&1)"
echo "  app stat it               : $(su 10123 -c 'ls -l /proc/susfs_kstat' 2>&1)"
echo "  root cat (first line)     : $(head -1 /proc/susfs_kstat 2>&1)"

rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "=== after rmmod ==="
nodes
echo "### done"
