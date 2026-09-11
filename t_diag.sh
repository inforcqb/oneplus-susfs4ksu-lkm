#!/system/bin/sh
echo "== device/module state =="
echo "uptime: $(cat /proc/uptime | cut -d' ' -f1)  cpus: $(grep -c processor /proc/cpuinfo)"
echo "lsmod : [$(lsmod | grep susfs | tr '\n' ' ')]"

echo
echo "== which susfs_/ksu_ symbols are still visible? =="
grep -E 'susfs_|ksu_' /proc/kallsyms | head -12
echo "count: $(grep -cE 'susfs_|ksu_' /proc/kallsyms)"

echo
echo "== is the kallsyms s_show the one we hooked? =="
grep -E ' s_show$' /proc/kallsyms

echo
echo "== app access to unrelated paths =="
echo "app ls /system/bin : $(su 10123 -c 'ls /system/bin' 2>&1 | head -1)"
echo "app id             : $(su 10123 -c 'id' 2>&1)"
echo "app cat /proc/version: $(su 10123 -c 'cat /proc/version' 2>&1 | cut -c1-40)"
echo "app ls /data       : $(su 10123 -c 'ls /data' 2>&1 | head -1)"
echo "app domain         : $(su 10123 -c 'cat /proc/self/attr/current' 2>&1)"

echo
echo "== rmmod again (it hung or failed last time) =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "lsmod now: [$(lsmod | grep susfs | tr '\n' ' ')]"
echo "app ls /system/bin after: $(su 10123 -c 'ls /system/bin' 2>&1 | head -1)"
echo "### done"
