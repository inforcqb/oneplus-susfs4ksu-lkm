#!/system/bin/sh
# Does an ordinary app live in its own mount namespace (i.e. would it see clone
# copies of the KSU mounts, which our marking cannot reach)?
echo "init ns: $(readlink /proc/1/ns/mnt 2>/dev/null)"
echo "su   ns: $(readlink /proc/self/ns/mnt 2>/dev/null)"
echo
echo "--- app processes (uid>=10000) ---"
ps -A -o PID,UID | awk '$2 >= 10000 {print $1, $2}' | head -6 | while read p u; do
	echo "pid=$p uid=$u ns=$(readlink /proc/$p/ns/mnt 2>/dev/null) data_adb_rows=$(grep -c '/data/adb' /proc/$p/mountinfo 2>/dev/null)"
done
echo
echo "--- zygote ---"
for p in $(pidof zygote64 2>/dev/null); do
	echo "zygote pid=$p ns=$(readlink /proc/$p/ns/mnt 2>/dev/null) data_adb_rows=$(grep -c '/data/adb' /proc/$p/mountinfo 2>/dev/null)"
done
echo
echo "--- KSU mount ids in init ns ---"
grep -E '/data/adb' /proc/1/mountinfo | cut -c1-30
