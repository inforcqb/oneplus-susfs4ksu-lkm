#!/system/bin/sh
exec > /data/local/tmp/selfhide.txt 2>&1

echo "=== ROOT view (must keep working) ==="
echo "-- stat --"
ls -l /proc/susfs_kstat /proc/susfs_open_redirect /proc/susfs_enable_log /proc/susfs_avc_spoof 2>&1
echo "-- read kstat node --"
cat /proc/susfs_kstat 2>&1 | head -3
echo
echo "=== APP view (must be ENOENT, NOT EACCES) ==="
su 10378 -c 'id
for p in /proc/susfs_kstat /proc/susfs_open_redirect /proc/susfs_enable_log /proc/susfs_avc_spoof; do
  echo "-- $p --"
  ls -l "$p" 2>&1
  cat "$p" 2>&1 | head -1
done
echo "-- hide_list --"
cat /sys/module/susfs_guard_lkm/parameters/hide_list 2>&1 | head -1
'
echo
echo "=== counters ==="
cat /sys/module/susfs_guard_lkm/parameters/hide_list 2>&1
echo
echo "=== dmesg ==="
dmesg | grep -i -E "sus_path: hidden|self-hide" | tail -6
echo DONE
