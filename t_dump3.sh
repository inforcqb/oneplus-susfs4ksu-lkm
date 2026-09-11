#!/system/bin/sh
# Newest minidump only, and only the parts that matter.
GZ=$(ls -t /mnt/vendor/oplusreserve/media/log/minidump/SYSTEM_LAST_KMSG@*.gz 2>/dev/null | head -1)
echo "dump: $(basename "$GZ")"
zcat "$GZ" > /data/local/tmp/k.txt 2>/dev/null
echo "size: $(wc -c < /data/local/tmp/k.txt)"

echo
echo "===== panic / fault lines ====="
grep -a -n -E 'Kernel panic|Unable to handle|Internal error|CFI failure|BUG:|WARNING:|Call trace|pc :|lr :|esr |Far |FAR' /data/local/tmp/k.txt | tail -45

echo
echo "===== our module ====="
grep -a -n -E 'susfs_guard_lkm|sus_path|sus_mount|sus_map|open_redirect|kstat' /data/local/tmp/k.txt | tail -45

echo
echo "===== open600 / dac_probe (the test files) ====="
grep -a -n -E 'dac_probe|open600|link600' /data/local/tmp/k.txt | tail -20

echo
echo "===== last 2500 bytes ====="
tail -c 2500 /data/local/tmp/k.txt
