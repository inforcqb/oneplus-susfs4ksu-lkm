#!/system/bin/sh
# Second pass: the previous one matched thousands of lines and timed out.
echo "===== module lines (first 40) ====="
grep -a -m 40 -E 'susfs_ih|sus_path:|inline hook' /data/local/tmp/k.txt
echo
echo "===== module lines (last 40) ====="
grep -a -E 'susfs_ih|sus_path:' /data/local/tmp/k.txt | tail -40
echo
echo "===== last 300 KB, fault-looking lines ====="
tail -c 300000 /data/local/tmp/k.txt | grep -a -E 'pc :|lr :|Call trace|Unable to handle|Kernel panic|Internal error|Oops|BUG:|WARNING:|serror|RIP' | tail -50
echo
echo "===== last 3 KB raw ====="
tail -c 3000 /data/local/tmp/k.txt
