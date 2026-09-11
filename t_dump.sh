#!/system/bin/sh
# Pull the newest kernel minidump apart and print the parts that matter.
GZ=$(ls -t /mnt/vendor/oplusreserve/media/log/minidump/SYSTEM_LAST_KMSG@*.gz 2>/dev/null | head -1)
echo "dump: $GZ"
zcat "$GZ" > /data/local/tmp/k.txt 2>/dev/null
echo "size: $(wc -c < /data/local/tmp/k.txt)"
echo
echo "===== pc / panic / fault ====="
grep -a -n -E 'Unable to handle|Kernel panic|Internal error|BUG:|WARNING:|Call trace|pc :|lr :|PC is at|Bad mode|esr |synchronous exception' /data/local/tmp/k.txt | tail -40
echo
echo "===== our module ====="
grep -a -n -E 'susfs_ih|sus_path|inline hook' /data/local/tmp/k.txt | tail -40
echo
echo "===== getname / openat context ====="
grep -a -n -E 'getname|openat|filename' /data/local/tmp/k.txt | tail -30
echo
echo "===== tail ====="
tail -c 4000 /data/local/tmp/k.txt
