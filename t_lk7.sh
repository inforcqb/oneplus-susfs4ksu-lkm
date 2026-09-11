#!/system/bin/sh
# Where did the hang happen?  A wedged box that eventually trips the watchdog
# leaves the stuck task's stack in the dump.
exec > /data/local/tmp/lk7_out.txt 2>&1

DIR=/mnt/vendor/oplusreserve/media/log/minidump
F=$DIR/SYSTEM_LAST_KMSG@bbec99b971338885ff7cf48c9f42f467@PJA110_11.H.11_3110_202601292238@2026_09_11_20_13_03.dat.gz
[ -f "$F" ] || F=$(ls -t $DIR/SYSTEM_LAST_KMSG* 2>/dev/null | head -1)
echo "dump: $F"

cp "$F" /data/local/tmp/lk7.gz
chmod 644 /data/local/tmp/lk7.gz
zcat /data/local/tmp/lk7.gz > /data/local/tmp/lk7.txt
echo "size: $(wc -c < /data/local/tmp/lk7.txt)"

echo "=== our module lines ==="
strings /data/local/tmp/lk7.txt | grep -a -e susfs_ih -e "sus_path" -e ih_hook | tail -25

echo "=== hang / panic ==="
strings /data/local/tmp/lk7.txt | grep -a -e "hung task" -e "blocked for more than" -e "Kernel panic" -e "watchdog" -e "Call trace" -e "susfs_ih_stub" -e "sus_path_match" -e "rcu_note" | tail -40

echo "=== end ==="
