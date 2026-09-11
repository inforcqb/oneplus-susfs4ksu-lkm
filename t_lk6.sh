#!/system/bin/sh
# Where did the main module's inline-hook build die?
exec > /data/local/tmp/lk6_out.txt 2>&1

DIR=/mnt/vendor/oplusreserve/media/log/minidump
F=$DIR/SYSTEM_LAST_KMSG@8444040c30745897d25e4ed9225cf829@PJA110_11.H.11_3110_202601292238@2026_09_11_18_32_09.dat.gz

if [ ! -f "$F" ]; then
	echo "not found, taking the newest"
	F=$(ls -t $DIR/SYSTEM_LAST_KMSG* 2>/dev/null | head -1)
fi
echo "dump: $F"

cp "$F" /data/local/tmp/lk6.gz
chmod 644 /data/local/tmp/lk6.gz
zcat /data/local/tmp/lk6.gz > /data/local/tmp/lk6.txt
echo "size: $(wc -c < /data/local/tmp/lk6.txt)"

echo "=== our module lines ==="
strings /data/local/tmp/lk6.txt | grep -a -e susfs_ih -e "sus_path" -e ih_hook | tail -30

echo "=== panic / fault ==="
strings /data/local/tmp/lk6.txt | grep -a -e "Kernel panic" -e BTI -e "Unable to handle" -e "Internal error" -e "pc :" -e "lr :" -e "susfs_guard_lkm" | tail -25

echo "=== end ==="
