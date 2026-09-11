#!/system/bin/sh
# What exactly faulted when the hook was installed from module_init?
exec > /data/local/tmp/lk8_out.txt 2>&1

DIR=/mnt/vendor/oplusreserve/media/log/minidump
F=$DIR/SYSTEM_LAST_KMSG@4666dec463df68d39a0f676a70e644a1@PJA110_11.H.11_3110_202601292238@2026_09_11_20_22_07.dat.gz
[ -f "$F" ] || F=$(ls -t $DIR/SYSTEM_LAST_KMSG* 2>/dev/null | head -1)
echo "dump: $F"

cp "$F" /data/local/tmp/lk8.gz
chmod 644 /data/local/tmp/lk8.gz
zcat /data/local/tmp/lk8.gz > /data/local/tmp/lk8.txt
echo "size: $(wc -c < /data/local/tmp/lk8.txt)"

echo "=== our lines ==="
strings /data/local/tmp/lk8.txt | grep -a -e susfs_ih -e "sus_path" | tail -20

echo "=== fault ==="
strings /data/local/tmp/lk8.txt | grep -a -e "Kernel panic" -e "pc :" -e "lr :" -e "Call trace" -e "susfs_ih_stub" -e "sus_path_match" -e "Unable to handle" -e "BTI" -e "Internal error" -e "CFI" | tail -35

echo "=== end ==="
