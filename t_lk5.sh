#!/system/bin/sh
# Analyse the newest dump: where exactly did the third attempt die?
exec > /data/local/tmp/lk5_out.txt 2>&1

DIR=/mnt/vendor/oplusreserve/media/log/minidump
F=$DIR/SYSTEM_LAST_KMSG@75c0a1b6185e0e7b310e3fe35ed9b38f@PJA110_11.H.11_3110_202601292238@2026_09_11_17_34_52.dat.gz

if [ ! -f "$F" ]; then
	echo "not found, using newest:"
	F=$(ls -t $DIR/SYSTEM_LAST_KMSG* 2>/dev/null | head -1)
fi
echo "dump: $F"

cp "$F" /data/local/tmp/lk5.gz
chmod 644 /data/local/tmp/lk5.gz
zcat /data/local/tmp/lk5.gz > /data/local/tmp/lk5.txt
echo "size: $(wc -c < /data/local/tmp/lk5.txt)"

echo "=== our module lines ==="
strings /data/local/tmp/lk5.txt | grep -a -e ih_hook -e ih_selftest | tail -25

echo "=== panic / fault ==="
strings /data/local/tmp/lk5.txt | grep -a -e "Kernel panic" -e "BTI" -e "Unable to handle" -e "Internal error" -e "Oops" -e "pc :" -e "lr :" -e "init_module" -e "branch target" | tail -40

echo "=== end ==="
