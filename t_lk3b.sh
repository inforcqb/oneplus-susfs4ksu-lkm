#!/system/bin/sh
# Analyse the 17:29 dump that was already copied out (lk3.gz), falling back to
# copying it again if needed.
exec > /data/local/tmp/lk3b_out.txt 2>&1

SRC=/mnt/vendor/oplusreserve/media/log/minidump/SYSTEM_LAST_KMSG@87dfeca1dfabf8b7ac4c88a3a96726ef@PJA110_11.H.11_3110_202601292238@2026_09_11_17_29_28.dat.gz

if [ ! -s /data/local/tmp/lk3.gz ]; then
	cp "$SRC" /data/local/tmp/lk3.gz
fi
chmod 644 /data/local/tmp/lk3.gz
ls -l /data/local/tmp/lk3.gz

zcat /data/local/tmp/lk3.gz > /data/local/tmp/lk3.txt
echo "size: $(wc -c < /data/local/tmp/lk3.txt)"

echo "=== our module lines ==="
strings /data/local/tmp/lk3.txt | grep -a -e ih_hook -e ih_selftest | tail -25

echo "=== panic / fault ==="
strings /data/local/tmp/lk3.txt | grep -a -e "Kernel panic" -e "BTI" -e "Unable to handle" -e "Internal error" -e "Oops" -e "pc :" -e "lr :" -e "init_module" -e "CFI" | tail -35

echo "=== end ==="
