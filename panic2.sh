#!/system/bin/sh
D=/mnt/vendor/oplusreserve/media/log/minidump
F=$(ls -t $D/SYSTEM_LAST_KMSG*.gz 2>/dev/null | head -1)
echo "FILE=$(basename $F)"
echo "=== panic line ==="
zcat "$F" 2>/dev/null | grep -a -E "Kernel panic|CFI failure" | head -5
echo
echo "=== pc/lr + call trace around panic ==="
zcat "$F" 2>/dev/null | grep -a -n -E "Kernel panic|CFI failure|pc : |lr : " | head -20
echo
echo "=== any CFI lines ==="
zcat "$F" 2>/dev/null | grep -a -i -E "cfi" | head -15
