#!/system/bin/sh
D=/mnt/vendor/oplusreserve/media/log/minidump
F=$(ls -t $D/SYSTEM_LAST_KMSG*.gz 2>/dev/null | head -1)
echo "FILE=$F"
ls -l "$F" 2>&1
echo
echo "=== PANIC MARKERS ==="
zcat "$F" 2>/dev/null | grep -n -E "Kernel panic|Unable to handle|Internal error|Oops|BUG:|pc :|lr :|Call trace|selinux_inode|susfs|lsm_hook" | head -50
echo
echo "=== TAIL 130 ==="
zcat "$F" 2>/dev/null | tail -130
