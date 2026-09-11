#!/system/bin/sh
# usage: t_vma.sh <binary>   -- run it so its own /proc/self/maps shows the
# binary's path, which is rendered through d_path (the reverse-disguise surface).
"$@" -c 'grep -c "" /proc/self/maps'
"$@" -c 'grep -o "/data/local/tmp/dac_probe/[a-z_]*" /proc/self/maps | sort -u'
