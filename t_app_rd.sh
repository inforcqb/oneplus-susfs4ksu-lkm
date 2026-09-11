#!/system/bin/sh
# usage: t_app_rd.sh <file>
# Print what readlink(/proc/self/fd/N) says about an fd we hold, plus the raw
# /proc/self/fd listing for comparison.  This is the reverse-disguise surface.
exec 3<"$1" || { echo "open failed: $1"; exit 1; }
echo "readlink: $(readlink /proc/self/fd/3 2>&1)"
echo "fd listing: $(ls -l /proc/self/fd/3 2>&1 | sed 's/.*-> //')"
