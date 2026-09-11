#!/system/bin/sh
# Which ksu_/susfs_ symbols survive hide_syms while the module is loaded?
K=/data/local/tmp/susfs.ko

rmmod susfs_guard_lkm 2>/dev/null
echo "== with no module =="
echo "  total matches: $(grep -cE 'susfs_|ksu_' /proc/kallsyms)"

ksud insmod $K
sleep 1
echo "== with the module loaded =="
echo "  total matches: $(grep -cE 'susfs_|ksu_' /proc/kallsyms)"
echo "  --- the survivors ---"
grep -E 'susfs_|ksu_' /proc/kallsyms
echo "  --- our own module name ---"
echo "  susfs_guard_lkm lines: $(grep -c 'susfs_guard_lkm' /proc/kallsyms)"
echo "  kallsyms_op.show == kprobe addr ? $(dmesg | grep -o 'kallsyms_op.show=.*' | tail -1)"

rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "### done"
