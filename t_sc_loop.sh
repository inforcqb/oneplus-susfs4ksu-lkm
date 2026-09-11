#!/system/bin/sh
# _LOOP semantics: register a path that does not exist yet, create it later, and
# check that it ends up hidden.
#
#   CMD_SUSFS_ADD_SUS_PATH_LOOP = 0x55553
#   payload = struct st_susfs_sus_path { char target_pathname[256]; int err; }
K=/data/local/tmp/susfs.ko
SC=/data/local/tmp/susfs_sc
D=/data/local/tmp/dac_probe
T=$D/loopme
HL=/sys/module/susfs_guard_lkm/parameters/hide_list
PAYLOAD=2f646174612f6c6f63616c2f746d702f6461635f70726f62652f6c6f6f706d65000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

rmmod susfs_guard_lkm 2>/dev/null
rm -rf $D
mkdir -p $D
echo "target exists before registration? $([ -e $T ] && echo yes || echo no)"

ksud insmod $K
echo "insmod rc=$?"
dmesg -c >/dev/null 2>&1

echo
echo "== register it while it does NOT exist =="
$SC 0x55553 $PAYLOAD
echo "client rc=$?"
dmesg | grep -E 'sus_path' | tail -4
echo "--- hide_list ---"
head -4 $HL

echo
echo "== create it now =="
printf 'secret\n' > $T
chmod 644 $T
echo "app cat right away : $(su 10123 -c "cat $T" 2>&1)"
sleep 4
echo "--- hide_list after ~4s ---"
head -4 $HL

echo
echo "== app vs root =="
echo "app  cat : $(su 10123 -c "cat $T" 2>&1)"
echo "app  ls  : $(su 10123 -c "ls $D" 2>&1)"
echo "app  stat: $(su 10123 -c "ls -l $T" 2>&1)"
echo "root cat : $(cat $T 2>&1)"
echo "root ls  : $(ls $D 2>&1)"

echo
echo "== a second, still-missing path stays pending and hides nothing =="
echo "pending counter: $(grep pending $HL)"

echo
echo "== rmmod =="
rmmod susfs_guard_lkm
echo "rmmod rc=$?"
echo "app cat after rmmod: $(su 10123 -c "cat $T" 2>&1)"
dmesg | grep -iE 'BUG:|WARNING:|Call trace|CFI failure' | tail -4
echo "### done"
