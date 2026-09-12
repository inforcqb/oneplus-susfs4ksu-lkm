#!/system/bin/sh
grep -E 'process_vm_rw|pin_user_pages|gup_longterm|get_user_pages|gup_remote' /proc/kallsyms
echo "=== count all kallsyms: $(wc -l < /proc/kallsyms)"
