#!/system/bin/sh
# usage: t_ln.sh <target> <link>
# The operation that crashed the kernel: linkat() passes getname()'s result to
# filename_lookup() without checking it, and for a hidden path getname() returns
# ERR_PTR(-ENOENT).
ln "$1" "$2" 2>&1
echo "ln rc=$?"
cat "$2" 2>&1
echo "cat rc=$?"
