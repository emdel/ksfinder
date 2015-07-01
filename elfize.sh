for vmlinuz in `ls $1/vmlinuz-*`
do
    echo ":: $vmlinuz"
    off=`sudo od -A d -t x1 $vmlinuz | grep '1f 8b 08 00' | cut -d " " -f1`
    vmoffset=`echo "$off + 12" | bc`
    echo -ne "\t - offset: $vmoffset\n"
    output="$1/vmlinux-`basename $vmlinuz`"
    dd if=$vmlinuz bs=1 skip=$vmoffset | zcat > $1"/"$output
    readelf -p __ksymtab_strings $output
    echo
done

