=== USAGE ===

        emdel -> time python kfinder.py 
        [-] Usage: kfinder.py <memory_dump> [symbol]

symbol is not mandatory. In the case it is not provided, `kfinder` runs 
in recursive mode and carves out all the possible symbols.

=== HOW ===

This is possible by parsing the `__ksymtab_strings` and `__ksymtab` of 
the Linux kernel image (aka vmlinux). `kfinder` analyzes the physical 
memory dump, locates the kernel .text segment and from there the 
two interesting sections: `__ksymtab_strings` and `__ksymtab`.


=== EXAMPLES ===

        emdel -> time python kfinder.py kernelexp.ram init_task
        :: __ksymtab_strings found at offset: 0x017e172d
        :: Symbol init_task found at offset: 0x017e1724
        :: Symbol Virtual Address: 0xc17e1724
        :: Packing the symbol_va
        :: __ksymtab offset guess: 0x016e172c
        :: symbol_va packed found at 0x017d2060
        :: init_task at 0xc180b020

        real    0m3.813s
        user    0m3.632s
        sys     0m0.172s



        emdel -> cat System.map-3.2.0-23-generic-pae | grep -w init_task
        c180b020 D init_task


        emdel -> time python kfinder.py kernelexp.ram > carved_sysmap.log

        real    12m18.355s
        user    12m17.326s
        sys     0m0.372s


        emdel -> cat System.map-3.2.0-23-generic-pae | wc -l
        69247


        emdel -> cat carved_sysmap.log | wc -l
        6334


        emdel -> head carved_sysmap.log 
        :: __ksymtab_strings found at offset: 0x017e172d
        [+] Retrived 6333 symbols
        c180b020 ? init_task
        c180c460 ? loops_per_jiffy
        c193e004 ? reset_devices
        c18742c0 ? system_state
        c180c5c0 ? init_uts_ns
        c1003580 ? populate_rootfs_wait
        c17fdf20 ? x86_hyper_xen_hvm
        c1003f70 ? xen_hvm_need_lapic


=== TODO AND LIMITATIONS ===

It supports only x86-32 memory dumps.
It has been tested on very few memory dump.
It is a simple POC :-)
In the future, I will write a Volatility plugin 
and provide x86-64 support.


Happy hacking,


emdel
