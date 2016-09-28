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


        08:38:53 emdel -> python kfinder.py /home/emdel/Downloads/fmem_1.6-0/vm-ksfinder-fmem.raw init_task
        ...
        ...
        Page: b8349000
                 - ei_class: 64bit format
                 - ABI: System V
                 - e_type: shared
                 - e_machine x86_64
        Page: b9d77000
                 - ei_class: 64bit format
                 - ABI: System V
                 - e_type: relocatable
                 - e_machine x86_64

        :: Architecture identified: x86_64
        :: init_task found at offset: 0x1b8243f
        :: __ksymtab_strings found at offset: 0x1b82436
        :: Symbol init_task found at offset: 0x01b82436
        :: Symbol Virtual Address: 0xffffffff81b82436
        :: Packing the symbol_va
        :: __ksymtab offset guess: 0x01a8243c
        :: symbol_va packed found at 0x01b5aa40
        :: init_task at 0xffffffff81c1d4e0


Old example - x86_32 bit only (missing x86_64 support and the check to identify
the architecture):

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


=== LIMITATIONS ===

It has been tested on very few memory dumps.
I used 'fmem' to dump the memory.
I tried with 'Lime' in the raw format, but 
there are some offset issues. Contact me if 
you want to discuss about it.


Happy hacking,


emdel
