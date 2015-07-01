#
# Simple POC to retrive kernel symbols from a 
# physical memory dump.
#
# Mariano Graziano - graziano@eurecom.fr
# 

# 
# References:
#   - https://github.com/0xAX/linux-insides/blob/master/Booting/linux-bootstrap-4.md
#   - Linux kernel source code
#   - https://github.com/psviderski/volatility-android/blob/master/volatility/plugins/linux/auto_ksymbol.py 
# 
#   The last link is basically the same idea/approach applied to Android. I discovered it
#   few days ago. Really cool work, it's a pity his thesis is not available in
#   english (only in russian).
#
# Thanks:
#    Andrew Case and Enrico Perla
#
#
# XXD Manual Debugging:
#
# cat System.map-3.2.0-23-generic-pae | grep -i dns_query
# c1574e30 T dns_query
# c17d0fc0 r __ksymtab_dns_query
# c17dc4ec r __kcrctab_dns_query
# c17fde42 r __kstrtab_dns_query
#
# 21:42:06 emdel -> xxd kernelexp.ram | grep -ni dns_query -A 1 -B 1
# 1450737-1622f00: 6174 6500 646e 735f 7265 736f 6c76 6572  ate.dns_resolver
# 1450738:1622f10: 2e64 6562 7567 0064 6e73 5f71 7565 7279  .debug.dns_query
# 1450739-1622f20: 0000 0000 0000 00c1 0000 00c1 db00 00c1  ................
#--
# 1572324-17fde30: 5f6e 6574 5f73 7973 6374 6c5f 7461 626c  _net_sysctl_tabl
# 1572325:17fde40: 6500 646e 735f 7175 6572 7900 6b6c 6973  e.dns_query.klis
# 1572326-17fde50: 745f 6e65 7874 006b 6c69 7374 5f69 7465  t_next.klist_ite
#
# c17fde42 --> 42de7fc1
#
# 21:44:25 emdel -> xxd kernelexp.ram | grep -ni "42de 7fc1"
# 1464144:16574f0: f0dd 7fc1 0cde 7fc1 28de 7fc1 42de 7fc1  ........(...B...
# 1560829:17d0fc0: [[304e 57c1]] 42de 7fc1 30e4 34c1 621c 7fc1  0NW.B...0.4.b...
#

import mmap, sys, struct, os

def main():
    if len(sys.argv) != 3:
        print "[-] Usage: %s %s %s" % (sys.argv[0], "<memory_dump>", "<symbol>")
        sys.exit(1)

    try:
        fd = os.open(sys.argv[1], os.O_RDONLY)
    except:
        print "[-] Error: fopen.\n"
        sys.exit(1)

    try:
        m = mmap.mmap(fd, 0, mmap.MAP_PRIVATE, mmap.PROT_READ)
    except:
        print "[-] Error: memmap.\n"
        sys.exit(1)

    #
    # This loop starts from 01000000 (the default address in which the vmlinux 
    # .text is loaded. We loop until 02000000 (no sense to go any further, 
    # I had a look at a couple of iomem outputs and it makes sense).
    # It looks like __ksymtab_strings starts always with 'init_task'.
    # 
    candidate_value = ""
    ksymtab_strings = None
    for addr in range(0x01000000, 0x02000000, 0x01):
        m.seek(addr)
        raw = m.read(1)
        if raw != "\x00": 
            candidate_value += raw
            continue
        if "init_task" in candidate_value:
            print ":: __ksymtab_strings found at offset: 0x%08x" % addr
            #print len(candidate_value), len(sys.argv[2])
            ksymtab_strings = addr
            break
        candidate_value = ""
   
    if not ksymtab_strings:
        print ":: __ksymtab_strings not found..."
        os.close(fd)
        m.close()
        sys.exit(1)

    # TODO: Recursive - Retrieve all symbols 
    candidate_value = ""
    for addr in range(ksymtab_strings - len("init_task"), 0x02000000, 0x01):
        m.seek(addr)
        raw = m.read(1)
        if raw != "\x00": 
            candidate_value += raw
            continue
        if sys.argv[2] == candidate_value:
            symbol_pa = addr - len(sys.argv[2])
            print ":: Symbol %s found at offset: 0x%08x" % (sys.argv[2], symbol_pa)
            #print len(candidate_value), len(sys.argv[2])
            symbol_va = symbol_pa + 0xC0000000
            print ":: Symbol Virtual Address: 0x%08x" % symbol_va
            break
        candidate_value = ""
    
    print ":: Packing the symbol_va"
    symbol_addr_raw = struct.pack("<L", symbol_va)

    ksymtab_pa = (ksymtab_strings - 0x100000) >> 2 << 2
    print ":: __ksymtab offset guess: 0x%08x" % ksymtab_pa
    for addr in range(ksymtab_pa, 0x02000000, 0x04):
        m.seek(addr)
        raw = m.read(4)
        if raw == symbol_addr_raw:
            symbol_offset = (addr - 4)
            print ":: symbol_va packed found at 0x%08x" % symbol_offset
            m.seek(symbol_offset)
            addr_raw = m.read(4)
            symbol_addr = struct.unpack("<L", addr_raw)[0]
            print ":: Result: %s at 0x%08x" % (sys.argv[2], symbol_addr)
            break

    os.close(fd)
    m.close()


main()
