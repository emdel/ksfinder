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


import mmap, sys, struct, os, string
from collections import OrderedDict


PAGE_SIZE = 4096
ELF_MAGIC = 0x7F454C46
x64 = 0
x86 = 0
is_x86 = False
is_x64 = False
THRESHOLD = 20

ei_class_table = {
0x01: "32bit format",
0x02: "64bit format"
}

ei_osabi_table = {
0x00: "System V",
0x01: "HP-UX",
0x02: "NetBSD",
0x03: "Linix",
0x06: "Solaris",
0x07: "AIX",
0x08: "IRIX",
0x09: "FreeBSD",
0x0C: "OpenBSD",
0x0D: "OpenVMS",
0x0E: "NonStop Kernel",
0x0F: "AROS",
0x10: "Fenix OS",
0x11: "CloudABI",
0x53: "Sortix"
}

e_type_table = {
0x01: "relocatable",
0x02: "executable",
0x03: "shared",
0x04: "core"
}

e_machine_table = {
0x00: "No specific instruction set",
0x02: "SPARC",
0x03: "x86",
0x08: "MIPS",
0x14: "PowerPC",
0x28: "ARM",
0x2A: "SuperH",
0x32: "IA-64",
0x3E: "x86_64",
0xB7: "AArch64"
}

def lookup(m, ksymtab_pa, symbol_addr_raw):
    for addr in xrange(ksymtab_pa, 0x3000000, 0x04):
        m.seek(addr)
        if is_x86:
            raw = m.read(4)
        elif is_x64:
            raw = m.read(8)
        if raw == symbol_addr_raw:
            if is_x86:
                symbol_offset = (addr - 4)
            elif is_x64:
                symbol_offset = (addr - 8)
            if len(sys.argv) > 2:
                print ":: symbol_va packed found at 0x%08x" % symbol_offset
            m.seek(symbol_offset)
            if is_x86:
                addr_raw = m.read(4)
                symbol_addr = struct.unpack("<L", addr_raw)[0]
            elif is_x64:
                addr_raw = m.read(8)
                symbol_addr = struct.unpack("<Q", addr_raw)[0]
            return symbol_addr
    return None


def find_ksymtab_strings(m, start_addr, end_addr):
    candidate_value = ""
    ksymtab_strings = None
    for page in range(start_addr, end_addr, PAGE_SIZE):
        #print "\tPage: %x" % page
        for addr in range(page, page + PAGE_SIZE - 1, 0x01):
            m.seek(addr)
            raw = m.read(1)
            if raw != "\x00": 
                candidate_value += raw
                continue
            if "init_task" in candidate_value:
                ksymtab_strings = addr
                print ":: init_task found at offset: 0x%x" % addr
                print ":: __ksymtab_strings found at offset: 0x%x" % (addr - len("init_task"))
                return ksymtab_strings
            candidate_value = ""
    return None

def main():
    global x64, x86, is_x64, is_x86
    if len(sys.argv) < 2:
        print "[-] Usage: %s %s %s" % (sys.argv[0], "<memory_dump>", "[symbol]") 
        sys.exit(1)

    # Open the memory dump
    try:
        fd = os.open(sys.argv[1], os.O_RDONLY)
    except:
        print "[-] Error: fopen.\n"
        sys.exit(1)

    # mmap the dump
    try:
        m = mmap.mmap(fd, 0, mmap.MAP_PRIVATE, mmap.PROT_READ)
    except:
        print "[-] Error: memmap.\n"
        sys.exit(1)

    # Scan for ELF files and get the architecture
    print "Size: " , m.size()
    for page in range(0, m.size(), PAGE_SIZE):
        m.seek(page)
        raw = m.read(4)
        value = struct.unpack(">L", raw)[0]
        if value == ELF_MAGIC:
            print "Page: %x" % page
            raw = m.read(1)
            ei_class = struct.unpack("<B", raw)[0]
            try:
                print "\t - ei_class: %s" % ei_class_table[ei_class]
            except KeyError:
                continue
            m.seek(page + 0x07)
            raw = m.read(1)
            ei_osabi = struct.unpack("<B", raw)[0]
            try:
                print "\t - ABI: %s" % ei_osabi_table[ei_osabi]
            except KeyError:
                continue
            m.seek(page + 0x10)
            raw = m.read(2)
            e_type = struct.unpack("<H", raw)[0]
            try:
                print "\t - e_type: %s" % e_type_table[e_type]
            except KeyError:
                continue
            m.seek(page + 0x12)
            raw = m.read(2)
            e_machine = struct.unpack("<H", raw)[0]
            try:
                machine = e_machine_table[e_machine]
                print "\t - e_machine %s" % machine
                if machine == "x86_64":
                    x64 += 1
                elif machine == "x86":
                    x86 += 1
            except KeyError:
                continue
    if x64 > THRESHOLD and x86 > THRESHOLD:
        print "Something went wrong."
        os.close(fd)
        m.close()
        sys.exit(1)
    elif x64 > THRESHOLD:
        print "\n:: Architecture identified: x86_64"
        is_x64 = True
    elif x86 > THRESHOLD:
        print "\n:: Architecture identified: x86"
        is_x86 = True

    if is_x86:
        ksymtab_strings = find_ksymtab_strings(m, 0x01000000, 0x02000000)
    elif is_x64:
        ksymtab_strings = find_ksymtab_strings(m, 0x100000, 0x03000000)

    if not ksymtab_strings:
        print ":: __ksymtab_strings not found..."
        os.close(fd)
        m.close()
        sys.exit(1)

    symbol_names = OrderedDict()

    # TODO: Make it modular 
    candidate_value = ""
    prev_addr = 0
    prev_val = ""
    for addr in range(ksymtab_strings - len("init_task"), 0x03000000, 0x01):
        m.seek(addr)
        raw = m.read(1)
        if raw != "\x00": 
            candidate_value += raw
            continue
        # Recursive mode. Build necessary data structures
        kaddr = addr - (len(candidate_value) + 1)
        if len(sys.argv) == 2:
            final_check = string.ascii_letters + "_" + string.digits
            if all(c in final_check for c in candidate_value) and len(candidate_value) >= 2:
                if len(symbol_names.keys()) == 0:
                    symbol_names[hex(kaddr).strip("L")] = candidate_value
                else:
                    if prev_addr in symbol_names.keys():
                        if hex(addr - (len(candidate_value) + 1) - (len(symbol_names[prev_addr]) + 1)).strip("L") in symbol_names.keys():
                            symbol_names[hex(kaddr).strip("L")] = candidate_value
        # Single lookup mode
        elif sys.argv[2] == candidate_value:
            symbol_pa = addr - len(sys.argv[2])
            print ":: Symbol %s found at offset: 0x%08x" % (sys.argv[2], symbol_pa)
            #print len(candidate_value), len(sys.argv[2])
            if is_x86:
                symbol_va = symbol_pa + 0xC0000000
            elif is_x64:
                symbol_va = symbol_pa + 0xFFFFFFFF80000000
            print ":: Symbol Virtual Address: 0x%08x" % symbol_va
            break
        prev_addr = hex(kaddr).strip("L")
        prev_val = candidate_value
        candidate_value = ""

    # Single lookup mode
    if len(sys.argv) > 2:
        print ":: Packing the symbol_va"
        if is_x86:
            symbol_addr_raw = struct.pack("<L", symbol_va)
        elif is_x64:
            symbol_addr_raw = struct.pack("<Q", symbol_va)
        ksymtab_pa = (ksymtab_strings - 0x100000) >> 2 << 2
        print ":: __ksymtab offset guess: 0x%08x" % ksymtab_pa
        symbol = lookup(m, ksymtab_pa, symbol_addr_raw)
        print ":: %s at 0x%08x" % (sys.argv[2], symbol)
    else:
        system_map = OrderedDict()
        print "[+] Retrived %d symbols" % len(symbol_names.keys())
        print symbol_names
        ksymtab_pa = (ksymtab_strings - 0x100000) >> 2 << 2
        for k, v in symbol_names.items():
            if is_x86:
                symbol_va = (int(k, 16) + 1) + 0xC0000000
                symbol_addr_raw = struct.pack("<L", symbol_va)
            elif is_x64:
                symbol_va = (int(k, 16) + 1) + 0xFFFFFFFF80000000
                symbol_addr_raw = struct.pack("<Q", symbol_va)
            #print ":: Looking up %s - %s" % (v, hex(symbol_va).strip("L"))
            symbol = lookup(m, ksymtab_pa, symbol_addr_raw)
            system_map[symbol] = v
        
        for k, v in system_map.items():
            print "%s %s %s" % (hex(k).strip("L")[2:], "?", v)

    os.close(fd)
    m.close()


main()
