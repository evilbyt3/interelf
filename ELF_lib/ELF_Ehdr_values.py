dict_magic = {
   "7f 45 4c 46" : "7f 45 4c 46 ( Confirmed ELF file )"
}


dict_class = {
    "0x0" : "Invalid",
    "0x1" : "32-bit",
    "0x2" : "64-bit"
}


dict_endian = {
    "0x0" : "Invalid",
    "0x1" : "Little endian",
    "0x2" : "Big endian"
}


dict_version = {
    "0x1" : "Version 1 ( current version )"
}


dict_osabi = {
    "0x0"  : "System V",
    "0x1"  : "HP-UX",
    "0x2"  : "NetBSD",
    "0x3"  : "Linux",
    "0x4"  : "GNU Hard",
    "0x6"  : "Sun Solaris",
    "0x7"  : "IBM AIX",
    "0x8"  : "SGI Irix",
    "0x9"  : "FreeBSD",
    "0xa"  : "Compaq TRU64 UNIX",
    "0xb"  : "Novell Modesto",
    "0xc"  : "OpenBSD",
    "0xd"  : "OpenVMS",
    "0xe"  : "ARM EABI",
    "0xf"  : "ARM",
    "0x10"  : "Fenix OS",
    "0x11"  : "CloudABI"
}

dict_type = {
    "0x0"    : "ET_NONE    ( No file type )",
    "0x1"    : "ET_REL     ( Relocatable file )",
    "0x2"    : "ET_EXEC    ( Executable file )",
    "0x3"    : "ET_DYN     ( Shared object file )",
    "0x4"    : "ET_CORE    ( Core file )",
    "0xff00"  : "ET_LOPROC ( Processor-specific )",
    "0xffff"  : "ET_HIPROC ( Processor-specific )",
}

dict_machine = {
    "0x0" : "No machine ",
    "0x2" : "AT&T WE 32100 ",
    "0x3" : "x86",
    "0x8" : "MIPS",
    "0x14" : "PowerPC",
    "0x16" : "S390",
    "0x28" : "ARM",
    "0x2a" : "SuperH",
    "0x32" : "IA-64",
    "0x3e" : "Advanced Micro Devices x86-64",
    "0xb7" : "AArch64",
    "0xf3" : "RISC-V"
}
