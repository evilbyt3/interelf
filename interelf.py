import binascii
import re
import argparse
import sys
from ELF_lib.ELF_Ehdr import Elf_Ehdr
from ELF_lib.ELF_Phdr import Elf_Phdr
from ELF_lib.ELF_Shdr import Elf_Shdr


# (offset, size)
x86_ELFHDR = [(0x18, 4), (0x1c, 4), (0x20, 4), (0x24, 4), (0x28, 2), (0x2a, 2), (0x2c, 2), (0x2e, 2), (0x30, 2), (0x32, 2)]
x64_ELFHDR = [(0x18, 8), (0x20, 8), (0x28, 8), (0x30, 4), (0x34, 2), (0x36, 2), (0x38, 2), (0x3a, 2), (0x3c, 2), (0x3e, 2)]


def get_bytes(stream, size, offset, flag=None):
    stream.seek(offset)
    byte_stream = stream.read(size)
    bytess = [c.encode('hex') for c in byte_stream]
    if flag:
    	return  " ".join(bytess)
    else:
    	return hex(int("".join(bytess), 16))


def get_sensitive_bytes(stream, size, offset, endian, flag=None):
    stream.seek(offset)
    byte_stream = stream.read(size).strip(b'\x00')
    if endian == '0x1':		# little endian
    	bytess = [c.encode('hex') for c in reversed(byte_stream)]
    else:					# big endian
    	bytess = [c.encode('hex') for c in byte_stream]
    try:
    	if flag:
    		return " ".join(bytess)
    	else:
    		return hex(int("".join(bytess), 16))
    except:
    	return "0x0"


def build_specific_elfhdr(ehdr, fd):
	if ehdr.e_ident_class == "0x1":	# 32-bit binary
		ehdr.e_entry  	 = get_sensitive_bytes(fd, x86_ELFHDR[0][1], x86_ELFHDR[0][0], ehdr.e_ident_endian)
		ehdr.e_phoff  	 = get_sensitive_bytes(fd, x86_ELFHDR[1][1], x86_ELFHDR[1][0], ehdr.e_ident_endian)
		ehdr.e_shoff  	 = get_sensitive_bytes(fd, x86_ELFHDR[2][1], x86_ELFHDR[2][0], ehdr.e_ident_endian)
		ehdr.e_flags  	 = get_sensitive_bytes(fd, x86_ELFHDR[3][1], x86_ELFHDR[3][0], ehdr.e_ident_endian)
		ehdr.e_ehsize 	 = get_sensitive_bytes(fd, x86_ELFHDR[4][1], x86_ELFHDR[4][0], ehdr.e_ident_endian)
		ehdr.e_phentsize = get_sensitive_bytes(fd, x86_ELFHDR[5][1], x86_ELFHDR[5][0], ehdr.e_ident_endian)
		ehdr.e_phnum	 = get_sensitive_bytes(fd, x86_ELFHDR[6][1], x86_ELFHDR[6][0], ehdr.e_ident_endian)
		ehdr.e_shentsize = get_sensitive_bytes(fd, x86_ELFHDR[7][1], x86_ELFHDR[7][0], ehdr.e_ident_endian)
		ehdr.e_shnum 	 = get_sensitive_bytes(fd, x86_ELFHDR[8][1], x86_ELFHDR[8][0], ehdr.e_ident_endian)
		ehdr.e_shstrndx  = get_sensitive_bytes(fd, x86_ELFHDR[9][1], x86_ELFHDR[9][0], ehdr.e_ident_endian)
	else:							# 64-bit binary
		ehdr.e_entry  	 = get_sensitive_bytes(fd, x64_ELFHDR[0][1], x64_ELFHDR[0][0], ehdr.e_ident_endian)
		ehdr.e_phoff  	 = get_sensitive_bytes(fd, x64_ELFHDR[1][1], x64_ELFHDR[1][0], ehdr.e_ident_endian)
		ehdr.e_shoff  	 = get_sensitive_bytes(fd, x64_ELFHDR[2][1], x64_ELFHDR[2][0], ehdr.e_ident_endian)
		ehdr.e_flags  	 = get_sensitive_bytes(fd, x64_ELFHDR[3][1], x64_ELFHDR[3][0], ehdr.e_ident_endian)
		ehdr.e_ehsize 	 = get_sensitive_bytes(fd, x64_ELFHDR[4][1], x64_ELFHDR[4][0], ehdr.e_ident_endian)
		ehdr.e_phentsize = get_sensitive_bytes(fd, x64_ELFHDR[5][1], x64_ELFHDR[5][0], ehdr.e_ident_endian)
		ehdr.e_phnum	 = get_sensitive_bytes(fd, x64_ELFHDR[6][1], x64_ELFHDR[6][0], ehdr.e_ident_endian)
		ehdr.e_shentsize = get_sensitive_bytes(fd, x64_ELFHDR[7][1], x64_ELFHDR[7][0], ehdr.e_ident_endian)
		ehdr.e_shnum 	 = get_sensitive_bytes(fd, x64_ELFHDR[8][1], x64_ELFHDR[8][0], ehdr.e_ident_endian)
		ehdr.e_shstrndx  = get_sensitive_bytes(fd, x64_ELFHDR[9][1], x64_ELFHDR[9][0], ehdr.e_ident_endian)


def build_ehdr(filename):
	with open(filename, "rb") as fd:
		ehdr = Elf_Ehdr()		
		ehdr.e_ident_magic   = get_bytes(fd, 4, 0x0, 1)
		ehdr.e_ident_class   = get_bytes(fd, 1, 0x4)
		ehdr.e_ident_endian  = get_bytes(fd, 1, 0x5)
		ehdr.e_ident_version = get_bytes(fd, 1, 0x6)
		ehdr.e_ident_osabi   = get_bytes(fd, 1, 0x7)
		ehdr.e_ident_pad     = get_bytes(fd, 8, 0x8, 1)
		ehdr.e_type			 = get_sensitive_bytes(fd, 2, 0x10, ehdr.e_ident_endian)
		ehdr.e_machine		 = get_sensitive_bytes(fd, 2, 0x12, ehdr.e_ident_endian)
		ehdr.e_version 		 = get_sensitive_bytes(fd, 2, 0x14, ehdr.e_ident_endian)
		build_specific_elfhdr(ehdr, fd)
	return ehdr


def build_phdr(filename, ehdr):
	total_phdr  = list()
	e_phoff		= int(ehdr.e_phoff, 16)
	e_phnum		= int(ehdr.e_phnum, 16)
	e_phentsize = int(ehdr.e_phentsize, 16)
	with open(filename, "rb") as fd:
		for i in range(0, e_phnum):
			phdr = Elf_Phdr()
			arch_specific_values = modify_phdr_and_arch(e_phoff, i, ehdr.e_ident_class, e_phentsize)
			phdr.p_type		= get_sensitive_bytes(fd, arch_specific_values[0][1], arch_specific_values[0][0], ehdr.e_ident_endian)
			phdr.p_flags	= get_sensitive_bytes(fd, arch_specific_values[1][1], arch_specific_values[1][0], ehdr.e_ident_endian)
			phdr.p_offset	= get_sensitive_bytes(fd, arch_specific_values[2][1], arch_specific_values[2][0], ehdr.e_ident_endian)
			phdr.p_vaddr	= get_sensitive_bytes(fd, arch_specific_values[3][1], arch_specific_values[3][0], ehdr.e_ident_endian)
			phdr.p_paddr	= get_sensitive_bytes(fd, arch_specific_values[4][1], arch_specific_values[4][0], ehdr.e_ident_endian)
			phdr.p_filesz	= get_sensitive_bytes(fd, arch_specific_values[5][1], arch_specific_values[5][0], ehdr.e_ident_endian)
			phdr.p_memsz	= get_sensitive_bytes(fd, arch_specific_values[6][1], arch_specific_values[6][0], ehdr.e_ident_endian)
			phdr.p_align	= get_sensitive_bytes(fd, arch_specific_values[7][1], arch_specific_values[7][0], ehdr.e_ident_endian)
			total_phdr.append(phdr)
	return total_phdr
				


def build_shdr(filename, ehdr):
	total_shdr	= list()
	shstrtab	= ""
	e_shoff 	= int(ehdr.e_shoff, 16)
	e_shnum 	= int(ehdr.e_shnum, 16)
	e_shentsize = int(ehdr.e_shentsize, 16)
	with open(filename, 'rb') as fd:
		for i in range(0, e_shnum):
			shdr = Elf_Shdr()
			arch_specific_values = modify_shdr_and_arch(e_shoff, i, ehdr.e_ident_class, e_shentsize)
			shdr.sh_name		= get_sensitive_bytes(fd, arch_specific_values[0][1], arch_specific_values[0][0], ehdr.e_ident_endian)
			shdr.sh_type		= get_sensitive_bytes(fd, arch_specific_values[1][1], arch_specific_values[1][0], ehdr.e_ident_endian)
			shdr.sh_flags		= get_sensitive_bytes(fd, arch_specific_values[2][1], arch_specific_values[2][0], ehdr.e_ident_endian)
			shdr.sh_addr		= get_sensitive_bytes(fd, arch_specific_values[3][1], arch_specific_values[3][0], ehdr.e_ident_endian)
			shdr.sh_offset		= get_sensitive_bytes(fd, arch_specific_values[4][1], arch_specific_values[4][0], ehdr.e_ident_endian)
			shdr.sh_size		= get_sensitive_bytes(fd, arch_specific_values[5][1], arch_specific_values[5][0], ehdr.e_ident_endian)
			shdr.sh_link		= get_sensitive_bytes(fd, arch_specific_values[6][1], arch_specific_values[6][0], ehdr.e_ident_endian)
			shdr.sh_info		= get_sensitive_bytes(fd, arch_specific_values[7][1], arch_specific_values[7][0], ehdr.e_ident_endian)
			shdr.sh_addralign	= get_sensitive_bytes(fd, arch_specific_values[8][1], arch_specific_values[8][0], ehdr.e_ident_endian)
			shdr.sh_entsize	  	= get_sensitive_bytes(fd, arch_specific_values[9][1], arch_specific_values[9][0], ehdr.e_ident_endian)
			total_shdr.append(shdr)
			if shdr.sh_type == "0x3":
				shstrtab = shdr.sh_offset
		get_section_name(fd, total_shdr, shstrtab)
	return total_shdr


def get_section_name(file, total_shdr, shstrtab):
	name = list()
	for shdr in total_shdr:
		string_pos = int(shstrtab, 16) + int(shdr.sh_name, 16)  
		file.seek(string_pos)
		data = "".join(iter(lambda : file.read(1), '\x00'))
		shdr.sh_name = data


def modify_shdr_and_arch(shdr_offset, number, arch, shdr_size):
	x86_SHDR   = [[0x00, 4], [0x04, 4], [0x08, 4], [0x0c, 4], [0x10, 4], [0x14, 4], [0x18, 4], [0x1c, 4], [0x20, 4], [0x24, 4]]
	x64_SHDR   = [[0x00, 4], [0x04, 4], [0x08, 8], [0x10, 8], [0x18, 8], [0x20, 8], [0x28, 4], [0x2c, 4], [0x30, 8], [0x38, 8]]
	if arch == "32-bit":
		arch_type = x84_SHDR
	else:
		arch_type = x64_SHDR
	for arr in arch_type:
		arr[0] += shdr_offset + shdr_size * number
	return arch_type



def modify_phdr_and_arch(phdr_offset, number, arch, phdr_size):
	x86_PHDR   = [[0x00, 4], [0x04, 4], [0x08, 4], [0x0c, 4], [0x10, 4], [0x14, 4], [0x18, 4], [0x1c, 4]] 
	x64_PHDR   = [[0x00, 4], [0x04, 4], [0x08, 8], [0x10, 8], [0x18, 8], [0x20, 8], [0x28, 8], [0x30, 8]]
	if arch == "64-bit":
		arch_type = x64_PHDR
	else:
		arch_type = x86_PHDR
	for arr in arch_type:
		arr[0] += phdr_offset + phdr_size * number
	return arch_type




def main():
        parser = argparse.ArgumentParser()
        parser.add_argument('filename'		, help='Filename to inject')
        parser.add_argument('-s', '--sections'  , action="store_true", help='Display only the Section Headers')
        parser.add_argument('-p', '--programs'  , action="store_true", help='Display only the Program Headers')
        parser.add_argument('-e', '--elf'	, action="store_true", help='Display only the elf header')
        parser.add_argument('-a', '--all'	, action="store_true", help='Display everything')
        args = parser.parse_args()

        elf_header 	= build_ehdr(sys.argv[1])
        program_headers = build_phdr(sys.argv[1], elf_header)
        section_headers = build_shdr(sys.argv[1], elf_header)

        if args.elf:
                elf_header.load_attributes()
                elf_header.print_elfhdr()
        elif args.programs:
                for program_header in program_headers:
                        program_header.load_attributes()
                        program_header.print_phdr()
        elif args.sections:
                for section_header in section_headers:
                        section_header.load_attributes()
                        section_header.print_shdr()
        else:
                elf_header.load_attributes()
                elf_header.print_elfhdr()
                for program_header in program_headers:
                        program_header.load_attributes()
                        program_header.print_phdr()

                for section_header in section_headers:
                        section_header.load_attributes()
                        section_header.print_shdr()

if __name__ == '__main__':
	main()
