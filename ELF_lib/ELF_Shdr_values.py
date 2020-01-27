dict_type = {
	"0x0"	 :	"SHT_NULL  (Section header table entry unused)",
	"0x1"	 :	"SHT_PROGBITS  (Program data)",
	"0x2"	 :	"SHT_SYMTAB  (Symbol table)",
	"0x3"	 :	"SHT_STRTAB  (String table)",
	"0x4"	 :	"SHT_RELA  (Relocation entries with addends)",
	"0x5"	 :	"SHT_HASH  (Symbol hash table)",
	"0x6"	 :	"SHT_DYNAMIC  (Dynamic linking information)",
	"0x7"	 :	"SHT_NOTE  (Notes)",
	"0x8"	 :	"SHT_NOBITS  (Program space with no data)",
	"0x9"	 :	"SHT_REL  (Relocation entries, no addends)",
	"0x0A"	 :	"SHT_SHLIB 	(Reserved)",
	"0x0B"	 :	"SHT_DYNSYM  (Dynamic linker symbol table)",
	"0x0E"	 :	"SHT_INIT_ARRAY  (Array of constructors)",
	"0x0F"	 :	"SHT_FINI_ARRAY  (Array of destructors)",
	"0x10"	 :	"SHT_PREINIT_ARRAY  (Array of pre-constructors)",
	"0x11"	 :	"SHT_GROUP  (Section group)",
	"0x12"	 :	"SHT_SYMTAB_SHNDX  (Extended section indices)",
	"0x13"	 :	"SHT_NUM  (Number of defined types)",
	"0x60000000": "SHT_LOOS  (Start OS-specific)"
}


dict_flags = {
	"0x1"				:	"SHF_WRITE 	(Writable)",
	"0x2"				:	"SHF_ALLOC  (Occupies memory during execution)",
	"0x4"				:	"SHF_EXECINSTR 	(Executable)",
	"0x10"				:	"SHF_MERGE 	(Might be merged)",
	"0x20"				:	"SHF_STRINGS  (Contains nul-terminated strings)",
	"0x40"				:	"SHF_INFO_LINK 	('sh_info' contains SHT index)",
	"0x80"				:	"SHF_LINK_ORDER  (Preserve order after combining)",
	"0x100"				:	"SHF_OS_NONCONFORMING  (Non-standard OS specific handling required)",
	"0x200"				:	"SHF_GROUP 	(Section is member of a group)",
	"0x400"				:	"SHF_TLS 	(Section hold thread-local data)",
	"0x0ff00000"		:	"SHF_MASKOS  (OS-specific)",
	"0xf0000000"		:	"SHF_MASKPROC  (Processor-specific)",
	"0x4000000"			:	"SHF_ORDERED  (Special ordering requirement (Solaris))",
	"0x8000000"			:	"SHF_EXCLUDE  (Section is excluded unless referenced or allocated (Solaris))" 
}