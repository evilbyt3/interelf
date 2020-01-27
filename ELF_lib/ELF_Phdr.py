import tabulate
from .ELF_Phdr_values import *

class Elf_Phdr:

	def __init__(self):
		self.p_type		= None
		self.p_flags	= None
		self.p_offset	= None
		self.p_vaddr	= None
		self.p_paddr	= None
		self.p_filesz	= None
		self.p_memsz	= None
		self.p_align	= None


	def set_values(self):
		values = list()
		values.append(("p_type  "   , self.p_type   ))
		values.append(("p_flags "   , self.p_flags  ))
		values.append(("p_offset"   , self.p_offset + " ( %d bytes from the beginning of the file )" % int(self.p_offset, 16)))
		values.append(("p_vaddr "   , self.p_vaddr  + " ( Address at which the segment will be loaded into memory )"))
		values.append(("p_paddr "   , self.p_paddr  + " ( Address at which the sehment resides on the disk )"))
		values.append(("p_filesz"   , self.p_filesz + " ( The size of the segment is %d bytes )" % int(self.p_filesz, 16)))
		values.append(("p_memsz "   , self.p_memsz  + " ( The size of the segment in memory is %d bytes)" % int(self.p_memsz, 16)))
		values.append(("p_align "   , self.p_align  + " ( Alignment for loading into memory)"))
		return values

	def print_phdr(self):
		values = self.set_values()
		print(tabulate.tabulate(values, headers=["Program Header"], tablefmt="rst"))
		print()
		print()

	def check_type(self):
		if self.p_type in dict_type:
			self.p_type = dict_type[self.p_type]

	def check_flags(self):
		if self.p_flags in dict_flags:
			self.p_flags = dict_flags[self.p_flags]

	def load_attributes(self):
		self.check_type()
		self.check_flags()
