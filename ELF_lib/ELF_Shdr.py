import tabulate
from .ELF_Shdr_values import *

class Elf_Shdr:

	def __init__(self):
		self.sh_name	  = None
		self.sh_type 	  = None
		self.sh_flags 	  = None
		self.sh_addr 	  = None
		self.sh_offset 	  = None
		self.sh_size 	  = None
		self.sh_link 	  = None
		self.sh_info 	  = None
		self.sh_addralign = None
		self.sh_entsize   = None


	def set_values(self):
		values = list()
		values.append(("sh_name"		, self.sh_name		 ))
		values.append(("sh_type"		, self.sh_type		 ))	 
		values.append(("sh_flags"		, self.sh_flags 	 ))
		values.append(("sh_addr"		, self.sh_addr 		 + "  (Virtual Address)"))
		values.append(("sh_offset"		, self.sh_offset 	 + "  (%d bytes into the file)" % int(self.sh_offset, 16))) 
		values.append(("sh_size"		, self.sh_size 	 	 + "  (%d bytes in the file image)" % int(self.sh_size, 16)))
		values.append(("sh_link"		, self.sh_link 	 	 + "  (Section index of an associated section)"))
		values.append(("sh_info"		, self.sh_info 	 	 + "  (Extra Information)"))
		values.append(("sh_addralign"	, self.sh_addralign	 + "  (Required alignment)"))
		values.append(("sh_entsize"		, self.sh_entsize  	 + "  (The size of each entry is %d bytes, only the ones that contain fixed-size entries)"))
		return values


	def check_type(self):
		if self.sh_type in dict_type:
			self.sh_type = dict_type[self.sh_type]

	def check_flags(self):
		if self.sh_flags in dict_flags:
			self.sh_flags = dict_flags[self.sh_flags]

	def load_attributes(self):
		self.check_type()
		self.check_flags()

	def print_shdr(self):
		values = self.set_values()
		print(tabulate.tabulate(values, headers=["Section Header"], tablefmt='rst'))
		print()
		print()
