import tabulate
from .ELF_Ehdr_values import *


def hex_repr(string):
    return "0x" + string.replace(" ", "")


class Elf_Ehdr:

    def __init__(self):
        self.e_ident_magic   = None
        self.e_ident_class   = None
        self.e_ident_endian  = None
        self.e_ident_version = None
        self.e_ident_osabi   = None
        self.e_ident_pad     = None
        self.e_type          = None
        self.e_machine       = None
        self.e_version       = None
        self.e_entry         = None
        self.e_phoff         = None
        self.e_shoff         = None
        self.e_flags         = None
        self.e_ehsize        = None
        self.e_phentsize     = None
        self.e_phnum         = None
        self.e_shentsize     = None
        self.e_shnum         = None
        self.e_shstrndx      = None


    def set_values(self):
        values = list()
        values.append(("e_ident_magic  " , self.e_ident_magic   ))  
        values.append(("e_ident_class  " , self.e_ident_class   ))
        values.append(("e_ident_endian " , self.e_ident_endian  ))
        values.append(("e_ident_version" , self.e_ident_version ))
        values.append(("e_ident_osabi  " , self.e_ident_osabi   ))
        values.append(("e_ident_pad    " , self.e_ident_pad     ))
        values.append(("e_type         " , self.e_type          ))
        values.append(("e_machine      " , self.e_machine       ))
        values.append(("e_version      " , self.e_version       ))
        values.append(("e_entry        " , self.e_entry         ))
        values.append(("e_phoff        " , self.e_phoff     + " ( %d bytes from the beginning of the file )"    % int(self.e_phoff, 16)))
        values.append(("e_shoff        " , self.e_shoff     + " ( %d bytes from the beginning of the file )"    % int(self.e_shoff, 16)))
        values.append(("e_flags        " , self.e_flags))
        values.append(("e_ehsize       " , self.e_ehsize    + " ( The ELF header is %d bytes )" % int(self.e_ehsize,16)))
        values.append(("e_phentsize    " , self.e_phentsize + " ( The size of one program header is %d bytes )" % int(self.e_phentsize, 16)))
        values.append(("e_phnum        " , self.e_phnum     + "  ( There are %d program headers )"               % int(self.e_phnum, 16)))
        values.append(("e_shentsize    " , self.e_shentsize + " ( The size of one section header is %d bytes )" % int(self.e_shentsize, 16)))
        values.append(("e_shnum        " , self.e_shnum     + " ( There are %d section headers )"               % int(self.e_shnum, 16)))
        values.append(("e_shstrndx     " , self.e_shstrndx  + " ( Index to the string table is %d )" % int(self.e_shstrndx, 16)))
        return values

    def check_magic(self):
        if self.e_ident_magic in dict_magic:
            self.e_ident_magic = dict_magic["7f 45 4c 46"]
        else:
            self.e_ident_magic = self.e_ident_magic + "( Invalid )"

    def check_class(self):
        if self.e_ident_class in dict_class:
            self.e_ident_class = dict_class[self.e_ident_class]


    # def check_endian(self):
    #     if self.e_ident_endian in dict_endian:
    #         self.e_ident_endian = dict_endian[self.e_ident_endian]


    def check_version(self):
        if self.e_ident_version in dict_version:
            self.e_ident_version = dict_version[self.e_ident_version]


    def check_osabi(self):
        if self.e_ident_osabi in dict_osabi:
            self.e_ident_osabi = dict_osabi[self.e_ident_osabi]


    def check_type(self):
        if self.e_type in dict_type:
            self.e_type = dict_type[self.e_type]


    def check_machine(self):
        if self.e_machine in dict_machine:
            self.e_machine = dict_machine[self.e_machine]


    def load_attributes(self):
        self.check_magic()
        self.check_class()
        self.check_version()
        self.check_osabi()
        self.check_type()
        self.check_machine()

    def print_elfhdr(self):
        # data = [(k, v) for k, v in self.__dict__.items()]
        values = self.set_values()
        print("+-----------------+ +-------------------------------------------------------+")
        print(tabulate.tabulate(values, ['ELF Header'], tablefmt="pipe"))
        print("+-----------------+ +-------------------------------------------------------+\n\n")
