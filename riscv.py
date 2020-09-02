#!/usr/bin/env python3

import sys

PG_SHFT = 12
PG_SIZE = 1 << PG_SHFT
PG_MASK = PG_SIZE - 1

class Elf64_Ehdr :
  
  def __init__(self, f) :

    f.seek(0) # make sure it is reading from the beginning of the file

    self.e_ident = f.read(16)

    assert self.e_ident[:4] == bytes('\x7fELF', 'utf-8'), "This is not an ELF file"

    if self.e_ident[4] == 1 :
      self.e_class = "ELFCLASS32"
    elif self.e_ident[4] == 2 :
      self.e_class = "ELFCLASS64"
    else :
      assert 0, "The file class is not correctly set."

    if self.e_ident[5] == 1 :
      self.encode = "little"
    elif self.e_ident[5] == 2 :
      self.encode = "big"
    else :
      assert 0, "The file encoding is not correctly set."

    assert self.e_ident[6] == 1, "The file version is incorrect."

    if self.e_ident[7] == 0 :
      self.osabi = "ELFOSABI_SYSV"
    elif self.e_ident[7] == 1 :
      self.osabi = "ELFOSABI_HPUX"
    elif self.e_ident[7] == 255 :
      self.osabi = "ELFOSABI_STANDALONE"
    else :
      assert 0, "The file Operating System and ABI Identifiers is not correctly set."

    assert self.e_ident[8] == 0, "The version of the ABI is incorrect."

    self.e_type = int.from_bytes(f.read(2), byteorder=self.encode, signed=False)
    if self.e_type == 0 :
      self.e_type = "No file type"
    elif self.e_type == 1 :
      self.e_type = "Relocatable object file"
    elif self.e_type == 2 :
      self.e_type = "Executable file"
    elif self.e_type == 3 :
      self.e_type = "Shared object file"
    elif self.e_type == 4 :
      self.e_type = "Core file"
    else :
      assert 0, "The Object File Types is not correctly set."

    assert int.from_bytes(f.read(2), byteorder=self.encode, signed=False) == 243, "It's not compiled for RISC-V ISA"

    assert int.from_bytes(f.read(4), byteorder=self.encode, signed=False) == 1, "The version number is not set to EV_CURRENT"

    self.e_entry = int.from_bytes(f.read(8), byteorder=self.encode, signed=False)

    self.e_phoff = int.from_bytes(f.read(8), byteorder=self.encode, signed=False)

    self.e_shoff = int.from_bytes(f.read(8), byteorder=self.encode, signed=False)

    data = int.from_bytes(f.read(4), byteorder=self.encode, signed=False)
    self.e_flags = list()
    if data & 1 :
      self.e_flags.append("RVC")
    
    if ((data >> 1) & 3) == 0 :
      self.e_flags.append("FLOAT_ABI_SOFT")
    elif ((data >> 1) & 3) == 1 :
      self.e_flags.append("FLOAT_ABI_SINGLE")
    elif ((data >> 1) & 3) == 2 :
      self.e_flags.append("FLOAT_ABI_DOUBLE")
    elif ((data >> 1) & 3) == 3 :
      self.e_flags.append("FLOAT_ABI_QUAD")

    if (data >> 3) & 1 :
      self.e_flags.append("RVE")
    if (data >> 4) & 1 :
      self.e_flags.append("TSO")
    
    self.e_ehsize = int.from_bytes(f.read(2), byteorder=self.encode, signed=False)
    
    self.e_phentsize = int.from_bytes(f.read(2), byteorder=self.encode, signed=False)
    
    self.e_phnum = int.from_bytes(f.read(2), byteorder=self.encode, signed=False)
    
    self.e_shentsize = int.from_bytes(f.read(2), byteorder=self.encode, signed=False)
    
    self.e_shnum = int.from_bytes(f.read(2), byteorder=self.encode, signed=False)
    
    self.e_shstrndx = int.from_bytes(f.read(2), byteorder=self.encode, signed=False)

  def print(self) :

    print("ELF Head:")
    
    print("  Magic", end="")
    for i in range(16) :
      print(":" + hex(self.e_ident[i]), end="")
    print()

    print("  Class:" + self.e_class)
    print("  Encode:" + self.encode)
    print("  OS/ABI:" + self.osabi)
    print("  Type:" + self.e_type)
    print("  Machine:" + "RISC-V")
    print("  Entry point address:" + hex(self.e_entry))
    print("  Start of program headers:" + str(self.e_phoff))
    print("  Start of section headers:" + str(self.e_shoff))
    print("  Flags:" + " ".join(self.e_flags))
    print("  Size of this header:" + str(self.e_ehsize))
    print("  Size of program headers:" + str(self.e_phentsize))
    print("  Number of program headers:" + str(self.e_phnum))
    print("  Size of section headers:" + str(self.e_shentsize))
    print("  Number of section headers:" + str(self.e_shnum))
    print("  Section header string table index:" + str(self.e_shstrndx))

class Elf64_Phdr_entry :

  def __init__(self, f, pos, ehdr) :

    f.seek(pos)

    self.p_type = int.from_bytes(f.read(4), byteorder=ehdr.encode, signed=False)
    if self.p_type == 0 :
      self.p_type = "PT_NULL"
    elif self.p_type == 1 :
      self.p_type = "PT_LOAD"
    elif self.p_type == 2 :
      self.p_type = "PT_DYNAMIC"
    elif self.p_type == 3 :
      self.p_type = "PT_INTERP"
    elif self.p_type == 4 :
      self.p_type = "PT_NOTE"
    elif self.p_type == 5 :
      self.p_type = "PT_SHLIB"
    elif self.p_type == 6 :
      self.p_type = "PT_PHDR"
    else :
      assert 0, "The program header type is not supported."
    
    self.p_flags = list()
    data = int.from_bytes(f.read(4), byteorder=ehdr.encode, signed=False)
    if data & 1 :
      self.p_flags.append("PF_X")
    if data & 2 :
      self.p_flags.append("PF_W")
    if data & 4 :
      self.p_flags.append("PF_R")

    self.p_offset = int.from_bytes(f.read(8), byteorder=ehdr.encode, signed=False)
    
    self.p_vaddr = int.from_bytes(f.read(8), byteorder=ehdr.encode, signed=False)
    
    self.p_paddr = int.from_bytes(f.read(8), byteorder=ehdr.encode, signed=False)
    
    self.p_filesz = int.from_bytes(f.read(8), byteorder=ehdr.encode, signed=False)
    
    self.p_memsz = int.from_bytes(f.read(8), byteorder=ehdr.encode, signed=False)
    
    self.p_align = int.from_bytes(f.read(8), byteorder=ehdr.encode, signed=False)

class Elf64_Phdr :

  def __init__(self, f, ehdr) :

    assert ehdr.e_class == "ELFCLASS64", "ELFCLASS32 is not currently supported."

    # The list of Program Heads
    self.phdr_list = list()

    for i in range(ehdr.e_phnum) :
      self.phdr_list.append(Elf64_Phdr_entry(f, ehdr.e_phoff + i * ehdr.e_phentsize, ehdr))

class Page :

  def __init__(self, flags) :

    self.data = bytearray(PG_SIZE)
    self.flags = flags

class Mem :

  def __init__(self, f, encode, prg_head) :

    self.__pages = dict()
    self.encode = encode 

    for phdr_entry in prg_head.phdr_list :

      addr = phdr_entry.p_vaddr
      offset = addr & PG_MASK
      memsz = phdr_entry.p_memsz
      flags = phdr_entry.p_flags

      while memsz :
        self.__allocat_new_page(addr, flags)
        memsz = memsz - (PG_SIZE - offset)
        if memsz < 0 :
          memsz = 0

      f.seek(phdr_entry.p_offset)
      filesz = phdr_entry.p_filesz

      while filesz :
        data = [int.from_bytes(f.read(1), byteorder=self.encode, signed=False), ]
        self.write(addr, data)
        filesz = filesz - 1
        addr = addr + 1

  def __allocat_new_page(self, vaddr, flags) :

    pg_tag = vaddr >> PG_SHFT
    page = self.__pages.get(pg_tag)

    if page == None :
      page = Page(flags)
      self.__pages[pg_tag] = page

  # data is a list of int, the size is the number of bytes
  def write(self, vaddr, data) :

    pg_tag = vaddr >> PG_SHFT
    pg_offset = vaddr & PG_MASK
    page = self.__pages.get(pg_tag)
    size = len(data)

    assert page, "The memory space is not allocated before write."

    page.data[pg_offset:pg_offset+size] = data

    assert len(page.data) == PG_SIZE, "The page size is changed"

  def read(self, vaddr, size) :

    pg_tag = vaddr >> PG_SHFT
    pg_offset = vaddr & PG_MASK
    page = self.__pages.get(pg_tag)
    
    assert page, "The memory space is not allocated before read."

    return int.from_bytes(page.data[pg_offset:pg_offset+size], byteorder=self.encode, signed=False)

class Elf64 :
  
  def __init__(self, f) :
    
    self.elf_head = Elf64_Ehdr(f)
    self.prg_head = Elf64_Phdr(f, self.elf_head)

  def print(self) :
    
    self.elf_head.print()

###############################
#####     main program
###############################

f = open(sys.argv[1], 'rb')

elf = Elf64(f)
elf.print()

mem = Mem(f, elf.elf_head.encode, elf.prg_head)

print(hex(mem.read(0x11470, 4)))

f.close()
