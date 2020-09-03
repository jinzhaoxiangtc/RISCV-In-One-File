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

  def __init__(self, f, encode, phdr) :

    self.__pages = dict()
    self.encode = encode 

    for phdr_entry in phdr.phdr_list :

      ###########################################
      # initialize the program segment with zeros
      vaddr = phdr_entry.p_vaddr
      memsz = phdr_entry.p_memsz
      flags = phdr_entry.p_flags

      while memsz > 0 :
        self.__allocat_new_page(vaddr, flags)
        ini_size = PG_SIZE - (vaddr & PG_MASK)
        vaddr = vaddr + ini_size
        memsz = memsz - ini_size
      ###########################################

      ###########################################
      # load the program segment from ELF file
      f.seek(phdr_entry.p_offset)
      vaddr = phdr_entry.p_vaddr
      filesz = phdr_entry.p_filesz

      while filesz :
        # a list of int, which only read one byte
        data = [int.from_bytes(f.read(1), byteorder=self.encode, signed=False), ]
        self.write(vaddr, data)
        vaddr = vaddr + 1
        filesz = filesz - 1
      ###########################################

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

    assert len(page.data) == PG_SIZE, "The page size has been changed"

  def read(self, vaddr, size) :

    pg_tag = vaddr >> PG_SHFT
    pg_offset = vaddr & PG_MASK
    page = self.__pages.get(pg_tag)
    
    assert page, "The memory space is not allocated before read."

    return int.from_bytes(page.data[pg_offset:pg_offset+size], byteorder=self.encode, signed=False)

class Elf64 :
  
  def __init__(self, f) :
    
    self.ehdr = Elf64_Ehdr(f)
    self.phdr = Elf64_Phdr(f, self.ehdr)

  def print(self) :
    
    self.ehdr.print()

class Decode32 :

  def __init__(self) :

    # bits
    # 6 5 4 3 2 1 0
    self.__dec_func = (
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none, # 0x10
      self._dec_none,
      self._dec_none,
      self.__dec_I_TYPE,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self.__dec_AUIPC,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none, # 0x20
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none, # 0x30
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none
    )

    # bits
    # 14  13  12
    self.__dec_func_I_TYPE = (
      self.__dec_ADDI,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none
    )

  def _dec_none(self, opcode) :
    print("NaISA")

  def __dec_AUIPC(self, opcode) :
    print("AUIPC")

  def __dec_ADDI(self, opcode) :
    print("ADDI")

  def __dec_I_TYPE(self, opcode) :
    self.__dec_func_I_TYPE[(opcode >> 12) & 7](opcode)

  def dec(self, opcode) :
    self.__dec_func[opcode & 0x7f](opcode)

class Decode16 (Decode32) :

  def __init__(self) :

    # bits
    # 15  14  13  1  0
    self.__dec_func = (
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self.__dec_C_LI,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self.__dec_10001,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none
    )

    # bits
    # 12  11  10  6  5
    self.__dec_func_10001 = (
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self.__dec_C_SUB,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none, # 0x10
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none,
      self._dec_none
    )

  def __dec_C_SUB(self, opcode) :
    print("C.SUB")

  def __dec_C_LI(self, opcode) :
    print("C.LI")

  def __dec_10001(self, opcode) :
    upper = (opcode >> 8) & 0x1c
    lower = (opcode >> 5) & 0x03
    self.__dec_func_10001[upper | lower](opcode)

  def dec(self, opcode) :
    self.__dec_func[(opcode >> 11) | (opcode & 3)](opcode)

class Cpu :

  def __init__(self, ehdr, mem) :

    self.pc = ehdr.e_entry
    self.mem = mem
    self.decode32 = Decode32()
    self.decode16 = Decode16()

    print("The starting PC = " + hex(self.pc))

  def step(self) :

    opcode = self.mem.read(self.pc, 4)

    if (opcode & 3) == 3 :      # 32-bit Op
      self.decode32.dec(opcode)
      self.pc = self.pc + 4
    else :                      # 16-bit Op
      opcode = opcode & 0xffff
      self.decode16.dec(opcode)
      self.pc = self.pc + 2

###############################
#####     main program
###############################

f = open(sys.argv[1], 'rb')

elf = Elf64(f)
elf.print()

mem = Mem(f, elf.ehdr.encode, elf.phdr)

cpu = Cpu(elf.ehdr, mem)
cpu.step()
cpu.step()
cpu.step()
cpu.step()
cpu.step()
cpu.step()

f.close()
