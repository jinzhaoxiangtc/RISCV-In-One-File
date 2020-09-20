#!/usr/bin/env python3

import sys

PG_SHFT = 12
PG_SIZE = 1 << PG_SHFT
PG_MASK = PG_SIZE - 1

CMD        = "CMD"
SRC1_NUM   = "SRC1_NUM"
SRC1_VALUE = "SRC1_VALUE"
SRC2_NUM   = "SRC2_NUM"
SRC2_VALUE = "SRC2_VALUE"
DST_NUM    = "DST_NUM"
DST_VALUE  = "DST_VALUE"
IMM        = "IMM"
PC         = "PC"
BR_TARGET  = "BR_TARGET"
MEM_SIZE   = "MEM_SIZE"
MEM_ADDR   = "MEM_ADDR"
ST_DATA    = "ST_DATA"

def get_Iimm(opcode) :

  return ( ( ( opcode >> 20 ) + 0x800 ) & 0xfff ) - 0x800

def get_Simm(opcode) :

  return ( ( (((opcode >> 20) & 0xfe0) | ((opcode >> 7) & 0x1f)) + 0x800 ) & 0xfff ) - 0x800

def get_Bimm(opcode) :

  bimm = ((opcode << 4) & 0x800) | ((opcode >> 20) & 0x7e0) | ((opcode >> 7) & 0x1e)

  if opcode >> 31 :
    bimm = bimm ^ 0xfff
    bimm = bimm + 1
    bimm = -bimm

  return bimm

def get_Uimm(opcode) :

  uimm = opcode & 0xfffff000

  if uimm >> 31 :
    uimm = uimm ^ 0xffffffff
    uimm = uimm + 1
    uimm = -uimm

  return uimm

def get_Jimm(opcode) :

  jimm = (opcode & 0xff000) | ((opcode & 0x100000) >> 9) | ((opcode & 0x7fe00000) >> 20)

  if opcode >> 31 :
    jimm = jimm ^ 0xfffff
    jimm = jimm + 1
    jimm = -jimm

  return jimm

def get_Cimm(opcode) :

  cimm = (opcode >> 2) & 0x1f

  if (opcode >> 12) & 1 :
    cimm = cimm ^ 0x1f
    cimm = cimm + 1
    cimm = -cimm

  return cimm

def get_CUimm(opcode) :

  return ((opcode >> 7) & 0x20) | ((opcode >> 2) & 0x1f)

def get_CBimm(opcode) :

  cbimm = ((opcode << 1) & 0xc0) | ((opcode << 3) & 0x20) | ((opcode >> 7) & 0x18) | ((opcode >> 2) & 0x6)

  if (opcode >> 12) & 1 :
    cbimm = cbimm ^ 0xff
    cbimm = cbimm + 1
    cbimm = -cbimm

  return cbimm

def get_CJimm(opcode) :

  cjimm = ((opcode >> 1) & 0x800) | ((opcode << 2) & 0x400) | ((opcode >>1) & 0x300) | ((opcode << 1) & 0x80) | ((opcode >> 1) & 0x40) | ((opcode << 3) & 0x20) | ((opcode >> 7) & 0x10) | ((opcode >> 2) & 0xe)
  return ( (cjimm + 0x800) & 0xfff ) - 0x800

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
        data = int.from_bytes(f.read(1), byteorder=self.encode, signed=False)
        self.write(vaddr, data, 1)
        vaddr = vaddr + 1
        filesz = filesz - 1
      ###########################################

  def __allocat_new_page(self, vaddr, flags) :

    pg_tag = vaddr >> PG_SHFT
    page = self.__pages.get(pg_tag)

    if page == None :
      page = Page(flags)
      self.__pages[pg_tag] = page

  def write(self, vaddr, data, size) :

    pg_tag = vaddr >> PG_SHFT
    pg_offset = vaddr & PG_MASK

    if pg_tag not in self.__pages :
      self.__allocat_new_page(vaddr, ["PF_W", "PF_R"])
      print("Allocate a new page on Address 0x" + hex(vaddr))

    page = self.__pages.get(pg_tag)

    page.data[pg_offset:pg_offset+size] = data.to_bytes(size, self.encode)

    assert len(page.data) == PG_SIZE, "The page size has been changed"

  def read(self, vaddr, size) :

    pg_tag = vaddr >> PG_SHFT
    pg_offset = vaddr & PG_MASK
    page = self.__pages.get(pg_tag)
    
    assert page, "The memory space is not allocated before read" + hex(vaddr)

    return int.from_bytes(page.data[pg_offset:pg_offset+size], byteorder=self.encode, signed=False)

class Elf64 :
  
  def __init__(self, f) :
    
    self.ehdr = Elf64_Ehdr(f)
    self.phdr = Elf64_Phdr(f, self.ehdr)

  def print(self) :
    
    self.ehdr.print()

class Execute :

  def exe_auipc(myself, inst) :

    inst[DST_VALUE] = inst[PC] + inst[IMM]

  def exe_add(myself, inst) :

    inst[DST_VALUE] = inst[SRC1_VALUE] + inst[SRC2_VALUE]

  def exe_addi(myself, inst) :

    inst[DST_VALUE] = inst[SRC1_VALUE] + inst[IMM]

  def exe_addiw(myself, inst) :

    data = (inst[SRC1_VALUE] + inst[IMM]) & 0xffffffff
    inst[DST_VALUE] = ((data + 0x80000000) & 0xffffffff) - 0x80000000

  def exe_andi(myself, inst) :

    inst[DST_VALUE] = inst[SRC1_VALUE] & inst[IMM]

  def exe_slli(myself, inst) :

    inst[DST_VALUE] = inst[SRC1_VALUE] << inst[IMM]

  def exe_srai(myself, inst) :

    inst[DST_VALUE] = inst[SRC1_VALUE] >> inst[IMM]

  def exe_jal(myself, inst) :

    inst[DST_VALUE] = inst[PC] + 4
    inst[BR_TARGET] = inst[PC] + inst[IMM]

  def exe_jalr(myself, inst) :

    inst[DST_VALUE] = inst[PC] + 4
    inst[BR_TARGET] = (inst[SRC1_VALUE] + inst[IMM]) & 0xfffffffffffffffe

  def exe_beq(myself, inst) :

    if inst[SRC1_VALUE] == inst[SRC2_VALUE] :
      inst[BR_TARGET] = inst[PC] + inst[IMM]

  def exe_bne(myself, inst) :

    if inst[SRC1_VALUE] != inst[SRC2_VALUE] :
      inst[BR_TARGET] = inst[PC] + inst[IMM]

  def exe_error(myself, inst) :

    assert 0, "Node decode"

    pass

  def exe_blt(myself, inst) :

    pass

  def exe_bge(myself, inst) :

    pass

  def exe_bltu(myself, inst) :

    if inst[SRC1_VALUE] < inst[SRC2_VALUE] :
      inst[BR_TARGET] = inst[PC] + inst[IMM]

  def exe_bgeu(myself, inst) :

    if inst[SRC1_VALUE] >= inst[SRC2_VALUE] :
      inst[BR_TARGET] = inst[PC] + inst[IMM]

  def exe_st(myself, inst) :

    inst[MEM_ADDR] = inst[SRC1_VALUE] + inst[IMM]
    inst[ST_DATA] =  inst[SRC2_VALUE] & (0x100 ** inst[MEM_SIZE] - 1)

  def exe_ld(myself, inst) :

    inst[MEM_ADDR] = inst[SRC1_VALUE] + inst[IMM]

  def exe_sub(myself, inst) :

    inst[DST_VALUE] = inst[SRC1_VALUE] - inst[SRC2_VALUE]

  def exe_c_li(myself, inst) :

    inst[DST_VALUE] = inst[IMM]

  def exe_c_mv(myself, inst) :

    inst[DST_VALUE] = inst[SRC1_VALUE]

  def exe_c_bnez(myself, inst) :

    if inst[SRC1_VALUE] != 0 :
      inst[BR_TARGET] = inst[PC] + inst[IMM]

  def exe_c_beqz(myself, inst) :

    if inst[SRC1_VALUE] == 0 :
      inst[BR_TARGET] = inst[PC] + inst[IMM]

  def exe_c_jr(myself, inst) :

    inst[BR_TARGET] = inst[SRC1_VALUE]

  def exe_c_jalr(myself, inst) :

    inst[DST_VALUE] = inst[PC] + 2
    inst[BR_TARGET] = inst[SRC1_VALUE] & 0xfffffffffffffffe

  def exe_c_addi(myself, inst) :

    inst[DST_VALUE] = inst[SRC1_VALUE] + inst[IMM]

  def exe_c_andi(myself, inst) :

    inst[DST_VALUE] = inst[SRC1_VALUE] & inst[IMM]

  def exe_c_j(myself, inst) :

    inst[BR_TARGET] = inst[PC] + inst[IMM]

class Decode32 :

  def __init__(self, cpu) :

    # bits
    # 6 5 4 3 2 1 0
    self.dec_func = (
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_LOAD,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none, # 0x10
      self.dec_none,
      self.dec_none,
      self.dec_I_TYPE,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_AUIPC,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_0011011,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none, # 0x20
      self.dec_none,
      self.dec_none,
      self.dec_STORE,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none, # 0x30
      self.dec_none,
      self.dec_none,
      self.dec_R_TYPE,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none, # 0x40
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none, # 0x50
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none, # 0x60
      self.dec_none,
      self.dec_none,
      self.dec_B_TYPE,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_JALR,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_JAL,
      self.dec_none, # 0x70
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none
    )

    # bits
    # 14  13  12
    self.dec_func_I_TYPE = (
      self.dec_ADDI,
      self.dec_SLLI,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_SRAI,
      self.dec_none,
      self.dec_ANDI
    )

    # bits
    # 14  13  12
    self.exe_func_B_TYPE = (
      cpu.execute.exe_beq,
      cpu.execute.exe_bne,
      cpu.execute.exe_error,
      cpu.execute.exe_error,
      cpu.execute.exe_blt,
      cpu.execute.exe_bge,
      cpu.execute.exe_bltu,
      cpu.execute.exe_bgeu
    )

  def dec_none(self, opcode, cpu) :
    print("NaISA")

  def dec_AUIPC(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_auipc,
      DST_NUM   : (opcode >> 7) & 0x1f,
      IMM       : get_Uimm(opcode),
      PC        : cpu.pc
    }

  def dec_ADDI(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_addi,
      DST_NUM   : (opcode >> 7) & 0x1f,
      SRC1_NUM  : (opcode >> 15) & 0x1f,
      IMM       : get_Iimm(opcode)
    }

  def dec_ANDI(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_andi,
      DST_NUM   : (opcode >> 7) & 0x1f,
      SRC1_NUM  : (opcode >> 15) & 0x1f,
      IMM       : get_Iimm(opcode)
    }

  def dec_SLLI(self, opcode, cpu) :

    assert (opcode >> 25) == 0, "The most significant 7 bits are not zeros."

    return {
      CMD       : cpu.execute.exe_slli,
      DST_NUM   : (opcode >> 7) & 0x1f,
      SRC1_NUM  : (opcode >> 15) & 0x1f,
      IMM       : (opcode >> 20) & 0x1f
    }

  def dec_SRAI(self, opcode, cpu) :

    if (opcode >> 25) == 0x20 :
      return {
      CMD       : cpu.execute.exe_srai,
      DST_NUM   : (opcode >> 7) & 0x1f,
      SRC1_NUM  : (opcode >> 15) & 0x1f,
      IMM       : (opcode >> 20) & 0x1f
      }


  def dec_JAL(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_jal,
      DST_NUM   : (opcode >> 7) & 0x1f,
      IMM       : get_Jimm(opcode),
      PC        : cpu.pc
    }

  def dec_JALR(self, opcode, cpu) :

    assert ((opcode >> 12) & 0x7) == 0, "JALR funct3 has to be zeros."

    return {
      CMD       : cpu.execute.exe_jalr,
      DST_NUM   : (opcode >> 7) & 0x1f,
      SRC1_NUM  : (opcode >> 15) & 0x1f,
      IMM       : get_Iimm(opcode),
      PC        : cpu.pc
    }

  def dec_STORE(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_st,
      SRC1_NUM  : (opcode >> 15) & 0x1f,
      SRC2_NUM  : (opcode >> 20) & 0x1f,
      IMM       : get_Simm(opcode),
      MEM_SIZE  : 1 << ((opcode >> 12) & 0x7)
    }

  def dec_LOAD(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_ld,
      DST_NUM   : (opcode >> 7) & 0x1f,
      SRC1_NUM  : (opcode >> 15) & 0x1f,
      IMM       : get_Iimm(opcode),
      MEM_SIZE  : 1 << ((opcode >> 12) & 0x7)
    }

  def dec_I_TYPE(self, opcode, cpu) :

    return self.dec_func_I_TYPE[(opcode >> 12) & 7](opcode, cpu)

  def dec_R_TYPE(self, opcode, cpu) :

    func = (opcode >> 12) & 7

    if func == 0 :
      if (opcode >> 25) == 0x00 :
        cmd = cpu.execute.exe_add
      elif (opcode >> 25) == 0x20 :
        cmd = cpu.execute.exe_sub
      else :
        assert 0

    return {
      CMD       : cmd,
      DST_NUM   : (opcode >> 7) & 0x1f,
      SRC1_NUM  : (opcode >> 15) & 0x1f,
      SRC2_NUM  : (opcode >> 20) & 0x1f,
    }

  def dec_B_TYPE(self, opcode, cpu) :
    
    return {
      CMD       : self.exe_func_B_TYPE[(opcode >> 12) & 7],
      SRC1_NUM  : (opcode >> 15) & 0x1f,
      SRC2_NUM  : (opcode >> 20) & 0x1f,
      IMM       : get_Bimm(opcode),
      PC        : cpu.pc
    }

  def dec_0011011(self, opcode, cpu) :

    if ( (opcode >> 12) & 0x7 == 0 ) : # addiw
      return {
      CMD       : cpu.execute.exe_addiw,
      DST_NUM   : (opcode >> 7) & 0x1f,
      SRC1_NUM  : (opcode >> 15) & 0x1f,
      IMM       : get_Iimm(opcode),
      }

class Decode16 (Decode32) :

  def __init__(self) :

    # bits
    # 15  14  13  1  0
    self.dec_func = (
      self.dec_none,
      self.dec_C_ADDI,
      self.dec_C_SLLI,
      self.dec_none,
      self.dec_none,
      self.dec_C_ADDIW,
      self.dec_none,
      self.dec_none,
      self.dec_C_LW,
      self.dec_C_LI,
      self.dec_none,
      self.dec_none,
      self.dec_C_LD,
      self.dec_C_LUI,
      self.dec_C_LDSP,
      self.dec_none,
      self.dec_none,
      self.dec_10001,
      self.dec_10010,
      self.dec_none,
      self.dec_none,
      self.dec_C_J,
      self.dec_none,
      self.dec_none,
      self.dec_C_SW,
      self.dec_C_BEQZ,
      self.dec_none,
      self.dec_none,
      self.dec_C_SD,
      self.dec_C_BNEZ,
      self.dec_C_SDSP,
      self.dec_none
    )

    # bits
    # 12  11  10  6  5
    self.dec_func_10001 = (
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_C_ANDI,
      self.dec_C_ANDI,
      self.dec_C_ANDI,
      self.dec_C_ANDI,
      self.dec_C_SUB,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none, # 0x10
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_C_ANDI,
      self.dec_C_ANDI,
      self.dec_C_ANDI,
      self.dec_C_ANDI,
      self.dec_none,
      self.dec_none,
      self.dec_none,
      self.dec_none
    )

  def dec_C_SUB(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_sub,
      DST_NUM   : ((opcode >> 7) & 0x7) + 8,
      SRC1_NUM  : ((opcode >> 7) & 0x7) + 8,
      SRC2_NUM  : ((opcode >> 2) & 0x7) + 8,
    }

  def dec_C_LI(self, opcode, cpu) :

    if (opcode >> 7) & 0x1f :
      return {
        CMD       : cpu.execute.exe_c_li,
        DST_NUM   : (opcode >> 7) & 0x1f,
        IMM       : get_Cimm(opcode)
      }

    # dest reg == 0
    return self.def_C_HINT(opcode, cpu)

  def dec_C_LUI(self, opcode, cpu) :

    rd = (opcode >> 7) & 0x1f

    assert rd, "rd cannot be X0 in C.LUI."

    nzimm = get_Cimm(opcode)

    assert nzimm, "imm cannot be zero."

    if rd == 2 : # C.ADDI16SP
      return {
        CMD       : cpu.execute.exe_addi,
        DST_NUM   : 2,
        SRC1_NUM  : 2,
        IMM       : (((((opcode >> 3) & 0x200) | ((opcode << 4) & 0x180) | ((opcode << 1) & 0x40) | ((opcode << 3) & 0x20) | ((opcode >> 2) & 0x10)) + 0x200 ) & 0x3ff ) - 0x200
      }
    else :
      return {
        CMD       : cpu.execute.exe_c_li,
        DST_NUM   : rd,
        IMM       : nzimm << 12
      }

  def dec_C_MV(self, opcode, cpu) :

    if (opcode >> 7) & 0x1f :
      return {
        CMD       : cpu.execute.exe_c_mv,
        DST_NUM   : (opcode >> 7) & 0x1f,
        SRC1_NUM  : (opcode >> 2) & 0x1f
      }

  def dec_C_BEQZ(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_c_beqz,
      SRC1_NUM  : ((opcode >> 7) & 0x7) + 8,
      IMM       : get_CBimm(opcode),
      PC        : cpu.pc
    }

  def dec_C_BNEZ(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_c_bnez,
      SRC1_NUM  : ((opcode >> 7) & 0x7) + 8,
      IMM       : get_CBimm(opcode),
      PC        : cpu.pc
    }

  def dec_C_ADD(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_add,
      DST_NUM   : (opcode >> 7) & 0x1f,
      SRC1_NUM  : (opcode >> 7) & 0x1f,
      SRC2_NUM  : (opcode >> 2) & 0x1f
    }

  def dec_C_ADDIW(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_addiw,
      DST_NUM   : (opcode >> 7) & 0x1f,
      SRC1_NUM  : (opcode >> 7) & 0x1f,
      IMM       : get_Cimm(opcode)
    }

  def dec_C_ANDI(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_c_andi,
      DST_NUM   : ((opcode >> 7) & 0x7) + 8,
      SRC1_NUM  : ((opcode >> 7) & 0x7) + 8,
      IMM       : get_Cimm(opcode),
    }

  def dec_C_SLLI(self, opcode, cpu) :

    rs1 = (opcode >> 7) & 0x1f
    imm = get_CUimm(opcode)

    if rs1 :
      if imm :
        return {
        CMD       : cpu.execute.exe_slli,
        DST_NUM   : (opcode >> 7) & 0x1f,
        SRC1_NUM  : (opcode >> 7) & 0x1f,
        IMM       : imm
        }

  def dec_C_JR(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_c_jr,
      SRC1_NUM  : (opcode >> 7) & 0x1f,
    }

  def dec_C_JALR(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_c_jalr,
      DST_NUM   : 1,
      SRC1_NUM  : (opcode >> 7) & 0x1f,
      PC        : cpu.pc
    }

  def dec_C_ADDI(self, opcode, cpu) :

    rs1 = (opcode >> 7) & 0x1f
    imm = get_Cimm(opcode)

    if rs1 :
      if imm != 0 : # addi
        return {
        CMD       : cpu.execute.exe_c_addi,
        DST_NUM   : rs1,
        SRC1_NUM  : rs1,
        IMM       : imm
        }
      else : # hint
        pass
    else : # nop
      pass

  def dec_C_J(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_c_j,
      IMM       : get_CJimm(opcode),
      PC        : cpu.pc
    }

  def dec_C_SD(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_st,
      SRC1_NUM  : ((opcode >> 7) & 0x7) + 8,
      SRC2_NUM  : ((opcode >> 2) & 0x7) + 8,
      IMM       : ((opcode << 1) & 0xc0) | ((opcode >> 7) & 0x38), # unsigned
      MEM_SIZE  : 8
    }

  def dec_C_SDSP(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_st,
      SRC1_NUM  : 2,
      SRC2_NUM  : (opcode >> 2) & 0x1f,
      IMM       : ((opcode >> 1) & 0x1c0) | ((opcode >> 7) & 0x38), # unsigned
      MEM_SIZE  : 8
    }

  def dec_C_SW(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_st,
      SRC1_NUM  : ((opcode >> 7) & 0x7) + 8,
      SRC2_NUM  : ((opcode >> 2) & 0x7) + 8,
      IMM       : ((opcode << 1) & 0x40) | ((opcode >> 7) & 0x38) | ((opcode >> 4) & 0x4), # unsigned
      MEM_SIZE  : 4
    }

  def dec_C_LW(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_ld,
      DST_NUM   : ((opcode >> 2) & 0x7) + 8,
      SRC1_NUM  : ((opcode >> 7) & 0x7) + 8,
      IMM       : ((opcode << 1) & 0x40) | ((opcode >> 7) & 0x38) | ((opcode >> 4) & 0x4), # unsigned
      MEM_SIZE  : 4
    }

  def dec_C_LD(self, opcode, cpu) :

    return {
      CMD       : cpu.execute.exe_ld,
      DST_NUM   : ((opcode >> 2) & 0x7) + 8,
      SRC1_NUM  : ((opcode >> 7) & 0x7) + 8,
      IMM       : ((opcode << 1) & 0xc0) | ((opcode >> 7) & 0x38), # unsigned
      MEM_SIZE  : 8
    }

  def dec_C_LDSP(self, opcode, cpu) :

    rd = (opcode >> 7) & 0x1f

    assert rd, "rd cannot be X0 in C.LDSP"

    return {
      CMD       : cpu.execute.exe_ld,
      DST_NUM   : rd,
      SRC1_NUM  : 2,
      IMM       : ((opcode << 4) & 0x1c0) | ((opcode >> 7) & 0x20) | ((opcode >> 2) & 0x18), # unsigned
      MEM_SIZE  : 8
    }

  def dec_10001(self, opcode, cpu) :

    upper = (opcode >> 8) & 0x1c
    lower = (opcode >> 5) & 0x03
    return self.dec_func_10001[upper | lower](opcode, cpu)

  def dec_10010(self, opcode, cpu) :

    if (opcode >> 12) & 1 : # Bit12 == 1
      if (opcode >> 7) & 0x1f : # Rd != 0
        if (opcode >> 2) & 0x1f : # Rs2 != 0
          return self.dec_C_ADD(opcode, cpu)
        else : # Rs2 == 0
          return self.dec_C_JALR(opcode, cpu)
      else : # Rd == 0
        pass
    else : # Bit12 == 0
      if (opcode >> 7) & 0x1f : # Rd != 0
        if (opcode >> 2) & 0x1f : # Rs2 != 0
          return self.dec_C_MV(opcode, cpu)
        else : # Rs2 == 0
          return self.dec_C_JR(opcode, cpu)
      else : # Rd == 0
        pass

class Cpu :

  def __init__(self, ehdr, mem) :

    self.pc = ehdr.e_entry
    self.reg = [0] *32
    # initialize SP
    self.reg[2] = 0xfee8b50

    self.mem = mem
    self.execute = Execute()

    self.decode32 = Decode32(self)
    self.decode16 = Decode16()

    print("The starting PC = " + hex(self.pc))

  def step(self) :

    opcode = self.mem.read(self.pc, 4)

    if (opcode & 3) == 3 :      # 32-bit Op
      inst = self.decode32.dec_func[opcode & 0x7f](opcode, self)
      self.pc = self.pc + 4
    else :                      # 16-bit Op
      opcode = opcode & 0xffff
      inst = self.decode16.dec_func[((opcode >> 11 ) & 0x1c) | (opcode & 3)](opcode, self)
      self.pc = self.pc + 2

    if SRC1_NUM in inst :
      self.read_reg(inst)

    inst[CMD](inst);

    if ST_DATA in inst :
      self.mem.write(inst[MEM_ADDR], inst[ST_DATA], inst[MEM_SIZE])

    if inst[CMD] == cpu.execute.exe_ld :
      inst[DST_VALUE] = self.mem.read(inst[MEM_ADDR], inst[MEM_SIZE])

    print(inst)

    # Do not write to X0
    if DST_NUM in inst and inst[DST_NUM] :
      self.write_reg(inst)

    if BR_TARGET in inst :
      assert isinstance(inst[BR_TARGET], int)
      self.pc = inst[BR_TARGET]

  def read_reg(self, inst) :

    inst[SRC1_VALUE] = self.reg[inst[SRC1_NUM]]

    if SRC2_NUM in inst :
      inst[SRC2_VALUE] = self.reg[inst[SRC2_NUM]]

  def write_reg(self, inst) :

    assert isinstance(inst[DST_VALUE], int)

    self.reg[inst[DST_NUM]] = inst[DST_VALUE]

###############################
#####     main program
###############################

f = open(sys.argv[1], 'rb')

elf = Elf64(f)
elf.print()

mem = Mem(f, elf.ehdr.encode, elf.phdr)

cpu = Cpu(elf.ehdr, mem)

for i in range(140) :
  cpu.step()

f.close()
