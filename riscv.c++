#include <elf.h>
#include <iostream>
#include <functional>
#include <cassert>
#include "riscv.h"

using namespace std;

ELF::ELF(FILE* elf_file)
{
  fread(&elf_head, sizeof(elf_head), 1, elf_file);

  assert(elf_head.e_ident[EI_MAG0] == ELFMAG0);
  assert(elf_head.e_ident[EI_MAG1] == ELFMAG1);
  assert(elf_head.e_ident[EI_MAG2] == ELFMAG2);
  assert(elf_head.e_ident[EI_MAG3] == ELFMAG3);

  // EI_CLASS
  // assume 64-bit
  assert(elf_head.e_ident[EI_CLASS] == ELFCLASS64);
  elf_class = "ELFCLASS64";

  // EI_DATA
  if ( elf_head.e_ident[EI_DATA] == ELFDATA2LSB )
    elf_encode = "ELFDATA2LSB";
  else if ( elf_head.e_ident[EI_DATA] == ELFDATA2MSB )
    elf_encode = "ELFDATA2MSB";
  else
    assert(0);

  // EI_VERSION
  assert(elf_head.e_ident[EI_VERSION] == EV_CURRENT);

  // EI_OSABI
  if ( elf_head.e_ident[EI_OSABI] == ELFOSABI_SYSV )
    elf_osabi = "ELFOSABI_SYSV";
  else if ( elf_head.e_ident[EI_OSABI] == ELFOSABI_HPUX )
    elf_osabi = "ELFOSABI_HPUX";
  else
    assert(0);

  // EI_ABIVERSION
  assert(elf_head.e_ident[EI_ABIVERSION] == 0);

  if ( elf_head.e_type == ET_NONE )
    elf_type = "ET_NONE";
  else if ( elf_head.e_type == ET_REL )
    elf_type = "ET_REL";
  else if ( elf_head.e_type == ET_EXEC )
    elf_type = "ET_EXEC";
  else if ( elf_head.e_type == ET_DYN )
    elf_type = "ET_DYN";
  else if ( elf_head.e_type == ET_CORE )
    elf_type = "ET_CORE";
  else
    assert(0);

  assert( elf_head.e_machine == EM_RISCV );

  assert( elf_head.e_version == EV_CURRENT );

  if ( elf_head.e_flags & EF_RISCV_RVC )
    elf_flags.insert("EF_RISCV_RVC");

  if ( elf_head.e_flags & EF_RISCV_FLOAT_ABI == EF_RISCV_FLOAT_ABI_SOFT )
    elf_flags.insert("EF_RISCV_FLOAT_ABI_SOFT");
  else if ( elf_head.e_flags & EF_RISCV_FLOAT_ABI == EF_RISCV_FLOAT_ABI_SINGLE )
    elf_flags.insert("EF_RISCV_FLOAT_ABI_SINGLE");
  else if ( elf_head.e_flags & EF_RISCV_FLOAT_ABI == EF_RISCV_FLOAT_ABI_DOUBLE )
    elf_flags.insert("EF_RISCV_FLOAT_ABI_DOUBLE");
  else if ( elf_head.e_flags & EF_RISCV_FLOAT_ABI == EF_RISCV_FLOAT_ABI_QUAD )
    elf_flags.insert("EF_RISCV_FLOAT_ABI_QUAD");
}

void ELF::print()
{
  cout << showbase;
  cout << "ELF Head :\n";
  cout << "  Class:\t" << elf_class << endl;
  cout << "  Encode:\t" << elf_encode << endl;
  cout << "  OS/ABI:\t" << elf_osabi << endl;
  cout << "  Type:\t\t" << elf_type << endl;
  cout << "  Machine:\t" << "RISC-V" << endl;
  cout << "  EntryPtr:\t" << hex << elf_head.e_entry << endl;
  cout << "  PHOffset:\t" << hex << elf_head.e_phoff << endl;
  cout << "  SHOffset:\t" << hex << elf_head.e_shoff << endl;
  
  cout << "  Flags:\t";
  for ( auto it : elf_flags )
    cout << it << " ";
  cout << endl;

}

int main ( int argc, char* argv[] )
{
  if ( argc < 2 )
  {
    cout << "\tNo ELF file input. For instance :\n";
    cout << "\t\triscv elf/test\n";
    return -1;
  }

  FILE* elf_file = fopen(argv[1], "rb");
  
  ELF elf = ELF(elf_file);
  elf.print();
  

  return 0;
}
