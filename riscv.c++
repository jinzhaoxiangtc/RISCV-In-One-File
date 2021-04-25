#include <elf.h>
#include <errno.h>
#include <string>
#include <set>
#include <map>
#include <iostream>
#include <cassert>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mman.h>
#include <string.h>

#define IS_NOT_ZR(num) ( num > 0 )

#define GET_BIT_31_12(opcode) ( opcode & 0xfffff000 )
#define GET_BIT_5_0(opcode) ( ((opcode >> 7) & 0x20) | ((opcode >> 2) & 0x1f) )
#define GET_BIT_20_1(opcode) ( ((opcode >> 11) & 0x100000) | (opcode & 0xff000) | ((opcode >> 9) & 0x800) | ((opcode >> 20) & 0x7fe) )
#define GET_BIT_12_1(opcode) ( ((opcode >> 19) & 0x1000) | ((opcode << 4) & 0x800) | ((opcode >> 20) & 0x7e0) | ((opcode >> 7) & 0x1e) )
#define GET_BIT_8_1(opcode) ( ((opcode >> 4) & 0x100) | ((opcode << 1) & 0xc0) | ((opcode << 3) & 0x20) | ((opcode >> 7) & 0x18) | ((opcode >> 2) & 0x6) )
#define GET_BIT_11_0(opcode) ( ((opcode >> 20) & 0xfe0) | ((opcode >> 7) & 0x1f) )
#define GET_BIT_11_1(opcode) ( ((opcode >> 1) & 0x800) | ((opcode << 2) & 0x400) | ((opcode >>1) & 0x300) | ((opcode << 1) & 0x80) | ((opcode >> 1) & 0x40) | ((opcode << 3) & 0x20) | ((opcode >> 7) & 0x10) | ((opcode >> 2) & 0xe) )

#define GET_UIMM(opcode) ( (((REG)GET_BIT_31_12(opcode) + 0x80000000) & 0xffffffff) - 0x80000000)
#define GET_IIMM(opcode) ( ((((REG)opcode >> 20) + 0x800) & 0xfff) - 0x800 )
#define GET_JIMM(opcode) ( (((REG)GET_BIT_20_1(opcode) + 0x100000) & 0x1fffff) - 0x100000 )
#define GET_BIMM(opcode) ( ((GET_BIT_12_1(opcode) + 0x1000) & 0x1fff) - 0x1000 )
#define GET_SIMM(opcode) ( (((REG)GET_BIT_11_0(opcode) + 0x800) & 0xfff) - 0x800)

#define GET_CIMM(opcode) ( (((REG)GET_BIT_5_0(opcode) + 0x20) & 0x3f) - 0x20 )
#define GET_CBIMM(opcode) ( (((REG)GET_BIT_8_1(opcode) + 0x100) & 0x1ff) - 0x100 )
#define GET_CJIMM(opcode) ( ((GET_BIT_11_1(opcode) + 0x800) & 0xfff) -0x800 )

#define GET_RD(opcode) ( (opcode >> 7) & 0x1f )
#define GET_RS1(opcode) ( (opcode >> 15) & 0x1f )
#define GET_RS2(opcode) ( (opcode >> 20) & 0x1f )
#define GET_FUNC3(opcode) ( (opcode >> 12) & 0x7 )
#define GET_FUNC7(opcode) ( (opcode >> 25) & 0x7f )

#define GET_C_RS1(opcode) ( (opcode >> 7) & 0x1f )
#define GET_C_RS2(opcode) ( (opcode >> 2) & 0x1f )
#define GET_C_RS1_prime(opcode) ( ((opcode >> 7) & 0x7) + 8 )
#define GET_C_RS2_prime(opcode) ( ((opcode >> 2) & 0x7) + 8 )

typedef uint64_t ADDRESS;
typedef uint32_t OPCODE;
typedef int64_t  REG;
typedef uint64_t UREG;

enum COMMAND
{
  CMD_AUIPC,
  CMD_BEQ,
  CMD_BGE,
  CMD_BGEU,
  CMD_BLT,
  CMD_BLTU,
  CMD_BNE,
  CMD_DIVU,
  CMD_LI,
  CMD_ADDI,
  CMD_SLTIU,
  CMD_XORI,
  CMD_ANDI,
  CMD_JAL,
  CMD_JALR,
  CMD_J,
  CMD_ADD,
  CMD_SUB,
  CMD_SLL,
  CMD_SLTU,
  CMD_XOR,
  CMD_AND,
  CMD_OR,
  CMD_ST,
  CMD_LD,
  CMD_MUL,
  CMD_REMU,
  CMD_SLLI,
  CMD_SRXI,
  CMD_SRLI,
  CMD_SRAI,
  CMD_NOP,
  CMD_HINT,
  CMD_ECALL,
  CMD_MAX
};

typedef struct instruction
{
  COMMAND  cmd;
  unsigned src1_num;
  unsigned src2_num;
  unsigned dst_num;
  REG      src1_value;
  REG      src2_value;
  REG      dst_value;
  REG      imm_value;
  int      br_target;
  ADDRESS  pc;
  ADDRESS  mem_addr;
  unsigned mem_size;
  bool     mem_signed;
  bool     is_16bits;
  bool     is_w_type;
} INST;

const COMMAND imm_exe_tbl[8] =
{
  CMD_ADDI,
  CMD_SLLI,
  CMD_ADDI,
  CMD_SLTIU,
  CMD_XORI,
  CMD_SRXI,
  CMD_ADDI,
  CMD_ANDI 
};

const COMMAND br_exe_tbl[8] =
{
  CMD_BEQ,
  CMD_BNE,
  CMD_BGEU,
  CMD_BGEU,
  CMD_BLT,
  CMD_BGE,
  CMD_BLTU,
  CMD_BGEU
};

using namespace std;

const map<COMMAND, string> ExeClassString =
{
  {CMD_AUIPC, "AUIPC"},
  {CMD_BEQ, "BEQ"},
  {CMD_BGE, "BGE"},
  {CMD_BGEU, "BGEU"},
  {CMD_BLTU, "BLTU"},
  {CMD_BLT, "BLT"},
  {CMD_BNE, "BNE"},
  {CMD_DIVU, "DIVU"},
  {CMD_SUB, "SUB"},
  {CMD_LI, "LI"},
  {CMD_JAL, "JAL"},
  {CMD_JALR, "JALR"},
  {CMD_J, "J"},
  {CMD_ADD, "ADD"},
  {CMD_SLL, "SLL"},
  {CMD_SLTU, "SLTU"},
  {CMD_XOR, "XOR"},
  {CMD_ST, "ST"},
  {CMD_LD, "LD"},
  {CMD_MUL, "MUL"},
  {CMD_REMU, "CMD_REMU"},
  {CMD_SLLI, "SLLI"},
  {CMD_SRLI, "SRLI"},
  {CMD_SRAI, "SRAI"},
  {CMD_AND, "AND"},
  {CMD_OR, "OR"},
  {CMD_ANDI, "ANDI"},
  {CMD_ADDI, "ADDI"},
  {CMD_SLTIU, "SLTIU"},
  {CMD_XORI, "XORI"},
  {CMD_ECALL, "ECALL"},
  {CMD_NOP, "NOP"},
};

class EXECUTE
{
  public:

  void execute(INST* inst)
  {
    (this->*cmd_map.at(inst->cmd))(inst);
  }

  private:

  typedef void (EXECUTE::*Execute) (INST* inst);

  const map<COMMAND, Execute> cmd_map =
  {
    {CMD_AUIPC, &EXECUTE::exe_auipc},
    {CMD_BGE, &EXECUTE::exe_bge},
    {CMD_BGEU, &EXECUTE::exe_bgeu},
    {CMD_DIVU, &EXECUTE::exe_divu},
    {CMD_ADDI, &EXECUTE::exe_addi},
    {CMD_SLTIU, &EXECUTE::exe_sltiu},
    {CMD_XORI, &EXECUTE::exe_xori},
    {CMD_SUB, &EXECUTE::exe_sub},
    {CMD_LI, &EXECUTE::exe_li},
    {CMD_JAL, &EXECUTE::exe_jal},
    {CMD_JALR, &EXECUTE::exe_jalr},
    {CMD_J, &EXECUTE::exe_j},
    {CMD_AND, &EXECUTE::exe_and},
    {CMD_OR, &EXECUTE::exe_or},
    {CMD_ANDI, &EXECUTE::exe_andi},
    {CMD_BNE, &EXECUTE::exe_bne},
    {CMD_BEQ, &EXECUTE::exe_beq},
    {CMD_BLTU, &EXECUTE::exe_bltu},
    {CMD_BLT, &EXECUTE::exe_blt},
    {CMD_ADD, &EXECUTE::exe_add},
    {CMD_REMU, &EXECUTE::exe_remu},
    {CMD_SLL, &EXECUTE::exe_sll},
    {CMD_SLTU, &EXECUTE::exe_sltu},
    {CMD_XOR, &EXECUTE::exe_xor},
    {CMD_ST, &EXECUTE::exe_st},
    {CMD_LD, &EXECUTE::exe_ld},
    {CMD_MUL, &EXECUTE::exe_mul},
    {CMD_SLLI, &EXECUTE::exe_slli},
    {CMD_SRLI, &EXECUTE::exe_srli},
    {CMD_SRAI, &EXECUTE::exe_srai},
    {CMD_NOP, &EXECUTE::exe_nop},
    {CMD_HINT, &EXECUTE::exe_hint}
  };

  void exe_nop(INST* inst)
  {}

  void exe_hint(INST* inst)
  {}

  void exe_auipc(INST* inst)
  {
    inst->dst_value = inst->pc + inst->imm_value;
  }

  void exe_divu(INST* inst)
  {
    UREG src1 = (UREG)inst->src1_value;
    UREG src2 = (UREG)inst->src2_value;
    
    UREG result = src1 / src2;
    inst->dst_value = result;
  }

  void exe_addi(INST* inst)
  {
    inst->dst_value = inst->src1_value + inst->imm_value;
  }

  void exe_sltiu(INST* inst)
  {
    UREG src1 = (UREG)inst->src1_value;
    UREG src2 = (UREG)inst->imm_value;

    inst->dst_value = (src1 < src2)? 1 : 0;
  }

  void exe_xori(INST* inst)
  {
    inst->dst_value = inst->src1_value ^ inst->imm_value;
  }

  void exe_andi(INST* inst)
  {
    inst->dst_value = inst->src1_value & inst->imm_value;
  }

  void exe_slli(INST* inst)
  {
    inst->dst_value = inst->src1_value << inst->imm_value;
  }

  void exe_srli(INST* inst)
  {
    inst->dst_value = (UREG)inst->src1_value >> (UREG)inst->imm_value;
  }

  void exe_srai(INST* inst)
  {
    inst->dst_value = inst->src1_value >> inst->imm_value;
  }

  void exe_sub(INST* inst)
  {
    inst->dst_value = inst->src1_value - inst->src2_value;
  }

  void exe_li(INST* inst)
  {
    inst->dst_value = inst->imm_value;
  }

  void exe_jal(INST* inst)
  {
    inst->dst_value = inst->pc + 4;
    inst->br_target = inst->pc + inst->imm_value;
  }

  void exe_jalr(INST* inst)
  {
    if ( inst->is_16bits )
      inst->dst_value = inst->pc + 2;
    else
      inst->dst_value = inst->pc + 4;
    inst->br_target = inst->src1_value + inst->imm_value;
  }

  void exe_j(INST* inst)
  {
    inst->br_target = inst->pc + inst->imm_value;
  }

  void exe_bge(INST* inst)
  {
    if ( inst->src1_value >= inst->src2_value )
      inst->br_target = inst->pc + inst->imm_value;
  }

  void exe_bgeu(INST* inst)
  {
    UREG src1 = (UREG)inst->src1_value;
    UREG src2 = (UREG)inst->src2_value;

    if ( src1 >= src2 )
      inst->br_target = inst->pc + inst->imm_value;
  }

  void exe_bltu(INST* inst)
  {
    UREG src1 = (UREG)inst->src1_value;
    UREG src2 = (UREG)inst->src2_value;

    if ( src1 < src2 )
      inst->br_target = inst->pc + inst->imm_value;
  }

  void exe_blt(INST* inst)
  {
    if ( inst->src1_value < inst->src2_value )
      inst->br_target = inst->pc + inst->imm_value;
  }

  void exe_bne(INST* inst)
  {
    if ( inst->src1_value != inst->src2_value )
    {
      inst->br_target = inst->pc + inst->imm_value;
    }
  }

  void exe_beq(INST* inst)
  {
    if ( inst->src1_value == inst->src2_value )
      inst->br_target = inst->pc + inst->imm_value;
  }

  void exe_add(INST* inst)
  {
    inst->dst_value = inst->src1_value + inst->src2_value;
  }

  void exe_remu(INST* inst)
  {
    UREG src1 = (UREG)inst->src1_value;
    UREG src2 = (UREG)inst->src2_value;

    UREG result = src1 % src2;
    inst->dst_value = result;
  }

  void exe_sll(INST* inst)
  {
    inst->dst_value = inst->src1_value << (inst->src2_value & 0x3f);
  }

  void exe_sltu(INST* inst)
  {
    UREG src1 = (UREG)inst->src1_value;
    UREG src2 = (UREG)inst->src2_value;

    inst->dst_value = (src1 < src2)? 1 : 0;
  }

  void exe_xor(INST* inst)
  {
    inst->dst_value = inst->src1_value ^ inst->src2_value;
  }

  void exe_and(INST* inst)
  {
    inst->dst_value = inst->src1_value & inst->src2_value;
  }

  void exe_or(INST* inst)
  {
    inst->dst_value = inst->src1_value | inst->src2_value;
  }

  void exe_st(INST* inst)
  {
    inst->mem_addr = inst->src1_value + inst->imm_value;
  }

  void exe_ld(INST* inst)
  {
    inst->mem_addr = inst->src1_value + inst->imm_value;
  }

  void exe_mul(INST* inst)
  {
    inst->dst_value = inst->src1_value * inst->src2_value;
  }

}; // end of class EXECUTE

class DECODE
{
  public:

  void decode(INST* inst, OPCODE opcode)
  {
    // 32-bit OP
    if ( (opcode & 3) == 3 )
    {
      (this->*decode_32[opcode & 0x7f])(inst, opcode);
    }
    else // 16-bit OP
    {
      (this->*decode_16[((opcode >> 11) & 0x1c) | (opcode & 3)])(inst, opcode & 0xffff);
    }
  }

  private:

  typedef void (DECODE::*Decode)(INST* inst, OPCODE opcode);

  // instruction undefined
  void dec_none(INST* inst, OPCODE opcode)
  {
    cout << "Undefined Instruction " << opcode << endl;
    assert(0);
  }

  // 32 bit decode function
  void dec_i_type(INST* inst, OPCODE opcode)
  {
    inst->cmd  = imm_exe_tbl[GET_FUNC3(opcode)];
    
    if ( inst->cmd == CMD_SRXI )
    {
      if ( opcode >> 25 )
        inst->cmd = CMD_SRAI;
      else
        inst->cmd = CMD_SRLI;
    }

    inst->dst_num = GET_RD(opcode);
    inst->src1_num = GET_RS1(opcode);
    inst->imm_value = GET_IIMM(opcode);

    if ( (opcode & 0x7f) == 0x1b )
      inst->is_w_type = true;
    else
      assert( (opcode & 0x7f) == 0x13 );
  }

  void dec_b_type(INST* inst, OPCODE opcode)
  {
    inst->cmd  = br_exe_tbl[GET_FUNC3(opcode)];
    inst->src1_num = GET_RS1(opcode);
    inst->src2_num = GET_RS2(opcode);
    inst->imm_value = GET_BIMM(opcode);
  }

  void dec_r_type(INST* inst, OPCODE opcode)
  {
    unsigned func3 = GET_FUNC3(opcode);
    unsigned func7 = GET_FUNC7(opcode);

    if ( (opcode & 0x7f) == 0x3b )
      inst->is_w_type = true;
    else
      assert( (opcode & 0x7f) == 0x33 );

    if ( func3 == 0 )
    {
      if ( func7 == 0 )
        inst->cmd = CMD_ADD;
      else if ( func7 == 1 )
        inst->cmd = CMD_MUL;
      else if ( func7 == 0x20 )
        inst->cmd = CMD_SUB;
      else
        assert(0);
    }
    else if ( func3 == 1 )
    {
      assert(func7 == 0);
      inst->cmd = CMD_SLL;
    }
    else if ( func3 == 3 )
    {
      assert(func7 == 0);
      inst->cmd = CMD_SLTU;
    }
    else if ( func3 == 4 )
    {
      assert(func7 == 0);
      inst->cmd = CMD_XOR;
    }
    else if ( func3 == 5 )
    {
      if ( func7 == 1 )
        inst->cmd = CMD_DIVU;
    }
    else if ( func3 == 6 )
    {
      assert(func7 == 0);
      inst->cmd = CMD_OR;
    }
    else if ( func3 == 7 )
    {
      if ( func7 == 0 )
        inst->cmd = CMD_AND;
      else if ( func7 == 1 )
        inst->cmd = CMD_REMU;
    }
    else
      assert(0);

    inst->dst_num  = GET_RD(opcode);
    inst->src1_num = GET_RS1(opcode);
    inst->src2_num = GET_RS2(opcode);
  }

  void dec_lui(INST* inst, OPCODE opcode)
  {
    inst->cmd       = CMD_LI;
    inst->dst_num   = GET_RD(opcode);
    inst->imm_value = GET_UIMM(opcode);
  }

  void dec_auipc(INST* inst, OPCODE opcode)
  {
    inst->cmd       = CMD_AUIPC;
    inst->dst_num   = GET_RD(opcode);
    inst->imm_value = GET_UIMM(opcode);
  }

  void dec_jal(INST* inst, OPCODE opcode)
  {
    inst->cmd       = CMD_JAL;
    inst->dst_num   = GET_RD(opcode);
    inst->imm_value = GET_JIMM(opcode);
  }

  void dec_jalr(INST* inst, OPCODE opcode)
  {
    assert(GET_FUNC3(opcode) == 0);
  
    inst->cmd       = CMD_JALR;
    inst->dst_num   = GET_RD(opcode);
    inst->src1_num  = GET_RS1(opcode);
    inst->imm_value = GET_IIMM(opcode);
  }

  void dec_st(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_ST;
    inst->src1_num = GET_RS1(opcode);
    inst->src2_num = GET_RS2(opcode);
    inst->imm_value= GET_SIMM(opcode);
    inst->mem_size = 1 << GET_FUNC3(opcode);
  }
  
  void dec_ld(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_LD;
    inst->dst_num  = GET_RD(opcode);
    inst->src1_num = GET_RS1(opcode);
    inst->imm_value= GET_IIMM(opcode);
    inst->mem_size = 1 << (GET_FUNC3(opcode) & 3);
  }

  void dec_ecall(INST* inst, OPCODE opcode)
  {
    inst->cmd     = CMD_ECALL;
    inst->dst_num = 10;
  }

  // 16 bit decode function
  void dec_c_10001(INST* inst, OPCODE opcode)
  {
    (this->*decode_16_10001[((opcode >> 8) & 0x1c) | ((opcode >> 5) & 0x3)])(inst, opcode);
  }

  void dec_c_10010(INST* inst, OPCODE opcode)
  {
    if ( opcode & 0x1000 ) // bit 12 is one
    {
      if ( GET_C_RS1(opcode) )
      {
        if ( GET_C_RS2(opcode) )
        {
          inst->cmd      = CMD_ADD;
          inst->dst_num  = GET_C_RS1(opcode);
          inst->src1_num = GET_C_RS1(opcode);
          inst->src2_num = GET_C_RS2(opcode);
        }
        else // JALR
        {
          inst->cmd      = CMD_JALR;
          inst->src1_num = GET_C_RS1(opcode);
          inst->dst_num  = 1;
          inst->is_16bits= true;
          inst->imm_value= 0;
        }
      }
    }
    else // bit 12 is zero
    {
      if ( GET_C_RS1(opcode) )
      {
        if ( GET_C_RS2(opcode) )
        {
          inst->cmd      = CMD_ADDI;
          inst->src1_num = GET_C_RS2(opcode);
          inst->dst_num  = GET_C_RS1(opcode);
          inst->imm_value= 0;
        }
        else
        { // JR, set dst_num to X0
          inst->cmd      = CMD_JALR;
          inst->src1_num = GET_C_RS1(opcode);
          inst->dst_num  = 0;
          inst->imm_value= 0;
        }
      }
    }
  }

  void dec_c_sub(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_SUB;
    inst->dst_num  = GET_C_RS1_prime(opcode);
    inst->src1_num = GET_C_RS1_prime(opcode);
    inst->src2_num = GET_C_RS2_prime(opcode);
  }

  void dec_c_li(INST* inst, OPCODE opcode)
  {
    if ( GET_RD(opcode) )
    {
      inst->cmd       = CMD_LI;
      inst->dst_num   = GET_RD(opcode);
      inst->imm_value = GET_CIMM(opcode);
    }
    else
      dec_c_hint(inst, opcode);
  }

  void dec_c_hint(INST* inst, OPCODE opcode)
  {
    assert(0);
  }
  
  void dec_c_bnez(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_BNE;
    inst->src1_num = GET_C_RS1_prime(opcode);
    inst->src2_num = 0;
    inst->imm_value= GET_CBIMM(opcode);
  }

  void dec_c_beqz(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_BEQ;
    inst->src1_num = GET_C_RS1_prime(opcode);
    inst->src2_num = 0;
    inst->imm_value= GET_CBIMM(opcode);
  }

  void dec_c_j(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_J;
    inst->imm_value= GET_CJIMM(opcode);
  }

  void dec_c_andi(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_ANDI;
    inst->dst_num  = GET_C_RS1_prime(opcode);
    inst->src1_num = GET_C_RS1_prime(opcode);
    inst->imm_value= GET_CIMM(opcode);
  }

  void dec_c_and(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_AND;
    inst->dst_num  = GET_C_RS1_prime(opcode);
    inst->src1_num = GET_C_RS1_prime(opcode);
    inst->src2_num = GET_C_RS2_prime(opcode);
  }

  void dec_c_or(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_OR;
    inst->dst_num  = GET_C_RS1_prime(opcode);
    inst->src1_num = GET_C_RS1_prime(opcode);
    inst->src2_num = GET_C_RS2_prime(opcode);
  }

  void dec_c_addw(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_ADD;
    inst->dst_num  = GET_C_RS1_prime(opcode);
    inst->src1_num = GET_C_RS1_prime(opcode);
    inst->src2_num = GET_C_RS2_prime(opcode);
    inst->is_w_type= true;
  }

  void dec_c_subw(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_SUB;
    inst->dst_num  = GET_C_RS1_prime(opcode);
    inst->src1_num = GET_C_RS1_prime(opcode);
    inst->src2_num = GET_C_RS2_prime(opcode);
    inst->is_w_type= true;
  }

  void dec_c_addi(INST* inst, OPCODE opcode)
  {
    if ( GET_C_RS1(opcode) )
    {
      if ( GET_CIMM(opcode) != 0 )
      {
        inst->cmd      = CMD_ADDI;
        inst->dst_num  = GET_C_RS1(opcode);
        inst->src1_num = GET_C_RS1(opcode);
        inst->imm_value= GET_CIMM(opcode);
      }
      else
        inst->cmd = CMD_HINT;
    }
    else
      inst->cmd = CMD_NOP;
  }

  void dec_c_addi4spn(INST* inst, OPCODE opcode)
  {
    assert(opcode >> 5);

    inst->cmd      = CMD_ADDI;
    inst->dst_num  = GET_C_RS2_prime(opcode);
    inst->src1_num = 2;
    inst->imm_value= ((opcode >> 1) & 0x3c0) | ((opcode >> 7) & 0x30) | ((opcode >> 2) & 0x8) | ((opcode >> 4) & 0x4);
  }

  void dec_c_slli(INST* inst, OPCODE opcode)
  {
    if ( GET_C_RS1(opcode) && GET_BIT_5_0(opcode) )
    {
      inst->cmd      = CMD_SLLI;
      inst->dst_num  = GET_C_RS1(opcode);
      inst->src1_num = GET_C_RS1(opcode);
      inst->imm_value= GET_BIT_5_0(opcode);
    }
    else
      inst->cmd = CMD_HINT;
  }

  void dec_c_srli(INST* inst, OPCODE opcode)
  {
    if ( GET_BIT_5_0(opcode) )
    {
      inst->cmd      = CMD_SRLI;
      inst->dst_num  = GET_C_RS1_prime(opcode);
      inst->src1_num = GET_C_RS1_prime(opcode);
      inst->imm_value= GET_BIT_5_0(opcode);
    }
    else
      inst->cmd = CMD_HINT;
  }

  void dec_c_lui(INST* inst, OPCODE opcode)
  {
    int32_t imm = GET_CIMM(opcode);
    unsigned rd = GET_C_RS1(opcode);

    assert(imm != 0);

    if ( rd == 0 )
      inst->cmd = CMD_HINT;
    else if ( rd == 2 )
    {
      inst->cmd       = CMD_ADDI;
      inst->src1_num  = 2;
      inst->imm_value = (((REG)(((opcode >> 3) & 0x200) | ((opcode << 4) & 0x180) | ((opcode << 1) & 0x40) | ((opcode << 3) & 0x20) | ((opcode >> 2) & 0x10)) + 0x200 ) & 0x3ff ) - 0x200;
    }
    else
    {
      inst->cmd       = CMD_LI;
      inst->imm_value = imm << 12;
    }

    inst->dst_num   = rd;
  }

  void dec_c_addiw(INST* inst, OPCODE opcode)
  {
    assert(GET_C_RS1(opcode));
  
    inst->cmd      = CMD_ADDI;
    inst->dst_num  = GET_C_RS1(opcode);
    inst->src1_num = GET_C_RS1(opcode);
    inst->imm_value= GET_CIMM(opcode);
    inst->is_w_type= true;
  }

  void dec_c_sd(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_ST;
    inst->src1_num = GET_C_RS1_prime(opcode);
    inst->src2_num = GET_C_RS2_prime(opcode);
    inst->imm_value= ((opcode << 1) & 0xc0) | ((opcode >> 7) & 0x38);
    inst->mem_size = 8;
  }

  void dec_c_sdsp(INST* inst, OPCODE opcode)
  {
    inst->cmd      = CMD_ST;
    inst->src1_num = 2;
    inst->src2_num = GET_C_RS2(opcode);
    inst->imm_value= ((opcode >> 1) & 0x1c0) | ((opcode >> 7) & 0x38);
    inst->mem_size = 8;
  }

  void dec_c_lw(INST* inst, OPCODE opcode)
  {
    inst->cmd       = CMD_LD;
    inst->dst_num   = GET_C_RS2_prime(opcode);
    inst->src1_num  = GET_C_RS1_prime(opcode);
    inst->imm_value = ((opcode << 1) & 0x40) | ((opcode >> 7) & 0x38) | ((opcode >> 4) & 0x4);
    inst->mem_size  = 4;
    inst->mem_signed= true;
  }

  void dec_c_ld(INST* inst, OPCODE opcode)
  {
    inst->cmd       = CMD_LD;
    inst->dst_num   = GET_C_RS2_prime(opcode);
    inst->src1_num  = GET_C_RS1_prime(opcode);
    inst->imm_value = ((opcode << 1) & 0xc0) | ((opcode >> 7) & 0x38);
    inst->mem_size  = 8;
  }

  void dec_c_ldsp(INST* inst, OPCODE opcode)
  {
    assert(GET_C_RS1(opcode));

    inst->cmd       = CMD_LD;
    inst->dst_num   = GET_C_RS1(opcode);
    inst->src1_num  = 2;
    inst->imm_value = ((opcode << 4) & 0x1c0) | ((opcode >> 7) & 0x20) | ((opcode >> 2) & 0x18);
    inst->mem_size  = 8;
  }

  void dec_c_lwsp(INST* inst, OPCODE opcode)
  {
    assert(GET_C_RS1(opcode));

    inst->cmd       = CMD_LD;
    inst->dst_num   = GET_C_RS1(opcode);
    inst->src1_num  = 2;
    inst->imm_value = ((opcode << 4) & 0xc0) | ((opcode >> 7) & 0x20) | ((opcode >> 2) & 0x1c);
    inst->mem_size  = 4;
  }

  void dec_c_sw(INST* inst, OPCODE opcode)
  {
    inst->cmd       = CMD_ST;
    inst->src1_num  = GET_C_RS1_prime(opcode);
    inst->src2_num  = GET_C_RS2_prime(opcode);
    inst->imm_value = ((opcode << 1) & 0x40) | ((opcode >> 7) & 0x38) | ((opcode >> 4) & 0x4);
    inst->mem_size  = 4;
  }

  // bit 12 11 10 6 5
  const Decode decode_16_10001[32] =
  {
    // 0x00
    &DECODE::dec_c_srli,
    &DECODE::dec_c_srli,
    &DECODE::dec_c_srli,
    &DECODE::dec_c_srli,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_c_andi,
    &DECODE::dec_c_andi,
    &DECODE::dec_c_andi,
    &DECODE::dec_c_andi,
    &DECODE::dec_c_sub,
    &DECODE::dec_none,
    &DECODE::dec_c_or,
    &DECODE::dec_c_and,
    // 0x10
    &DECODE::dec_c_srli,
    &DECODE::dec_c_srli,
    &DECODE::dec_c_srli,
    &DECODE::dec_c_srli,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_c_andi,
    &DECODE::dec_c_andi,
    &DECODE::dec_c_andi,
    &DECODE::dec_c_andi,
    &DECODE::dec_c_subw,
    &DECODE::dec_c_addw,
    &DECODE::dec_none,
    &DECODE::dec_none
  };
  
  const Decode decode_32[128] =
  {
    // 0x00
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_ld,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    // 0x10
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_i_type,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_auipc,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_i_type,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    // 0x20
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_st,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    // 0x30
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_r_type,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_lui,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_r_type,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    // 0x40
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    // 0x50
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    // 0x60
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_b_type,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_jalr,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_jal,
    // 0x70
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_ecall,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_none
  };

  const Decode decode_16[32] =
  {
    // 0x00
    &DECODE::dec_c_addi4spn,
    &DECODE::dec_c_addi,
    &DECODE::dec_c_slli,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_c_addiw,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_c_lw,
    &DECODE::dec_c_li,
    &DECODE::dec_c_lwsp,
    &DECODE::dec_none,
    &DECODE::dec_c_ld,
    &DECODE::dec_c_lui,
    &DECODE::dec_c_ldsp,
    &DECODE::dec_none,
    // 0x10
    &DECODE::dec_none,
    &DECODE::dec_c_10001,
    &DECODE::dec_c_10010,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_c_j,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_c_sw,
    &DECODE::dec_c_beqz,
    &DECODE::dec_none,
    &DECODE::dec_none,
    &DECODE::dec_c_sd,
    &DECODE::dec_c_bnez,
    &DECODE::dec_c_sdsp,
    &DECODE::dec_none
  };
}; // end of class DECODE

class ELF
{
  public :

  ELF(int elf_file)
  {
    read(elf_file, &elf_head, sizeof(elf_head));
  
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
  
    if ( (elf_head.e_flags & EF_RISCV_FLOAT_ABI) == EF_RISCV_FLOAT_ABI_SOFT )
      elf_flags.insert("EF_RISCV_FLOAT_ABI_SOFT");
    else if ( (elf_head.e_flags & EF_RISCV_FLOAT_ABI) == EF_RISCV_FLOAT_ABI_SINGLE )
      elf_flags.insert("EF_RISCV_FLOAT_ABI_SINGLE");
    else if ( (elf_head.e_flags & EF_RISCV_FLOAT_ABI) == EF_RISCV_FLOAT_ABI_DOUBLE )
      elf_flags.insert("EF_RISCV_FLOAT_ABI_DOUBLE");
    else if ( (elf_head.e_flags & EF_RISCV_FLOAT_ABI) == EF_RISCV_FLOAT_ABI_QUAD )
      elf_flags.insert("EF_RISCV_FLOAT_ABI_QUAD");
  
    assert( sizeof(Elf64_Phdr) == elf_head.e_phentsize );
  }
  
  Elf64_Half get_phnum()
  {
    return elf_head.e_phnum;
  }

  Elf64_Off  get_phoff()
  {
    return elf_head.e_phoff;
  }
  
  ADDRESS    get_e_entry()
  {
    return elf_head.e_entry;
  }

  void print()
  {
    cout << "ELF Head :\n";
    cout << "  Class:\t" << elf_class << endl;
    cout << "  Encode:\t" << elf_encode << endl;
    cout << "  OS/ABI:\t" << elf_osabi << endl;
    cout << "  Type:\t\t" << elf_type << endl;
    cout << "  Machine:\t" << "RISC-V" << endl;
    cout << "  EntryPtr:\t" << showbase << hex << elf_head.e_entry << endl;
    cout << "  PHOffset:\t" << hex << elf_head.e_phoff << endl;
    cout << "  SHOffset:\t" << hex << elf_head.e_shoff << endl;
    
    cout << "  Flags:\t";
    for ( auto it : elf_flags )
      cout << it << " ";
    cout << endl;
  
    cout << "  HeadSize:\t" << noshowbase << dec << elf_head.e_ehsize << endl;
    cout << "  PHeadSize:\t" << elf_head.e_phentsize << endl;
    cout << "  PHeadNum:\t" << elf_head.e_phnum << endl;
    cout << "  SHeadSize:\t" << elf_head.e_shentsize << endl;
    cout << "  SHeadNum:\t" << elf_head.e_shnum << endl;
  }

  private :

  Elf64_Ehdr  elf_head;
  string      elf_class;
  string      elf_encode;
  string      elf_osabi;
  string      elf_type;
  set<string> elf_flags;
};

class MMU
{
  public :

  ADDRESS access_page_table(ADDRESS vaddr)
  {
    ADDRESS vpn = vaddr & 0xFFFFFFFFFFFFF000;

    if ( page_table.find(vpn) == page_table.end() )
    {
      ADDRESS ppn = (ADDRESS)calloc(0x1000, sizeof(char));
      page_table[vpn] = ppn;
    }
    
    return page_table[vpn] + (vaddr & 0xFFF);
  }

  private :

  map<ADDRESS , ADDRESS > page_table;
};

class MEM
{
  public :

  MEM(int elf_file, ELF elf, MMU* mmu)
  {
    this->mmu = mmu;

    lseek(elf_file, elf.get_phoff(), SEEK_SET);

    Elf64_Phdr* elf_phdrs = (Elf64_Phdr*) malloc( sizeof(Elf64_Phdr) * elf.get_phnum() );

    // Load Program Headers
    read(elf_file, elf_phdrs, sizeof(Elf64_Phdr) * elf.get_phnum());

    for( unsigned i = 0; i < elf.get_phnum(); i++ )
    {
      cout << hex << elf_phdrs[i].p_vaddr << endl;

      /*int protect = PROT_NONE;
      if ( elf_phdrs[i].p_flags & PF_X )
      protect |= PROT_EXEC;
      if ( elf_phdrs[i].p_flags & PF_W )
      protect |= PROT_WRITE;
      if ( elf_phdrs[i].p_flags & PF_R )
      protect |= PROT_READ;*/

      lseek(elf_file, elf_phdrs[i].p_offset, SEEK_SET);
      for ( unsigned j = 0; j < elf_phdrs[i].p_memsz; j++ )
      {
        char data;
        read(elf_file, &data, 1);

        ADDRESS vaddr = elf_phdrs[i].p_vaddr + j;
        ADDRESS paddr = mmu->access_page_table(vaddr);
        char* ptr = (char*)paddr;

        *ptr = data;
      }
    }
  }

  OPCODE get_opcode(ADDRESS pc)
  {
    if ( (pc & 0x3ff) == 0x3fe )
    {
      ADDRESS paddr = mmu->access_page_table(pc);
      OPCODE* opcode_lower = (OPCODE*) paddr;

      paddr = mmu->access_page_table(pc+2);
      OPCODE* opcode_upper = (OPCODE*) paddr;

      return ((*opcode_upper & 0xffff) << 16) | (*opcode_lower & 0xffff);
    }
    else
    {
      ADDRESS paddr = mmu->access_page_table(pc);
      OPCODE* opcode = (OPCODE*) paddr;
      return *opcode;
    }
  }

  template <typename T>
  T read_mem(ADDRESS vaddr)
  {
    ADDRESS paddr = mmu->access_page_table(vaddr);
    T* data = (T*)paddr;
    return *data;
  }
  
  template <typename T>
  void write_mem(ADDRESS vaddr, T st_data)
  {
    ADDRESS paddr = mmu->access_page_table(vaddr);
    T* data = (T*)paddr;
    *data = st_data;
  }

  private :

  MMU* mmu;
};

class CPU
{
  public :

  CPU(ELF elf, MMU* mmu, MEM* mem, int argc, char* argv[])
  {
    this->mmu = mmu;
    this->mem = mem;
    pc = elf.get_e_entry();
  
    // SP initial value
    reg[2] = 0x3ffffffb50;

    // Program Break initial value
    brk = 0x1f438;

    mem->write_mem<uint64_t>((ADDRESS)reg[2], (uint64_t)argc);
  
    cout << hex << "Execution PC : " << pc << endl;
  }
  
  void step()
  {
    reset_inst();
  
    OPCODE opcode = mem->get_opcode(pc);
  
    inst.pc = pc;
    if ( (opcode & 3) == 3) // 32-bit OP
      pc += 4;
    else
      pc += 2;
  
    decode.decode(&inst, opcode);
  
    read_reg(&inst);
  
    if ( inst.cmd == CMD_ECALL )
      execute_ecall();
    else
      execute.execute(&inst);
  
    if ( inst.cmd == CMD_LD )
    {
      if ( inst.mem_size == 8 )
        inst.dst_value = mem->read_mem<uint64_t>(inst.mem_addr);
      else if ( inst.mem_size == 4 )
      {
        REG data = mem->read_mem<uint32_t>(inst.mem_addr);
	if ( inst.mem_signed )
	{
          data = ((data + 0x80000000) & 0xffffffff) - 0x80000000;
	}
        inst.dst_value = data;
      }
      else if ( inst.mem_size == 2 )
        inst.dst_value = mem->read_mem<uint16_t>(inst.mem_addr);
      else if ( inst.mem_size == 1 )
        inst.dst_value = mem->read_mem<uint8_t>(inst.mem_addr);
      else
        assert(0);
    }
    else if ( inst.cmd == CMD_ST )
    {
      if ( inst.mem_size == 8 )
        mem->write_mem<uint64_t>(inst.mem_addr, (uint64_t)inst.src2_value);
      else if ( inst.mem_size == 4 )
        mem->write_mem<uint32_t>(inst.mem_addr, (uint32_t)inst.src2_value);
      else if ( inst.mem_size == 2 )
        mem->write_mem<uint16_t>(inst.mem_addr, (uint16_t)inst.src2_value);
      else if ( inst.mem_size == 1 )
        mem->write_mem<uint8_t>(inst.mem_addr, (uint8_t)inst.src2_value);
      else
        assert(0);
    }

    ADDRESS paddr = mmu->access_page_table(0xfee8758);
    uint64_t* data = (uint64_t*)paddr;
    //cout << "read data 0xfee8758 " << *data << endl;

    if ( inst.is_w_type )
      convert_to_w(&inst);
  
    if ( IS_NOT_ZR(inst.dst_num) )
      write_reg(&inst);
  
    if ( inst.br_target )
      pc = inst.br_target;
  
    print_inst();
  
  }
  
  void print_inst()
  {
    cout << " PC:" << inst.pc
         << " OPCODE:" << ExeClassString.at(inst.cmd)
         << " IMM_VALUE:" << inst.imm_value;
  
    if ( IS_NOT_ZR(inst.dst_num) )
      cout << " DST_NUM:" << inst.dst_num
           << " DST_VALUE:" << inst.dst_value;
  
    if ( inst.mem_addr )
      cout << " MEM_ADDR:" << inst.mem_addr;

    if ( inst.cmd == CMD_ST )
      cout << " MEM_DATA:" << inst.src2_value;
  
    if ( inst.br_target )
      cout << " BR_TARGET:" << inst.br_target;
  
    cout << endl;
  }
  
  private :

  ADDRESS pc;
  REG     reg[32] = {0};
  MMU*    mmu;
  MEM*    mem;
  INST    inst;
  REG     brk;

  void execute_ecall()
  {
    REG syscall_num  = reg[17];
    REG syscall_arg1 = reg[10];
    REG syscall_arg2 = reg[11];
    REG syscall_arg3 = reg[12];

    struct stat temp_stat;
    uint32_t st_mode;

    switch( syscall_num )
    {
      case 57 : // close
        // If the file descriptor is valid
        if ( fcntl((int)syscall_arg1, F_GETFD) )
	  inst.dst_value = close((int)syscall_arg1);
	else
	  inst.dst_value = 0;

	if ( inst.dst_value != 0 )
	  perror("close error");

        break;
      case 64 : // write
        syscall_arg2 = mmu->access_page_table((ADDRESS)syscall_arg2);

        inst.dst_value = write((int)syscall_arg1, (void*)syscall_arg2, (size_t)syscall_arg3);

        break;
      case 80 : // fstat
        syscall_arg2 = mmu->access_page_table((ADDRESS)syscall_arg2);
        
	inst.dst_value = fstat((int)syscall_arg1, &temp_stat);
        if ( inst.dst_value != 0 )
          perror("fstat error");
        
	memcpy((void*)syscall_arg2, &temp_stat, 128);
        // write mode_t 0x2190
        st_mode = 0x2190;
        memcpy((void*)(syscall_arg2 + 16), &st_mode, 4);
        
	break;
      case 93 : // exit
        exit((int)syscall_arg1);

	break;
      case 214 : // sbrk
        if ( syscall_arg1 == 0 )
	{
	}
	else
        {
	  brk = syscall_arg1;
        }
	
        inst.dst_value = brk;
	
	break;
      default :
        printf("Unsupported syscall number %ld, arg1 %lx, arg2 %lx, arg3 %lx\n", syscall_num, syscall_arg1,
	syscall_arg2, syscall_arg3);
        assert(0);
    }
  }
  
  void    convert_to_w(INST* inst)
  {
    inst->dst_value = ((inst->dst_value + 0x80000000) & 0xffffffff) - 0x80000000;
  }

  void    read_reg(INST* inst)
  {
    if ( IS_NOT_ZR(inst->src1_num) )
      inst->src1_value = reg[inst->src1_num];
    else
      inst->src1_value = 0;
  
    if ( IS_NOT_ZR(inst->src2_num) )
      inst->src2_value = reg[inst->src2_num];
    else
      inst->src2_value = 0;
  }
  
  void    write_reg(INST* inst)
  {
    reg[inst->dst_num] = inst->dst_value;
  }
  
  void    reset_inst()
  {
    inst.src1_num = 0;
    inst.src2_num = 0;
    inst.dst_num  = 0;
    inst.br_target= 0;
    inst.mem_addr = 0;
    inst.is_16bits= false;
    inst.is_w_type = false;
  }
  
  DECODE  decode;
  EXECUTE execute;
};

int main ( int argc, char* argv[] )
{
  if ( argc < 2 )
  {
    cout << "\tNo ELF file input. For instance :\n";
    cout << "\t\triscv elf/test\n";
    return -1;
  }

  int elf_file = open(argv[1], O_RDONLY);
  
  ELF elf = ELF(elf_file);
  elf.print();

  MMU* mmu = new MMU();
  MEM* mem = new MEM(elf_file, elf, mmu);

  char* argv_no_first[argc-1];
  for (unsigned i = 1; i < argc; i++)
    argv_no_first[i-1] = argv[i];

  CPU cpu = CPU(elf, mmu, mem, argc - 1, argv_no_first);

  for ( unsigned i = 0; i < 100000; i++ )
    cpu.step();

  return 0;
}

