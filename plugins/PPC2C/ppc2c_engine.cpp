/*
 * ppc2c.h -- PPC to C converter
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */
#include "ppc2c_engine.hpp"
#include <cstring>
#include <sstream>

#define INSTRUCTION_IS(x) (strcmp (ins.instruction, x) == 0)
#define HAS_NO_OPERAND (ins.operands[0] == NULL)
#define HAS_ONE_OPERAND (ins.operands[0] != NULL && ins.operands[1] == NULL)
#define HAS_TWO_OPERANDS (ins.operands[1] != NULL && ins.operands[2] == NULL)
#define HAS_THREE_OPERANDS (ins.operands[2] != NULL && ins.operands[3] == NULL)
#define HAS_FOUR_OPERANDS (ins.operands[3] != NULL && ins.operands[4] == NULL)
#define HAS_FIVE_OPERANDS (ins.operands[4] != NULL)


ConditionRegister cr[MAX_CR+1];

string tostr(int i) {
  std::ostringstream oss;
  oss << i;
  return oss.str();
}


Instruction::Instruction ()
{
  this->type = INSTRUCTION_TYPE_NONE;
  this->name = "";
  for (int i = 0; i < 5; i++)
    this->operands[i] = "";
}

Function::Function ()
{
  this->name = "";
  this->address = 0;
  this->arguments = 0;
  this->ret = false;
}

Register::Register (const string &reg)
{
  this->value = REGISTER_UNSET;
  if (reg[0] == '%') {
    switch (reg.length()) {
    case 3:
      if (reg == "%sp")
        this->value = REGISTER_SP;
      else if (reg[1] == 'r' && reg[2] >= '0' && reg[2] <= '9')
        this->value = (enum_register) (reg[2] - '0');
    case 4:
      if (reg[1] == 'r' && reg[2] >= '0' && reg[2] <= '9'
          && reg[3] >= '0' && reg[3] <= '9') {
        int r = (reg[2] - '0') * 10 + (reg[3] - '0');
        if (r <= 32)
          this->value = (enum_register) r;
      }
    case 5:
      if (reg == "%rtoc")
        this->value = REGISTER_RTOC;
    default:
      if (this->value == REGISTER_UNSET)
        ERROR("Error: Unknown register : '%s'\n", reg.c_str());
    }
  } else {
    if (reg == "LR" || reg == "lr")
      this->value = REGISTER_LR;
    else if (reg == "CTR" || reg == "ctr")
      this->value = REGISTER_CTR;
    else if (reg.length() == 3 && reg.compare(0, 2, "cr") == 0 &&
             reg[2] >= '0' && reg[2] <= '7')
      this->value = (enum_register) (REGISTER_CR0 + reg[2] - '0');

	if (this->value == REGISTER_UNSET) {
      //ERROR("Error: Unknown special register : '%s'\n", reg.c_str());
		this->str = reg;
	}
  }
}


Register::operator std::string ()
{
  int reg = this->value;

  if (reg >= 0 && reg <= 32)
    return "r" + tostr(reg);
  else if (reg == REGISTER_SP)
    return "sp";
  else if (reg == REGISTER_LR)
    return "LR";
  else if (reg == REGISTER_CTR)
    return "CTR";

  //ERROR ("Error: Can't convert register to string : '%d'\n", reg);
  return this->str;
}

Register
parse_pointer (ea_t ea, int operand, ea_t &offset)
{
  ua_ana0(ea);
  if (cmd.Operands[operand].type != o_displ)
	  return REGISTER_UNSET;
  offset = cmd.Operands[operand].addr;
  return cmd.Operands[operand].reg;
}
