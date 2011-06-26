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
    if (reg == "LR")
      this->value = REGISTER_LR;
    else if (reg == "CTR")
      this->value = REGISTER_CTR;
    else if (reg.length() == 3 && reg.compare(0, 2, "cr") == 0 &&
             reg[2] >= '0' && reg[2] <= '7')
      this->value = (enum_register) (REGISTER_CR0 + reg[2] - '0');

    if (this->value == REGISTER_UNSET)
      ERROR("Error: Unknown specialregister : '%s'\n", reg.c_str());
  }
}


Register::operator std::string ()
{
  int reg = this->value;

  if (reg >= 0 && reg <= 32)
    return "r" + tostr(reg);
  else if (reg == REGISTER_SP)
    return "sp";

  ERROR ("Error: Can't convert register to string : '%d'\n", reg);
  return "";
}

Register
parse_pointer (const string &ptr, int *offset)
{
  long int idx1 = ptr.find('(');
  long int idx2 = ptr.find(')');
  string reg;
  string value;

  if ((idx2 - idx1 - 1) > 5) {
    ERROR ("Error: Unable to parse pointer: %s\n", ptr.c_str());
    return REGISTER_UNSET;
  }
  reg = ptr.substr(idx1 + 1, idx2 - idx1 - 1);
  value = ptr.substr(0, idx1);
  idx1 = value.find("arg_");
  idx2 = value.find("var_");
  if (idx1 != -1)
    *offset = -strtol (value.c_str() + idx1, NULL, 16);
  else if (idx2 != -1)
    *offset = strtol (value.c_str() + idx2, NULL, 16);
  else
    *offset = strtol (value.c_str(), NULL, 16);

  return reg;
}
