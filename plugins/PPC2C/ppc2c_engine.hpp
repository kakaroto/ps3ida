/*
 * ppc2c.h -- PPC to C converter
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __PPC2C_HPP__
#define __PPC2C_HPP__

#include <ida.hpp>
#include <idp.hpp>

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <string>
#include <list>

using namespace std;

typedef enum {
  REGISTER_UNSET = -1,
  REGISTER_R0 = 0,
  REGISTER_R1,
  REGISTER_R2,
  REGISTER_R3,
  REGISTER_R4,
  REGISTER_R5,
  REGISTER_R6,
  REGISTER_R7,
  REGISTER_R8,
  REGISTER_R9,
  REGISTER_R10,
  REGISTER_R11,
  REGISTER_R12,
  REGISTER_R13,
  REGISTER_R14,
  REGISTER_R15,
  REGISTER_R16,
  REGISTER_R17,
  REGISTER_R18,
  REGISTER_R19,
  REGISTER_R20,
  REGISTER_R21,
  REGISTER_R22,
  REGISTER_R23,
  REGISTER_R24,
  REGISTER_R25,
  REGISTER_R26,
  REGISTER_R27,
  REGISTER_R28,
  REGISTER_R29,
  REGISTER_R30,
  REGISTER_R31,
  REGISTER_R32,
  REGISTER_R0_TO_R10,
  REGISTER_SP,
  REGISTER_LR,
  REGISTER_CTR,
  REGISTER_CR0,
  REGISTER_CR1,
  REGISTER_CR2,
  REGISTER_CR3,
  REGISTER_CR4,
  REGISTER_CR5,
  REGISTER_CR6,
  REGISTER_CR7,
} enum_register;
#define REGISTER_RTOC REGISTER_R2

class Register {
public:
  Register() { this->value = REGISTER_UNSET;};
  Register(int reg) { this->value = (enum_register) reg;};
  Register(const string &reg);
  operator int () {return this->value;};
  operator string ();
private:
  enum_register value;
};

typedef enum {
  INSTRUCTION_TYPE_NONE = 0,
  INSTRUCTION_TYPE_PREPROCESSOR,
  INSTRUCTION_TYPE_INSTRUCTION,
  INSTRUCTION_TYPE_COMMENT,
  INSTRUCTION_TYPE_INLINE_COMMENT,
  INSTRUCTION_TYPE_LABEL,
  INSTRUCTION_TYPE_FLOW,
} InstructionType;


class Instruction {
public:
  Instruction();
  ea_t address;
  InstructionType type;
  string name;
  string operands[5];
};

class Function {
public:
  Function();
  string name;
  ea_t address;
  ea_t end_address;
  int arguments;
  bool ret;
  list<Instruction> instructions;
};

typedef enum {
  REGISTER_SIZE_BYTE,
  REGISTER_SIZE_SHORT,
  REGISTER_SIZE_WORD,
  REGISTER_SIZE_QWORD,
} RegisterSize;

class ConditionRegister {
public:
  ConditionRegister() {};
  Register reg; // Register to compare
  RegisterSize size; // size of comparison
  bool immediate; // whether or not it's an immediate comparison
  bool _signed; // whether or not the comparison is arithmetic or logical
  uval_t cmp_imm; // Immediate value to compare
  Register cmp_reg; // Second register to compare
};

#define MAX_CR 7
extern ConditionRegister cr[MAX_CR + 1];

#ifdef NODEBUG
#define DEBUG(...) {}
#else
#define DEBUG(...) msg (__VA_ARGS__)
#endif

#define ERROR(...)							        \
  {										            \
    warning(__VA_ARGS__);							    \
    /*exit (-1);*/                                  \
  }

string tostr(int);
Register parse_pointer (const string &ptr, int *offset);


#endif /* __PPC2C_HPP__ */
