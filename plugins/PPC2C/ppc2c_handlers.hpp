/*
 * ppc_handelrs.h -- Handlers for PPC instructions
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#ifndef __PPC_HANDLERS_H__
#define __PPC_HANDLERS_H__

#include "ppc2c_engine.hpp"
#include <string>

typedef struct {
  string c_code;
  Register out_reg;
  Register in_reg1;
  Register in_reg2;
} HandlerResult;

typedef struct {
  const char *instruction;
  InstructionType type;
  bool (*check_operands) (Instruction *);
  void (*handler) (Instruction *, HandlerResult *);
} InstructionSet;

static inline bool has_no_operand (Instruction *ins) {
  return (ins->operands[0] == "");
}
static inline bool has_one_operand (Instruction *ins) {
  return (ins->operands[0] != "" && ins->operands[1] == "");
}
static inline bool has_two_operands (Instruction *ins) {
  return (ins->operands[1] != "" && ins->operands[2] == "");
}
static inline bool has_three_operands (Instruction *ins) {
  return (ins->operands[2] != "" && ins->operands[3] == "");
}
static inline bool has_four_operands (Instruction *ins) {
  return (ins->operands[3] != "" && ins->operands[4] == "");
}
static inline bool has_five_operands (Instruction *ins) {
  return (ins->operands[4] != "");
}
static inline bool has_variable_operands (Instruction *ins) {
  (void)ins;
  return true;
}

void handle_preproc_set (Instruction *ins, HandlerResult *result);
void handle_stdu (Instruction *ins, HandlerResult *result);
void handle_mr (Instruction *ins, HandlerResult *result);
void handle_mflr (Instruction *ins, HandlerResult *result);
void handle_mfspr (Instruction *ins, HandlerResult *result);
void handle_mtlr (Instruction *ins, HandlerResult *result);
void handle_mtspr (Instruction *ins, HandlerResult *result);
void handle_std (Instruction *ins, HandlerResult *result);
void handle_lbz (Instruction *ins, HandlerResult *result);
void handle_lwz (Instruction *ins, HandlerResult *result);
void handle_li (Instruction *ins, HandlerResult *result);
void handle_lis (Instruction *ins, HandlerResult *result);
void handle_add (Instruction *ins, HandlerResult *result);
void handle_addi (Instruction *ins, HandlerResult *result);
void handle_addis (Instruction *ins, HandlerResult *result);
void handle_or (Instruction *ins, HandlerResult *result);
void handle_ori (Instruction *ins, HandlerResult *result);
void handle_oris (Instruction *ins, HandlerResult *result);
void handle_xor (Instruction *ins, HandlerResult *result);
void handle_and (Instruction *ins, HandlerResult *result);


static const InstructionSet instruction_set[] = {
  {"set", INSTRUCTION_TYPE_PREPROCESSOR, has_two_operands, handle_preproc_set},
  {"stdu", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_stdu},
  {"mr", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_mr},
  {"mflr", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_mflr},
  {"mfspr", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_mfspr},
  {"mtlr", INSTRUCTION_TYPE_INSTRUCTION, has_one_operand, handle_mtlr},
  {"mtspr", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_mtspr},
  {"std", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_std},
  {"lbz", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_lbz},
  {"lwz", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_lwz},
  {"li", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_li},
  {"lis", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_lis},
  {"add", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_add},
  {"addi", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_addi},
  {"addis", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_addis},
  {"or", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_or},
  {"ori", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_ori},
  {"oris", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_oris},
  {"xor", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_xor},
  {"and", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_and},
  {NULL, INSTRUCTION_TYPE_NONE, NULL, NULL}
};
  /*{"", INSTRUCTION_TYPE_INSTRUCTION, has__operands, handle_},*/

#endif /* __PPC_HANDLERS_H__ */
