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
  bool (*check_operands) (Instruction&);
  void (*handler) (Function &, Instruction&, HandlerResult *);
} InstructionSet;

static inline bool has_no_operand (Instruction &ins) {
  return (ins.operands[0] == "");
}
static inline bool has_one_operand (Instruction &ins) {
  return (ins.operands[0] != "" && ins.operands[1] == "");
}
static inline bool has_two_operands (Instruction &ins) {
  return (ins.operands[1] != "" && ins.operands[2] == "");
}
static inline bool has_three_operands (Instruction &ins) {
  return (ins.operands[2] != "" && ins.operands[3] == "");
}
static inline bool has_four_operands (Instruction &ins) {
  return (ins.operands[3] != "" && ins.operands[4] == "");
}
static inline bool has_five_operands (Instruction &ins) {
  return (ins.operands[4] != "");
}
static inline bool has_variable_operands (Instruction &ins) {
  (void)ins; // Please be happy Mr. Compiler!!
  return true;
}

void handle_ppc2c_instructions (Function &func, Instruction &ins, HandlerResult *result);
void handle_preproc_set (Function &func, Instruction &ins, HandlerResult *result);
void handle_stdu (Function &func, Instruction &ins, HandlerResult *result);
void handle_mr (Function &func, Instruction &ins, HandlerResult *result);
void handle_mflr (Function &func, Instruction &ins, HandlerResult *result);
void handle_mfspr (Function &func, Instruction &ins, HandlerResult *result);
void handle_mtlr (Function &func, Instruction &ins, HandlerResult *result);
void handle_mtspr (Function &func, Instruction &ins, HandlerResult *result);
void handle_std (Function &func, Instruction &ins, HandlerResult *result);
void handle_lbz (Function &func, Instruction &ins, HandlerResult *result);
void handle_lwz (Function &func, Instruction &ins, HandlerResult *result);
void handle_li (Function &func, Instruction &ins, HandlerResult *result);
void handle_lis (Function &func, Instruction &ins, HandlerResult *result);
void handle_add (Function &func, Instruction &ins, HandlerResult *result);
void handle_addi (Function &func, Instruction &ins, HandlerResult *result);
void handle_addis (Function &func, Instruction &ins, HandlerResult *result);
void handle_or (Function &func, Instruction &ins, HandlerResult *result);
void handle_ori (Function &func, Instruction &ins, HandlerResult *result);
void handle_oris (Function &func, Instruction &ins, HandlerResult *result);
void handle_xor (Function &func, Instruction &ins, HandlerResult *result);
void handle_and (Function &func, Instruction &ins, HandlerResult *result);
void handle_cmpw (Function &func, Instruction &ins, HandlerResult *result);
void handle_cmplw (Function &func, Instruction &ins, HandlerResult *result);
void handle_cmpwi (Function &func, Instruction &ins, HandlerResult *result);
void handle_cmplwi (Function &func, Instruction &ins, HandlerResult *result);


static const InstructionSet instruction_set[] = {
  {"set", INSTRUCTION_TYPE_PREPROCESSOR, has_two_operands, handle_preproc_set},
  {"stdu", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_stdu},
  {"mr", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_mr},
  {"mflr", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_mflr},
  {"mfspr", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_mfspr},
  {"mtlr", INSTRUCTION_TYPE_INSTRUCTION, has_two_operands, handle_mtlr},
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
  {"cmpw", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_cmpw},
  {"cmplw", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_cmplw},
  {"cmpwi", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_cmpwi},
  {"cmplwi", INSTRUCTION_TYPE_INSTRUCTION, has_three_operands, handle_cmplwi},
  // PPCAsm2C functions
  {"bc", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"clrlwi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"clrrwi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"clrlslwi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"extlwi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"extrwi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"inslwi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"insrwi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rlwimi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rlwinm", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rlwnm", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rotlw", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rotlwi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rotrwi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"slwi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"srwi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"clrldi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"clrrdi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"clrlsldi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"extldi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"extrdi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"insrdi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rotld", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rotldi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rotrdi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rldcl", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rldcr", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rldic", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rldicl", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rldicr", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"rldimi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"sldi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {"srdi", INSTRUCTION_TYPE_INSTRUCTION, has_variable_operands, handle_ppc2c_instructions},
  {NULL, INSTRUCTION_TYPE_NONE, NULL, NULL}
};
  /*{"", INSTRUCTION_TYPE_INSTRUCTION, has__operands, handle_},*/

#endif /* __PPC_HANDLERS_H__ */
