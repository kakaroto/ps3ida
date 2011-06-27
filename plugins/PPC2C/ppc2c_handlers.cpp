/*
 * ppc_handelrs.h -- Handlers for PPC instructions
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include "ppc2c_handlers.hpp"

bool PPCAsm2C(ea_t ea, char* buff, int buffSize);
void
handle_ppc2c_instructions (Function &func, Instruction &ins, HandlerResult *result)
{
  char buffer[1024];
  result->out_reg = result->in_reg1 = result->in_reg2 = REGISTER_UNSET;

  if (PPCAsm2C(ins.address, buffer, sizeof(buffer)))
    result->c_code = buffer;
  else
	result->c_code = " /* Error handling PPCAsm2C */";
}

void
handle_preproc_set (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = result->in_reg1 = result->in_reg2 = REGISTER_UNSET;

  result->c_code = "#define " + ins.operands[0] + ins.operands[1];
}

void
handle_stdu (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = result->out_reg;
  result->in_reg2 = REGISTER_UNSET;

  assert (result->out_reg == REGISTER_SP);

  /* TODO: modify the stack */
  result->c_code = "";
}


void
handle_mflr (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = REGISTER_LR;
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = string (result->out_reg) + " = LR";
}

void
handle_mr (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = string (result->out_reg) + " = " + string (result->in_reg1);
}

void
handle_mfspr (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = REGISTER_UNSET;

  if (result->in_reg1 != REGISTER_LR)
    ERROR ("MFSPR: Unrecognized special register : " + result->in_reg1);

  result->c_code = string(result->out_reg) + " = LR";
}

void
handle_mtlr (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = "LR = " + string (result->in_reg1);
}

void
handle_mtspr (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = REGISTER_UNSET;

  if (result->in_reg1 == REGISTER_LR)
    result->c_code = "  LR = " + string (result->in_reg1);
  else
    ERROR ("MFSPR: Unrecognized special register : " + result->in_reg1);
}


void
handle_std (Function &func, Instruction &ins, HandlerResult *result)
{
  ea_t offset;

  result->out_reg = parse_pointer (ins.address, 1, offset);
  result->in_reg1 = ins.operands[0];
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = string (result->out_reg) + "[" + tostr(offset) + "] = " +
    string (result->in_reg1);
}

void
handle_lbz (Function &func, Instruction &ins, HandlerResult *result)
{
  ea_t offset;

  result->out_reg = ins.operands[0];
  result->in_reg1 = parse_pointer (ins.address, 1, offset);
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = string (result->out_reg) + " = ((uint8_t *)" +
    string (result->in_reg1) + ")[" + tostr(offset) + "]";
}

void
handle_lwz (Function &func, Instruction &ins, HandlerResult *result)
{
  ea_t offset;

  result->out_reg = ins.operands[0];
  result->in_reg1 = parse_pointer (ins.address, 1, offset);
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = string (result->out_reg) + " = ((uint32_t *)";
  if (offset > 0)
    result->c_code += "(" + string (result->in_reg1) + " + " + tostr(offset) + ")";
  else
    result->c_code += string (result->in_reg1);
  result->c_code += ")[0]";
}

void
handle_li (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = REGISTER_UNSET;
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = string (result->out_reg) + " = " + ins.operands[1];
}

void
handle_lis (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = REGISTER_UNSET;
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = string(result->out_reg) + " = " + ins.operands[1] + " << 16";
}

void
handle_add (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = ins.operands[2];

  result->c_code = string (result->out_reg) + " = " +
    string (result->in_reg1) + " + " + string (result->in_reg2);
}

void
handle_addi (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = string (result->out_reg) + " = " +
    string (result->in_reg1) + " + " + ins.operands[2];
}

void
handle_addis (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = string (result->out_reg) + " = (" +
    string (result->in_reg1) + " + " + ins.operands[2] + ") << 16";
}

void
handle_or (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = ins.operands[2];

  result->c_code = string (result->out_reg) + " = " +
    string (result->in_reg1) + " | " + string (result->in_reg2);
}

void
handle_ori (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = string (result->out_reg) + " = " +
    string (result->in_reg1) + " | " + ins.operands[2];
}

void
handle_oris (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = REGISTER_UNSET;

  result->c_code = string (result->out_reg) + " = (" +
    string (result->in_reg1) + " | " + ins.operands[2] + ") << 16";
}


void
handle_xor (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = ins.operands[2];

  result->c_code = string (result->out_reg) + " = " +
    string (result->in_reg1) + " ^ " + string (result->in_reg2);
}

void
handle_and (Function &func, Instruction &ins, HandlerResult *result)
{
  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = ins.operands[2];

  result->c_code = string (result->out_reg) + " = " +
    string (result->in_reg1) + " & " + string (result->in_reg2);
}

void
handle_cmpw (Function &func, Instruction &ins, HandlerResult *result)
{
  ConditionRegister *crX;

  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = ins.operands[2];
  result->c_code = "";

  assert (result->out_reg >= REGISTER_CR0 && result->out_reg <= REGISTER_CR7);

  crX = &cr[result->out_reg - REGISTER_CR0];

  crX->reg = result->in_reg1;
  crX->size = REGISTER_SIZE_WORD;
  crX->immediate = false;
  crX->_signed = true;
  crX->cmp_reg = result->in_reg2;
}

void
handle_cmplw (Function &func, Instruction &ins, HandlerResult *result)
{
  ConditionRegister *crX;

  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = ins.operands[2];
  result->c_code = "";

  assert (result->out_reg >= REGISTER_CR0 && result->out_reg <= REGISTER_CR7);

  crX = &cr[result->out_reg - REGISTER_CR0];

  crX->reg = result->in_reg1;
  crX->size = REGISTER_SIZE_WORD;
  crX->immediate = false;
  crX->_signed = false;
  crX->cmp_reg = result->in_reg2;
}

void
handle_cmpwi (Function &func, Instruction &ins, HandlerResult *result)
{
  ConditionRegister *crX;

  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = REGISTER_UNSET;
  result->c_code = "";

  assert (result->out_reg >= REGISTER_CR0 && result->out_reg <= REGISTER_CR7);

  crX = &cr[result->out_reg - REGISTER_CR0];

  crX->reg = result->in_reg1;
  crX->size = REGISTER_SIZE_WORD;
  crX->immediate = true;
  crX->_signed = true;
  crX->cmp_imm = strtol (ins.operands[2].c_str(), NULL, 0);
}

void
handle_cmplwi (Function &func, Instruction &ins, HandlerResult *result)
{
  ConditionRegister *crX;

  result->out_reg = ins.operands[0];
  result->in_reg1 = ins.operands[1];
  result->in_reg2 = REGISTER_UNSET;
  result->c_code = "";

  assert (result->out_reg >= REGISTER_CR0 && result->out_reg <= REGISTER_CR7);

  crX = &cr[result->out_reg - REGISTER_CR0];

  crX->reg = result->in_reg1;
  crX->size = REGISTER_SIZE_WORD;
  crX->immediate = true;
  crX->_signed = false;
  crX->cmp_imm = strtol (ins.operands[2].c_str(), NULL, 0);
}


#if 0
proc cmpd {cr reg1 reg2} {
    return "$cr = (uint64) [reg_to_var $reg1] - (uint64) [reg_to_var $reg2];"
}


proc ble {cr to} {
    return "if ($cr <= 0) goto $to;"
}
proc bgt {cr to} {
    return "if ($cr > 0) goto $to;"
}
proc slwi {to from pos} {
    return "[reg_to_var $to] = [reg_to_var $from] << $pos;"
}
proc rldicl {to from rotate clear} {
    set bmask [string repeat "0" $clear]
    append bmask [string repeat "1" [expr 64 - $clear]]
    binary scan [binary format B* $bmask] H* mask
    return "[reg_to_var $to] = ([reg_to_var $from] << $rotate) & $mask;"
}
proc srawi {dst src val} {
    return "[reg_to_var $dst] = [reg_to_var $src] >> $val;"
}
proc subf {dst src from} {
    return "[reg_to_var $dst] = [reg_to_var $from] - [reg_to_var $src];"
}

proc beq {cr to} {
    return "if ($cr == 0) goto $to;"
}
proc bne {cr to} {
    return "if ($cr != 0) goto $to;"
}
proc bne+ {cr to} {
    return "if ($cr != 0) goto $to;"
}
proc bl {to} {
    return "$to ();"
}
proc ld {reg ptr} {
    return "[reg_to_var $reg] = [ptr_to_val $ptr];"
}
proc stw {reg ptr} {
    return "[ptr_to_val $ptr] = (uint32) [reg_to_var $reg];"
}
proc blr {} {
    return "return;"
}
proc nop {} {
    return ""
}
proc extsw {dst src} {
    return "[reg_to_var $dst] = (uint64) [reg_to_var $src];"
}

#endif
