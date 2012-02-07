/*
 *
 * PowerPC to C conversion framework
 *
 * This plugin includes a Conversion framework in order to analyze and
 * convert PPC instructions into their equivalent C code
 * This plugin will recurisvely convert a function into compilable C code
 *
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 * This payload is a modified version of the original PSJailbreak's payload.
 * The people behing PSJailbrak are the original authors and copyright holders
 * of the code they wrote.
 */


#ifdef NO_OBSOLETE_FUNCS
#undef NO_OBSOLETE_FUNCS
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <auto.hpp>
#include <ua.hpp>

#include <time.h>
#include <list>
#include <set>

#include "ppc2c_engine.hpp"
#include "ppc2c_handlers.hpp"

static list<Function> functions;

#define PPC2C_VERSION	"v0.1"


#if 1

#define MASK32_ALLSET	0xFFFFFFFF
#define MASK64_ALLSET	0xFFFFFFFFFFFFFFFFULL


#define G_STR_SIZE	256
char g_mnem[G_STR_SIZE];
char g_opnd_s0[G_STR_SIZE];
char g_opnd_s1[G_STR_SIZE];
char g_opnd_s2[G_STR_SIZE];
char g_opnd_s3[G_STR_SIZE];
char g_opnd_s4[G_STR_SIZE];

char g_RA[G_STR_SIZE];
char g_RS[G_STR_SIZE];
char g_RB[G_STR_SIZE];
int g_SH;
int g_MB;
int g_ME;


// generates the mask between MaskBegin(MB) and MaskEnd(ME) inclusive
// MB and ME should be values 0 - 31
unsigned int GenerateMask32(int MB, int ME)
{
  if(	MB <  0 || ME <  0 ||
                         MB > 31 || ME > 31 )
    {
      msg("PPC2C: Error with paramters GenerateMask32(%d, %d)\n", MB, ME);
      return 0;
    }
	
  unsigned int mask = 0;
  if(MB < ME+1)
    {
      // normal mask
      for(int i=MB; i<=ME; i=i+1)
        {
          mask = mask | (1<<(31-i));
        }
    }
  else if(MB == ME+1)
    {
      // all mask bits set
      mask = MASK32_ALLSET;
    }
  else if(MB > ME+1)
    {
      // split mask
      unsigned int mask_lo = GenerateMask32(0, ME);
      unsigned int mask_hi = GenerateMask32(MB, 31);
      mask = mask_lo | mask_hi;
    }
	
  return mask;
}

// generates the mask between MaskBegin(MB) and MaskEnd(ME) inclusive
// MB and ME should be values 0 - 63
unsigned long long GenerateMask64(int MB, int ME)
{
  if(	MB <  0 || ME <  0 ||
                         MB > 63 || ME > 63 )
    {
      msg("PPC2C: Error with paramters GenerateMask64(%d, %d)\n", MB, ME);
      return 0;
    }
	
  unsigned long long mask = 0;
  if(MB < ME+1)
    {
      // normal mask
      for(int i=MB; i<=ME; i=i+1)
        {
          mask = mask | (unsigned long long)(1ULL<<(63-i));
        }
    }
  else if(MB == ME+1)
    {
      // all mask bits set
      mask = MASK64_ALLSET;
    }
  else if(MB > ME+1)
    {
      // split mask
      unsigned long long mask_lo = GenerateMask64(0, ME);
      unsigned long long mask_hi = GenerateMask64(MB, 63);
      mask = mask_lo | mask_hi;
    }
	
  return mask;
}

// generate string showing rotation or shifting within instruction
// returns:	true if string requires brackets if a mask is used, ie: (r4 << 2) & 0xFF
bool GenerateRotate32(char* buff, int buffSize, const char* src, int leftShift, int rightShift, unsigned int& mask)
{
  // work out "rotate" part of the instruction
  if(	leftShift== 0 && rightShift==32 ||
        leftShift==32 && rightShift== 0 )
    {
      qsnprintf(buff, buffSize, "%s", src);
      return false;
    }
	
  if(((MASK32_ALLSET<<leftShift ) & mask) == 0)
    {
      // right shift only
      if((MASK32_ALLSET>>rightShift) == mask)
        mask = MASK32_ALLSET;
      qsnprintf(buff, buffSize, "%s >> %d", src, rightShift);
    }
  else if(((MASK32_ALLSET>>rightShift) & mask) == 0)
    {
      // left shift only
      if((MASK32_ALLSET<<leftShift) == mask)
        mask = MASK32_ALLSET;
      qsnprintf(buff, buffSize, "%s << %d", src, leftShift);
    }
  else
    {
      // shift both ways
      qsnprintf(buff, buffSize, "(%s << %d) | (%s >> %d)", src, leftShift, src, rightShift);
    }
  return true;
}

// generate string showing rotation or shifting within instruction
// returns:	true if string requires brackets if a mask is used, ie: (r4 << 2) & 0xFF
bool GenerateRotate64(char* buff, int buffSize, const char* src, int leftShift, int rightShift, unsigned long long& mask)
{
  // work out "rotate" part of the instruction
  if(	leftShift== 0 && rightShift==64 ||
        leftShift==64 && rightShift== 0 )
    {
      // no rotation
      qsnprintf(buff, buffSize, "%s", src);
      return false;
    }
	
  if(((MASK64_ALLSET<<leftShift ) & mask) == 0)
    {
      // right shift only
      if((MASK64_ALLSET>>rightShift) == mask)
        mask = MASK64_ALLSET;
      qsnprintf(buff, buffSize, "%s >> %d", src, rightShift);
    }
  else if(((MASK64_ALLSET>>rightShift) & mask) == 0)
    {
      // left shift only
      if((MASK64_ALLSET<<leftShift) == mask)
        mask = MASK64_ALLSET;
      qsnprintf(buff, buffSize, "%s << %d", src, leftShift);
    }
  else
    {
      // shift both ways
      qsnprintf(buff, buffSize, "(%s << %d) | (%s >> %d)", src, leftShift, src, rightShift);
    }
  return true;
}




// register rotate and immediate mask
bool Rotate_iMask32(ea_t ea, char* buff, int buffSize,
                    const char* leftRotate, int mb, int me)
{
  // calculate the mask
  // if no mask, then result is always 0
  unsigned int mask = GenerateMask32(mb, me);
  if(mask == 0)
    {
      // no rotation
      qsnprintf(buff, buffSize, "%s = 0", g_RA);
      return true;
    }
	
  // work out "rotate" part of the instruction
  // if all mask bits are set, then no need to use the mask
  char rot_str[G_STR_SIZE];
  qsnprintf(rot_str, sizeof(rot_str), "(%s << %s) | (%s >> 32-%s)", g_RS, leftRotate, g_RS, leftRotate);
  if(mask == MASK32_ALLSET)
    {
      //qsnprintf(buff, buffSize, "%s = (u32)(%s)", g_RA, rot_str);
      qsnprintf(buff, buffSize, "%s = %s", g_RA, rot_str);
      return true;
    }
	
  // generate mask string
  char mask_str[G_STR_SIZE];
  qsnprintf(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", mask);
	
  // generate the resultant string
  qsnprintf(buff, buffSize, "%s = (%s) & %s", g_RA, rot_str, mask_str);
  return true;
}

// immediate rotate and immediate mask
bool iRotate_iMask32(ea_t ea, char* buff, int buffSize,
                     int leftRotate, int mb, int me)
{
  // calculate the mask
  // if no mask, then result is always 0
  unsigned int mask = GenerateMask32(mb, me);
  if(mask == 0)
    {
      qsnprintf(buff, buffSize, "%s = 0", g_RA);
      return true;
    }
	
  // work out "rotate" part of the instruction
  // if all mask bits are set, then no need to use the mask
  char rot_str[G_STR_SIZE];
  bool brackets = GenerateRotate32(rot_str, sizeof(rot_str), g_RS, leftRotate, 32-leftRotate, mask);
  if(mask == MASK32_ALLSET)
    {
      //		if(brackets)
      //			qsnprintf(buff, buffSize, "%s = (u32)(%s)", g_RA, rot_str);
      //		else
      //			qsnprintf(buff, buffSize, "%s = (u32)%s", g_RA, rot_str);
      qsnprintf(buff, buffSize, "%s = %s", g_RA, rot_str);
      return true;
    }
	
  //	MASK32_ALLSET << leftRotate
	
  // generate mask string
  char mask_str[G_STR_SIZE];
  qsnprintf(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", mask);
	
  // generate the resultant string
  if(brackets)
    qsnprintf(buff, buffSize, "%s = (%s) & %s", g_RA, rot_str, mask_str);
  else
    qsnprintf(buff, buffSize, "%s = %s & %s", g_RA, rot_str, mask_str);
  return true;
}

// insert immediate rotate and immediate mask
bool insert_iRotate_iMask32(ea_t ea, char* buff, int buffSize,
                            int leftRotate, int mb, int me)
{
  // calculate the mask
  // if no mask, then result is the untouched target register
  unsigned int mask = GenerateMask32(mb, me);
  if(mask == 0)
    {
      qsnprintf(buff, buffSize, "%s = %s", g_RA, g_RA);
      return true;
    }
	
  // work out "rotate" part of the instruction
  // if all mask bits are set, then no need to use the mask
  char rot_str[G_STR_SIZE];
  unsigned int rot_mask = mask;
  bool brackets = GenerateRotate32(rot_str, sizeof(rot_str), g_RS, leftRotate, 32-leftRotate, rot_mask);
	
  // generate mask strings
  char mask_str[G_STR_SIZE];
  qsnprintf(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", mask);
  char rot_mask_str[G_STR_SIZE];
  qsnprintf(rot_mask_str, sizeof(rot_mask_str), "%s%X", (rot_mask<0xA)?"":"0x", rot_mask);
  //	unsigned int not_mask = ~mask;
  //	char not_mask_str[G_STR_SIZE];
  //	qsnprintf(not_mask_str, sizeof(not_mask_str), "%s%X", (not_mask<0xA)?"":"0x", not_mask);
	
  // generate the resultant string
  if(mask == MASK32_ALLSET)
    {
      qsnprintf(buff, buffSize, "%s = %s | %s", g_RA, g_RA, rot_str);
      return true;
    }
  else if(rot_mask == MASK32_ALLSET)
    {
      if(brackets)
        qsnprintf(buff, buffSize, "%s = (%s & ~%s) | (%s)", g_RA,
                  g_RA, mask_str,
                  rot_str);
      else
        qsnprintf(buff, buffSize, "%s = (%s & ~%s) | %s", g_RA,
                  g_RA, mask_str,
                  rot_str);
    }
  else
    {
      if(brackets)
        qsnprintf(buff, buffSize, "%s = (%s & ~%s) | ((%s) & %s)", g_RA,
                  g_RA, mask_str,
                  rot_str, rot_mask_str);
      else
        qsnprintf(buff, buffSize, "%s = (%s & ~%s) | (%s & %s)", g_RA,
                  g_RA, mask_str,
                  rot_str, rot_mask_str);
    }
  return true;
}

bool gen_rlwimi(ea_t ea, char* buff, int buffSize,
                int leftRotate, int mb, int me)
{
  return insert_iRotate_iMask32(ea, buff, buffSize, leftRotate, mb, me);
}

bool gen_rlwinm(ea_t ea, char* buff, int buffSize,
                int leftRotate, int mb, int me)
{
  return iRotate_iMask32(ea, buff, buffSize, leftRotate, mb, me);
}

bool gen_rlwnm(ea_t ea, char* buff, int buffSize,
               const char* leftRotate, int mb, int me)
{
  return Rotate_iMask32(ea, buff, buffSize, leftRotate, mb, me);
}



// register rotate and immediate mask
bool Rotate_iMask64(ea_t ea, char* buff, int buffSize,
                    const char* leftRotate, int mb, int me)
{
  // calculate the mask
  // if no mask, then result is always 0
  unsigned long long mask = GenerateMask64(mb, me);
  if(mask == 0)
    {
      qsnprintf(buff, buffSize, "%s = 0", g_RA);
      return true;
    }
	
  // work out "rotate" part of the instruction
  // if all mask bits are set, then no need to use the mask
  char rot_str[G_STR_SIZE];
  qsnprintf(rot_str, sizeof(rot_str), "(%s << %s) | (%s >> 64-%s)", g_RS, leftRotate, g_RS, leftRotate);
  if(mask == MASK64_ALLSET)
    {
      qsnprintf(buff, buffSize, "%s = %s", g_RA, rot_str);
      return true;
    }
	
  // generate mask string
  char mask_str[G_STR_SIZE];
  if(mask>>32 == 0)
    qsnprintf(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", (unsigned long)mask);
  else
    qsnprintf(mask_str, sizeof(mask_str), "%s%X%08X", (mask<0xA)?"":"0x", (unsigned long)(mask>>32), (unsigned long)mask);
	
  // generate the resultant string
  qsnprintf(buff, buffSize, "%s = (%s) & %s", g_RA, rot_str, mask_str);
  return true;
}

// immediate rotate and immediate mask
bool iRotate_iMask64(ea_t ea, char* buff, int buffSize,
                     int leftRotate, int mb, int me)
{
  // calculate the mask
  // if no mask, then result is always 0
  unsigned long long mask = GenerateMask64(mb, me);
  if(mask == 0)
    {
      qsnprintf(buff, buffSize, "%s = 0", g_RA);
      return true;
    }
	
  // work out "rotate" part of the instruction
  // if all mask bits are set, then no need to use the mask
  char rot_str[G_STR_SIZE];
  bool brackets = GenerateRotate64(rot_str, sizeof(rot_str), g_RS, leftRotate, 64-leftRotate, mask);
  if(mask == MASK64_ALLSET)
    {
      qsnprintf(buff, buffSize, "%s = %s", g_RA, rot_str);
      return true;
    }
	
  // generate mask string
  char mask_str[G_STR_SIZE];
  if(mask>>32 == 0)
    qsnprintf(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", (unsigned long)mask);
  else
    qsnprintf(mask_str, sizeof(mask_str), "%s%X%08X", (mask<0xA)?"":"0x", (unsigned long)(mask>>32), (unsigned long)mask);
	
  // generate the resultant string
  if(brackets)
    qsnprintf(buff, buffSize, "%s = (%s) & %s", g_RA, rot_str, mask_str);
  else
    qsnprintf(buff, buffSize, "%s = %s & %s", g_RA, rot_str, mask_str);
  return true;
}

// insert immediate rotate and immediate mask
bool insert_iRotate_iMask64(ea_t ea, char* buff, int buffSize,
                            int leftRotate, int mb, int me)
{
  // calculate the mask
  // if no mask, then result is the untouched target register
  unsigned long long mask = GenerateMask64(mb, me);
  if(mask == 0)
    {
      qsnprintf(buff, buffSize, "%s = %s", g_RA, g_RA);
      return true;
    }
	
  // work out "rotate" part of the instruction
  // if all mask bits are set, then no need to use the mask
  char rot_str[G_STR_SIZE];
  unsigned long long rot_mask = mask;
  bool brackets = GenerateRotate64(rot_str, sizeof(rot_str), g_RS, leftRotate, 64-leftRotate, rot_mask);
	
  // generate mask string
  char mask_str[G_STR_SIZE];
  if(mask>>32 == 0)
    qsnprintf(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", (unsigned long)mask);
  else
    qsnprintf(mask_str, sizeof(mask_str), "%s%X%08X", (mask<0xA)?"":"0x", (unsigned long)(mask>>32), (unsigned long)mask);
  char rot_mask_str[G_STR_SIZE];
  if(rot_mask>>32 == 0)
    qsnprintf(rot_mask_str, sizeof(rot_mask_str), "%s%X", (rot_mask<0xA)?"":"0x", (unsigned long)rot_mask);
  else
    qsnprintf(rot_mask_str, sizeof(rot_mask_str), "%s%X%08X", (rot_mask<0xA)?"":"0x", (unsigned long)(rot_mask>>32), (unsigned long)rot_mask);
  //	unsigned long long not_mask = ~mask;
  //	char not_mask_str[G_STR_SIZE];
  //	if(not_mask>>32 == 0)
  //		qsnprintf(not_mask_str, sizeof(not_mask_str), "%s%X", (not_mask<0xA)?"":"0x", (unsigned long)not_mask);
  //	else
  //		qsnprintf(not_mask_str, sizeof(not_mask_str), "%s%X%08X", (not_mask<0xA)?"":"0x", (unsigned long)(not_mask>>32), (unsigned long)not_mask);
	
  // generate the resultant string
  if(mask == MASK64_ALLSET)
    {
      qsnprintf(buff, buffSize, "%s = %s", g_RA, rot_str);
    }
  else if(rot_mask == MASK64_ALLSET)
    {
      if(brackets)
        qsnprintf(buff, buffSize, "%s = (%s & ~%s) | (%s)", g_RA,
                  g_RA, mask_str,
                  rot_str);
      else
        qsnprintf(buff, buffSize, "%s = (%s & ~%s) | %s", g_RA,
                  g_RA, mask_str,
                  rot_str);
    }
  else
    {
      if(brackets)
        qsnprintf(buff, buffSize, "%s = (%s & ~%s) | ((%s) & %s)", g_RA,
                  g_RA, mask_str,
                  rot_str, rot_mask_str);
      else
        qsnprintf(buff, buffSize, "%s = (%s & ~%s) | (%s & %s)", g_RA,
                  g_RA, mask_str,
                  rot_str, rot_mask_str);
    }
  return true;
}





// ==================================================================
//
// instructions
//
// ==================================================================


bool bc(ea_t ea, char* buff, int buffSize)
{
  // Branch Conditional
  // bc BO,BI,target_addr
  char BO_str[G_STR_SIZE] = "";
  char BI_str[G_STR_SIZE] = "";
  char target_addr[G_STR_SIZE] = "";
  char cr_str[G_STR_SIZE] = "cr0";
  char condition_str[G_STR_SIZE] = "";
  int BO = 0;
	
  if( strlen(g_opnd_s2) )
    {
      // 3 args
      qstrncpy(BO_str, g_opnd_s0, sizeof(BO_str));
      qstrncpy(BI_str, g_opnd_s1, sizeof(BI_str));
      qstrncpy(target_addr, g_opnd_s2, sizeof(target_addr));
		
      BO = atol(BO_str);
      if( strncmp(BI_str, "4*", 2) == 0 )
        {
          qstrncpy(cr_str, BI_str+2, 4);
          qstrncpy(condition_str, BI_str+6, 3);
        }
      else
        qstrncpy(condition_str, BI_str, 3);
    }
  else if( strlen(g_opnd_s1) )
    {
      // 2 args. can you have 2 args?
      qstrncpy(target_addr, g_opnd_s1, sizeof(target_addr));
    }
  else
    {
      // 1 arg. can you have only 1 arg?
      qstrncpy(target_addr, g_opnd_s0, sizeof(target_addr));
    }
	
  if(		strcmp(condition_str, "lt")==0) qstrncpy(condition_str, "less than", sizeof(condition_str));
  else if(strcmp(condition_str, "le")==0) qstrncpy(condition_str, "less than or equal", sizeof(condition_str));
  else if(strcmp(condition_str, "eq")==0) qstrncpy(condition_str, "equal", sizeof(condition_str));
  else if(strcmp(condition_str, "ge")==0) qstrncpy(condition_str, "greater than or equal", sizeof(condition_str));
  else if(strcmp(condition_str, "gt")==0) qstrncpy(condition_str, "greater than", sizeof(condition_str));
	
  else if(strcmp(condition_str, "nl")==0) qstrncpy(condition_str, "not less than", sizeof(condition_str));
  else if(strcmp(condition_str, "ne")==0) qstrncpy(condition_str, "not equal", sizeof(condition_str));
  else if(strcmp(condition_str, "ng")==0) qstrncpy(condition_str, "not greater than", sizeof(condition_str));
  else if(strcmp(condition_str, "so")==0) qstrncpy(condition_str, "summary overflow", sizeof(condition_str));
  else if(strcmp(condition_str, "ns")==0) qstrncpy(condition_str, "not summary overflow", sizeof(condition_str));
  else if(strcmp(condition_str, "un")==0) qstrncpy(condition_str, "unordered", sizeof(condition_str));
  else if(strcmp(condition_str, "nu")==0) qstrncpy(condition_str, "not unordered", sizeof(condition_str));

  if(		(BO & 0x1E) == 0x00)
    {
      // decrement the CTR, then branch if the decremented CTR(M:63) != 0 and CR(BI) == 0
      qsnprintf(buff, buffSize, "ctr--; if(ctr != 0 && %s is not %s) goto %s", cr_str, condition_str, target_addr);
    }
  else if((BO & 0x1E) == 0x02)
    {
      // decrement the CTR, then branch if the decremented CTR(M:63) == 0 and CR(BI) == 0
      qsnprintf(buff, buffSize, "ctr--; if(ctr == 0 && %s is not %s) goto %s", cr_str, condition_str, target_addr);
    }
  else if((BO & 0x1C) == 0x04)
    {
      // branch if CR(BI) == 0
      qsnprintf(buff, buffSize, "if(%s is not %s) goto %s", cr_str, condition_str, target_addr);
    }
  else if((BO & 0x1E) == 0x08)
    {
      // decrement the CTR, then branch if the decremented CTR(M:63) != 0 and CR(BI) == 1
      qsnprintf(buff, buffSize, "ctr--; if(ctr != 0 && %s is %s) goto %s", cr_str, condition_str, target_addr);
    }
  else if((BO & 0x1E) == 0x0A)
    {
      // decrement the CTR, then branch if the decremented CTR(M:63) == 0 and CR(BI) == 1
      qsnprintf(buff, buffSize, "ctr--; if(ctr == 0 && %s is %s) goto %s", cr_str, condition_str, target_addr);
    }
  else if((BO & 0x1C) == 0x0C)
    {
      // branch if CR(BI) == 1
      qsnprintf(buff, buffSize, "if(%s is %s) goto %s", cr_str, condition_str, target_addr);
    }
  else if((BO & 0x1C) == 0x10)
    {
      // decrement the CTR, then branch if the decremented CTR(M:63) != 0
      qsnprintf(buff, buffSize, "ctr--; if(ctr != 0) goto %s", target_addr);
    }
  else if((BO & 0x1C) == 0x12)
    {
      // decrement the CTR, then branch if the decremented CTR(M:63) == 0
      qsnprintf(buff, buffSize, "ctr--; if(ctr == 0) goto %s", target_addr);
    }
  else if((BO & 0x1C) == 0x14)
    {
      // branch always
      qsnprintf(buff, buffSize, "goto %s", target_addr);
    }
	
  return true;
}


bool clrlwi(ea_t ea, char* buff, int buffSize)
{
  // Clear left immediate
  // clrlwi RA, RS, n   (n < 32)
  // rlwinm RA, RS, 0, n, 31
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = 0;
  g_MB = n;
  g_ME = 31;
	
  return gen_rlwinm(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool clrrwi(ea_t ea, char* buff, int buffSize)
{
  // Clear right immediate
  // clrrwi RA, RS, n   (n < 32)
  // rlwinm RA, RS, 0, 0, 31-n
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = 0;
  g_MB = 0;
  g_ME = 31-n;

  return gen_rlwinm(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool clrlslwi(ea_t ea, char* buff, int buffSize)
{
  // Clear left and shift left immediate
  // clrlslwi RA, RS, b, n   (n <= b < 32)
  // rlwinm RA, RS, n, b-n, 31-n
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int b = atol(g_opnd_s2);
  int n = atol(g_opnd_s3);
  g_SH = n;
  //	g_MB = 31;
  //	g_ME = 31-b;
  g_MB = b-n;
  g_ME = 31-n;
	
  return gen_rlwinm(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool extlwi(ea_t ea, char* buff, int buffSize)
{
  // Extract and left justify immediate
  // extlwi RA, RS, n, b   (n > 0)
  // rlwinm RA, RS, b, 0, n-1
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  int b = atol(g_opnd_s3);
  g_SH = b;
  g_MB = 0;
  g_ME = n-1;
	
  return gen_rlwinm(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool extrwi(ea_t ea, char* buff, int buffSize)
{
  // Extract and right justify immediate
  // extrwi RA, RS, n, b   (n > 0)
  // rlwinm RA, RS, b+n, 32-n, 31
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  int b = atol(g_opnd_s3);
  g_SH = b+n;
  g_MB = 32-n;
  g_ME = 31;
	
  return gen_rlwinm(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool inslwi(ea_t ea, char* buff, int buffSize)
{
  // Insert from left immediate
  // inslwi RA, RS, n, b   (n > 0)
  // rlwimi RA, RS, 32-b, b, (b+n)-1
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  int b = atol(g_opnd_s3);
  g_SH = 32-b;
  g_MB = b;
  g_ME = (b+n)-1;
	
  return gen_rlwimi(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool insrwi(ea_t ea, char* buff, int buffSize)
{
  // Insert from right immediate
  // insrwi RA, RS, n, b   (n > 0)
  // rlwimi RA, RS, 32-(b+n), b, (b+n)-1
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  int b = atol(g_opnd_s3);
  g_SH = 32-(b+n);
  g_MB = b;
  g_ME = (b+n)-1;
	
  return gen_rlwimi(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool rlwimi(ea_t ea, char* buff, int buffSize)
{
  // Rotate Left Word Immediate Then Mask Insert
  // rlwimi RA, RS, SH, MB, ME
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  g_SH = atol(g_opnd_s2);
  g_MB = atol(g_opnd_s3);
  g_ME = atol(g_opnd_s4);
	
  return gen_rlwimi(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool rlwinm(ea_t ea, char* buff, int buffSize)
{
  // Rotate Left Word Immediate Then AND with Mask
  // rlwinm RA, RS, SH, MB, ME
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  g_SH = atol(g_opnd_s2);
  g_MB = atol(g_opnd_s3);
  g_ME = atol(g_opnd_s4);
	
  return gen_rlwinm(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool rlwnm(ea_t ea, char* buff, int buffSize)
{
  // Rotate Left Word Then AND with Mask
  // rlwnm RA, RS, RB, MB, ME
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  qstrncpy(g_RB, g_opnd_s2, sizeof(g_RB));
  g_MB = atol(g_opnd_s3);
  g_ME = atol(g_opnd_s4);
	
  return gen_rlwnm(ea, buff, buffSize, g_RB, g_MB, g_ME);
}

bool rotlw(ea_t ea, char* buff, int buffSize)
{
  // Rotate left
  // rotlw RA, RS, RB
  // rlwnm RA, RS, RB, 0, 31
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  qstrncpy(g_RB, g_opnd_s2, sizeof(g_RB));
  g_MB = 0;
  g_ME = 31;
	
  return gen_rlwnm(ea, buff, buffSize, g_RB, g_MB, g_ME);
}

bool rotlwi(ea_t ea, char* buff, int buffSize)
{
  // Rotate left immediate
  // rotlwi RA, RS, n
  // rlwinm RA, RS, n, 0, 31
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = n;
  g_MB = 0;
  g_ME = 31;
	
  return gen_rlwinm(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool rotrwi(ea_t ea, char* buff, int buffSize)
{
  // Rotate right immediate
  // rotrwi RA, RS, n
  // rlwinm RA, RS, 32-n, 0, 31
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = 32-n;
  g_MB = 0;
  g_ME = 31;
	
  return gen_rlwinm(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool slwi(ea_t ea, char* buff, int buffSize)
{
  // Shift left immediate
  // slwi RA, RS, n   (n < 32)
  // rlwinm RA, RS, n, 0, 31-n
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = n;
  g_MB = 0;
  g_ME = 31-n;
	
  // fix the mask values because no mask is required when doing "slwi"
  return gen_rlwinm(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool srwi(ea_t ea, char* buff, int buffSize)
{
  // Shift right immediate
  // srwi RA, RS, n   (n < 32)
  // rlwinm RA, RS, 32-n, n, 31
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = 32-n;
  g_MB = n;
  g_ME = 31;
	
  // fix the mask values because no mask is required when doing "slwi"
  return gen_rlwinm(ea, buff, buffSize, g_SH, g_MB, g_ME);
}






// Rotate Left Double Word then Clear Left
// rldcl RA, RS, RB, MB
bool gen_rldcl(ea_t ea, char* buff, int buffSize,
               const char* leftRotate, int mb, int me)
{
  return Rotate_iMask64(ea, buff, buffSize, leftRotate, mb, me);
}

// Rotate Left Double Word then Clear Right
// rldcr RA, RS, RB, MB
bool gen_rldcr(ea_t ea, char* buff, int buffSize,
               const char* leftRotate, int mb, int me)
{
  return gen_rldcl(ea, buff, buffSize, leftRotate, me, mb);
}

// Rotate Left Double Word Immediate then Clear
// rldic RA, RS, SH, MB
bool gen_rldic(ea_t ea, char* buff, int buffSize,
               int leftRotate, int mb, int me)
{
  return iRotate_iMask64(ea, buff, buffSize, leftRotate, mb, me);
}

// Rotate Left Double Word Immediate then Clear Left
// rldicl RA, RS, SH, MB
bool gen_rldicl(ea_t ea, char* buff, int buffSize,
                int leftRotate, int mb, int me)
{
  return iRotate_iMask64(ea, buff, buffSize, leftRotate, mb, me);
}

// Rotate Left Double Word Immediate then Clear Right
// rldicr RA, RS, SH, ME
bool gen_rldicr(ea_t ea, char* buff, int buffSize,
                int leftRotate, int mb, int me)
{
  return iRotate_iMask64(ea, buff, buffSize, leftRotate, mb, me);
}

// Rotate Left Double Word Immediate then Mask Insert
// rldimi RA, RS, SH, MB
bool gen_rldimi(ea_t ea, char* buff, int buffSize,
                int leftRotate, int mb, int me)
{
  return insert_iRotate_iMask64(ea, buff, buffSize, leftRotate, mb, me);
}



// 64bit instructions

bool clrldi(ea_t ea, char* buff, int buffSize)
{
  // Clear left immediate
  // clrldi RA, RS, n   (n < 64)
  // rldicl RA, RS, 0, n
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = 0;
  g_MB = n;
  g_ME = 63;
	
  return gen_rldicl(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool clrrdi(ea_t ea, char* buff, int buffSize)
{
  // Clear right immediate
  // clrrdi RA, RS, n   (n < 64)
  // rldicr RA, RS, 0, 63-n
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = 0;
  g_MB = 0;
  g_ME = 63-n;
	
  return gen_rldicr(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool clrlsldi(ea_t ea, char* buff, int buffSize)
{
  // Clear left and shift left immediate
  // clrlsldi RA, RS, b, n   (n <= b < 64)
  // rldic RA, RS, n, b-n
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int b = atol(g_opnd_s2);
  int n = atol(g_opnd_s3);
  g_SH = n;
  g_MB = b-n;
  g_ME = 63-n;
	
  return gen_rldic(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool extldi(ea_t ea, char* buff, int buffSize)
{
  // Extract and left justify immediate
  // extldi RA, RS, n, b   (n > 0)
  // rldicr RA, RS, b, n-1
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  int b = atol(g_opnd_s3);
  g_SH = b;
  g_MB = 0;
  g_ME = n-1;
	
  return gen_rldicr(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool extrdi(ea_t ea, char* buff, int buffSize)
{
  // Extract and right justify immediate
  // extrdi RA, RS, n, b   (n > 0)
  // rldicl RA, RS, b+n, 64-n
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  int b = atol(g_opnd_s3);
  g_SH = b+n;
  g_MB = 64-n;
  g_ME = 63;
	
  return gen_rldicl(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool insrdi(ea_t ea, char* buff, int buffSize)
{
  // Insert from right immediate
  // insrdi RA, RS, n, b   (n > 0)
  // rldimi RA, RS, 64-(b+n), b
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  int b = atol(g_opnd_s3);
  g_SH = 64-(b+n);
  g_MB = b;
  g_ME = 63 - g_SH;
	
  return gen_rldimi(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool rotld(ea_t ea, char* buff, int buffSize)
{
  // Rotate left
  // rotld RA, RS, RB
  // rldcl RA, RS, RB, 0
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  qstrncpy(g_RB, g_opnd_s2, sizeof(g_RB));
  g_MB = 0;
  g_ME = 63;
	
  return gen_rldcl(ea, buff, buffSize, g_RB, g_MB, g_ME);
}

bool rotldi(ea_t ea, char* buff, int buffSize)
{
  // Rotate left immediate
  // rotldi RA, RS, n
  // rldicl RA, RS, n, 0
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = n;
  g_MB = 0;
  g_ME = 63;
	
  return gen_rldicl(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool rotrdi(ea_t ea, char* buff, int buffSize)
{
  // ate right immediate
  // rotrdi RA, RS, n
  // rldicl RA, RS, 64-n, 0
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = 64-n;
  g_MB = 0;
  g_ME = 63;
	
  return gen_rldicl(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool rldcl(ea_t ea, char* buff, int buffSize)
{
  // Rotate Left Double Word then Clear Left
  // rldcl RA, RS, RB, MB
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  qstrncpy(g_RB, g_opnd_s2, sizeof(g_RB));
  g_MB = atol(g_opnd_s3);
  g_ME = 63;
	
  return gen_rldcl(ea, buff, buffSize, g_RB, g_MB, g_ME);
}

bool rldcr(ea_t ea, char* buff, int buffSize)
{
  // Rotate Left Double Word then Clear Right
  // rldcr RA, RS, RB, ME
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  qstrncpy(g_RB, g_opnd_s2, sizeof(g_RB));
  g_MB = 0;
  g_ME = atol(g_opnd_s3);
	
  return gen_rldcr(ea, buff, buffSize, g_RB, g_MB, g_ME);
}

bool rldic(ea_t ea, char* buff, int buffSize)
{
  // Rotate Left Double Word Immediate then Clear
  // rldic RA, RS, SH, MB
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  g_SH = atol(g_opnd_s2);
  g_MB = atol(g_opnd_s3);
  g_ME = 63 - g_SH;
	
  return gen_rldic(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool rldicl(ea_t ea, char* buff, int buffSize)
{
  // Rotate Left Double Word Immediate then Clear Left
  // rldicl RA, RS, SH, MB
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  g_SH = atol(g_opnd_s2);
  g_MB = atol(g_opnd_s3);
  g_ME = 63;
	
  return gen_rldicl(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool rldicr(ea_t ea, char* buff, int buffSize)
{
  // Rotate Left Double Word Immediate then Clear Right
  // rldicr RA, RS, SH, ME
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  g_SH = atol(g_opnd_s2);
  g_MB = 0;
  g_ME = atol(g_opnd_s3);

  return gen_rldicr(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool rldimi(ea_t ea, char* buff, int buffSize)
{
  // Rotate Left Double Word Immediate then Mask Insert
  // rldimi RA, RS, SH, MB
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  g_SH = atol(g_opnd_s2);
  g_MB = atol(g_opnd_s3);
  g_ME = 63 - g_SH;
	
  return gen_rldimi(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool sldi(ea_t ea, char* buff, int buffSize)
{
  // Shift left immediate
  // sldi RA, RS, n   (n < 64)
  // rldicr RA, RS, n, 63-n
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = n;
  g_MB = 0;
  g_ME = 63-n;
	
  return gen_rldimi(ea, buff, buffSize, g_SH, g_MB, g_ME);
}

bool srdi(ea_t ea, char* buff, int buffSize)
{
  // Shift right immediate
  // srdi RA, RS, n   (n < 64)
  // rldicl RA, RS, 64-n, n
  qstrncpy(g_RA, g_opnd_s0, sizeof(g_RA));
  qstrncpy(g_RS, g_opnd_s1, sizeof(g_RS));
  int n = atol(g_opnd_s2);
  g_SH = 64-n;
  g_MB = n;
  g_ME = 63;
	
  return gen_rldimi(ea, buff, buffSize, g_SH, g_MB, g_ME);
}



// try to do as much work in this function as possible in order to 
// simplify each "instruction" handling function
bool PPCAsm2C(ea_t ea, char* buff, int buffSize)
{

	// make sure address is valid and that it points to the start of an instruction
	if(ea == BADADDR)
		return false;
	if( !isCode(get_flags_novalue(ea)) )
		return false;
	*buff = 0;
	
	// get instruction mnemonic
	if( !ua_mnem(ea, g_mnem, sizeof(g_mnem)) )
		return false;
	tag_remove(g_mnem, g_mnem, sizeof(g_mnem));
	char* ptr = (char*)qstrstr(g_mnem, ".");
	if(ptr) *ptr = 0;
	
	// get instruction operand strings
	// IDA only natively supports 3 operands
	*g_opnd_s0 = 0;
	ua_outop2(ea, g_opnd_s0, sizeof(g_opnd_s0), 0);
	tag_remove(g_opnd_s0, g_opnd_s0, sizeof(g_opnd_s0));
	
	*g_opnd_s1 = 0;
	ua_outop2(ea, g_opnd_s1, sizeof(g_opnd_s1), 1);
	tag_remove(g_opnd_s1, g_opnd_s1, sizeof(g_opnd_s1));
	
	*g_opnd_s2 = 0;
	ua_outop2(ea, g_opnd_s2, sizeof(g_opnd_s2), 2);
	tag_remove(g_opnd_s2, g_opnd_s2, sizeof(g_opnd_s2));
	
	// use some string manipulation to extract additional operands
	// when more than 3 operands are used
	*g_opnd_s4 = 0;
	*g_opnd_s3 = 0;
	const char* comma1 = qstrstr(g_opnd_s2, ",");
	if(comma1 != NULL)
	{
		// operand-3 exists
		qstrncpy(g_opnd_s3, comma1+1, sizeof(g_opnd_s3));
		g_opnd_s2[comma1-g_opnd_s2] = 0;
		
		const char* comma2 = qstrstr(comma1+1, ",");
		if(comma2 != NULL)
		{
			// operand-4 exists
			qstrncpy(g_opnd_s4, comma2+1, sizeof(g_opnd_s4));
			g_opnd_s3[comma2-(comma1+1)] = 0;
		}
	}

  // below is a list of supported instructions
  if(		qstrcmp(g_mnem, "bc")==0 )		return bc(		ea, buff, buffSize);
  // clear
  else if(qstrcmp(g_mnem, "clrlwi")==0 )	return clrlwi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "clrrwi")==0 )	return clrrwi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "clrlslwi")==0 )return clrlslwi(ea, buff, buffSize);
  // extract
  else if(qstrcmp(g_mnem, "extlwi")==0 )	return extlwi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "extrwi")==0 )	return extrwi(	ea, buff, buffSize);
  // insert
  else if(qstrcmp(g_mnem, "inslwi")==0 )	return inslwi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "insrwi")==0 )	return insrwi(	ea, buff, buffSize);
  // rotate and mask
  else if(qstrcmp(g_mnem, "rlwimi")==0 )	return rlwimi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "rlwinm")==0 )	return rlwinm(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "rlwnm" )==0 )	return rlwnm(	ea, buff, buffSize);
  // rotate
  else if(qstrcmp(g_mnem, "rotlw" )==0 )	return rotlw(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "rotlwi")==0 )	return rotlwi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "rotrwi")==0 )	return rotrwi(	ea, buff, buffSize);
  // shift
  else if(qstrcmp(g_mnem, "slwi"  )==0 )	return slwi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "srwi"  )==0 )	return srwi(	ea, buff, buffSize);
	
	
  // 64bit versions of the above
  // *** possibly these are not correct ***
  // *** they need more testing ***
	
  // clear
  else if(qstrcmp(g_mnem, "clrldi" )==0 )	return clrldi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "clrrdi" )==0 )	return clrrdi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "clrlsldi" )==0)return clrlsldi(ea, buff, buffSize);
  // extract
  else if(qstrcmp(g_mnem, "extldi" )==0 )	return extldi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "extrdi" )==0 )	return extrdi(	ea, buff, buffSize);
  // insert
  else if(qstrcmp(g_mnem, "insrdi" )==0 )	return insrdi(	ea, buff, buffSize);
  // rotate
  else if(qstrcmp(g_mnem, "rotld" )==0 )	return rotld(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "rotldi" )==0 )	return rotldi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "rotrdi" )==0 )	return rotrdi(	ea, buff, buffSize);
  // rotate and mask
  else if(qstrcmp(g_mnem, "rldcl" )==0 )	return rldcl(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "rldcr" )==0 )	return rldcr(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "rldic" )==0 )	return rldic(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "rldicl")==0 )	return rldicl(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "rldicr")==0 )	return rldicr(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "rldimi")==0 )	return rldimi(	ea, buff, buffSize);
  // shift
  else if(qstrcmp(g_mnem, "sldi" )==0 )	return sldi(	ea, buff, buffSize);
  else if(qstrcmp(g_mnem, "srdi" )==0 )	return srdi(	ea, buff, buffSize);
	
  return true;
}

#endif

static bool
has_function(ea_t address)
{
	list<Function>::iterator it;
	for (it = functions.begin(); it != functions.end(); it++) {
		if ((*it).address == address)
			return true;
	}

	return false;
}

static bool
has_instruction(Function &func, ea_t address)
{
	list<Instruction>::iterator it;
	for (it = func.instructions.begin(); it != func.instructions.end(); it++) {
		if ((*it).address == address)
			return true;
	}

	return false;
}

static char buffer[1024];

static bool
parse_instruction (Function &func, ea_t ea)
{
  Instruction ins;

  // make sure address is valid and that it points to the start of an instruction
  if(ea == BADADDR)
    return false;
  if( !isCode(get_flags_novalue(ea)) )
    return false;


  if (get_name(ea, ea, buffer, sizeof(buffer)) != NULL) {
	Instruction label;
	label.address = ea;
	label.type = INSTRUCTION_TYPE_LABEL;
    label.name = buffer;
    func.instructions.push_back(label);
  }
  if (get_cmt(ea, false, buffer, sizeof(buffer)) != -1) {
	Instruction comment;
    comment.address = ea;
    comment.type = INSTRUCTION_TYPE_COMMENT;
    comment.name = buffer;
    func.instructions.push_back(comment);
  }
  if (get_cmt(ea, true, buffer, sizeof(buffer)) != -1) {
	Instruction rpt_comment;
    rpt_comment.address = ea;
	rpt_comment.type = INSTRUCTION_TYPE_COMMENT;
    rpt_comment.name = buffer;
    func.instructions.push_back(rpt_comment);
  }

  // get instruction mnemonic
  if( !ua_mnem(ea, buffer, sizeof(buffer)) )
    return false;
  tag_remove(buffer, buffer, sizeof(buffer));
  
  // Some mnemonics are wrong, let's fix them.
  ua_ana0(ea);
  if(cmd.itype == 13 && (cmd.auxpref & 8)) {
    // fix mnemonic for "bl"
	qstrncpy(buffer, "bl", sizeof(buffer));
  } else if(cmd.itype == 320 && cmd.auxpref == 0x500) {
    // fix mnemonic for "blr"
	qstrncpy(buffer, "blr", sizeof(buffer));
  }

  ins.type = INSTRUCTION_TYPE_INSTRUCTION;
  ins.address = ea;
  ins.name = buffer;
  if (ins.name.find('.') != -1)
    ins.name.erase(ins.name.find('.'), 1);
	
  // get instruction operand strings
  // IDA only natively supports 3 operands
  *buffer = 0;
  ua_outop2(ea, buffer, sizeof(buffer), 0);
  tag_remove(buffer, buffer, sizeof(buffer));
  ins.operands[0] = buffer;

  *buffer = 0;
  ua_outop2(ea, buffer, sizeof(buffer), 1);
  tag_remove(buffer, buffer, sizeof(buffer));
  ins.operands[1] = buffer;

  *buffer = 0;
  ua_outop2(ea, buffer, sizeof(buffer), 2);
  tag_remove(buffer, buffer, sizeof(buffer));
  ins.operands[2] = buffer;

  
  // use some string manipulation to extract additional operands
  // when more than 3 operands are used

  long int comma = ins.operands[2].find(',');
  if(comma != -1) {
      // operand-3 exists
	  ins.operands[3] = ins.operands[2].substr(comma + 1);
      ins.operands[2] = ins.operands[2].substr(0, comma);
		
	  comma = ins.operands[3].find(',');
	  if(comma != -1) {
		  // operand-4 exists
		  ins.operands[4] = ins.operands[3].substr(comma + 1);
		  ins.operands[3] = ins.operands[3].substr(0, comma);
      }
  }
  for (int i = 4; i >= 0; i--) {
	  if (ins.operands[i] == "")
		  continue;
	  long int comm = ins.operands[i].find(" # ");
	  if (comm != -1) {
		  Instruction  comment;
		  comment.address = ea;
		  comment.type = INSTRUCTION_TYPE_INLINE_COMMENT;
		  comment.name = ins.operands[i].substr(comm + 3);
		  func.instructions.push_back(comment);
		  //DEBUG("Inline comment : '%s'\n", comment.name.c_str());
		  ins.operands[i] = ins.operands[i].substr(0, comm);
		  break;
	  }
  }

  /*DEBUG ("Instruction at %a is : '%s' - '%s' - '%s' - '%s' - '%s' - '%s'\n", ea, ins.name.c_str(),
       ins.operands[0].c_str(), ins.operands[1].c_str(), ins.operands[2].c_str(), ins.operands[3].c_str(), ins.operands[4].c_str());*/
  func.instructions.push_back(ins);

  return true;
}

static bool
parse_function (ea_t address, bool recursive = true)
{
	func_t* p_func = NULL;
	bool success = true;
	Function func;

	p_func = get_func(address);
	if(p_func == NULL) {
		msg("Not in a function, so can't do PPC to C conversion for the current function!\n");
		return false;
	}
	func.address = p_func->startEA;
	func.end_address = p_func->endEA;
	func.name = get_func_name(func.address, buffer, sizeof(buffer));


	//DEBUG("%a: Parsing function '%s'\n", func.address, func.name.c_str());
	//success = parse_instruction(func, func.address);
	

	xrefblk_t xb;
	ea_t ea;
	set<ea_t> instructions;
	set<ea_t>::iterator iter1;
	set<ea_t>::iterator iter2;
	set<ea_t> calls;
	bool modified = true;

	//_Export_sysPrxForUser_sys_time_get_system_time
	//_Export_sysPrxForUser_2E20EC1
	instructions.insert(func.address);
break_loop2:
	iter1 = instructions.begin();
	iter2 = instructions.begin();
	while (modified) {
		modified = false;
		for (; iter1 != instructions.end(); iter1++) {
			ea = *iter1;
			//DEBUG("Looping instruction list : %a\n", ea);
			for (bool ok = xb.first_from(ea, XREF_ALL); ok && xb.iscode; ok = xb.next_from()) {
				//DEBUG("First xref from %a to %a : %s (%d)\n", xb.from, xb.to, xb.type == fl_F? "Flow" : xb.type == fl_JN? "Jump near" : xb.type == fl_JF ? "Jump far" : xb.type == fl_CN ? "Call near" : xb.type == fl_CF ? "Call far" : "unknown flow", xb.type);
				if (xb.type == fl_F && instructions.find(xb.to) == instructions.end()) {
					instructions.insert(xb.to);
					modified = true;
				}
			}
		}
		for (; iter2 != instructions.end(); iter2++) {
			ea = *iter2;
			//DEBUG("Looping instruction list : %a\n", ea);
			for (bool ok = xb.first_from(ea, XREF_ALL); ok && xb.iscode; ok = xb.next_from()) {
				//DEBUG("Second xref from %a to %a : %s (%d)\n", xb.from, xb.to, xb.type == fl_F? "Flow" : xb.type == fl_JN? "Jump near" : xb.type == fl_JF ? "Jump far" : xb.type == fl_CN ? "Call near" : xb.type == fl_CF ? "Call far" : "unknown flow", xb.type);
				if ((xb.type == fl_JN || xb.type == fl_JF) && instructions.find(xb.to) == instructions.end()) {
					instructions.insert(xb.to);
					modified = true;
					goto break_loop2;
				}
			}
		}
	}

	for (iter1 = instructions.begin(); success && iter1 != instructions.end(); iter1++) {
		ea = *iter1;
		//DEBUG("Looping instruction list : %a\n", ea);
		success &= parse_instruction(func, ea);
		for (bool ok = xb.first_from(ea, XREF_ALL); ok && xb.iscode; ok = xb.next_from()) {
			//DEBUG("Third xref from %a to %a : %s (%d)\n", xb.from, xb.to, xb.type == fl_F? "Flow" : xb.type == fl_JN? "Jump near" : xb.type == fl_JF ? "Jump far" : xb.type == fl_CN ? "Call near" : xb.type == fl_CF ? "Call far" : "unknown flow", xb.type);
			if (xb.type == fl_F && has_instruction(func, xb.to)) {
				Instruction flow;
				
				flow.address = ea;
				flow.type = INSTRUCTION_TYPE_FLOW;
				if (get_name(xb.to, xb.to, buffer, sizeof(buffer)) != NULL) {
					flow.name = buffer;
					//DEBUG ("Flow goes to %s\n", flow.name.c_str());
				} else {
					ERROR ("Flow expected to have a label at %a\n", xb.to);
				}
				func.instructions.push_back(flow);
			}
			if (xb.type == fl_CN || xb.type == fl_CF)
				calls.insert(xb.to);
		}
	}

	if (success) {
		functions.push_back(func);
		if (recursive) {
			set<ea_t>::iterator it;
			for (it = calls.begin(); success && it != calls.end(); it++) {
				if (!has_function(*it))
					success &= parse_function(*it, recursive);
			}
		}
	}
	//DEBUG("%a: Parsed function '%s', got %d instructions\n", func.address, func.name.c_str(), func.instructions.size());

	return success;
}

#define OUTPUT msg

static void
generate_prototype (Function &func)
{
	OUTPUT("%s %s (", func.ret ? "uint64" : "void", func.name.c_str());
	for (int i = 0; i < func.arguments; i++)
		OUTPUT ("uint64t arg%d%s", i+1, i == func.arguments-1 ? "" : ", ");
	OUTPUT(")");
}

static bool
generate_functions ()
{
	list<Function>::iterator it;
	for (it = functions.begin(); it != functions.end(); it++) {
		Function func = *it;
		list<Instruction>::iterator iter;
		Instruction inline_comment;
		inline_comment.type = INSTRUCTION_TYPE_NONE;

		generate_prototype(func);
		OUTPUT ("\n{\n");
		OUTPUT ("  uint64_t LR, *sp, *rtoc, r0, r1, r2, r3, r4, r5, r6,\n");
		OUTPUT ("      r7, r8, r9, r10, r11, r12, r13, r14, r15, r16,\n");
		OUTPUT ("      r17, r18, r19, r20, r21, r22, r23, r24, r25, r26,\n");
		OUTPUT ("      r27, r28, r29, r30, r31, r32;\n\n");

		for (iter = func.instructions.begin(); iter != func.instructions.end(); iter++) {
			Instruction ins = *iter;
			switch (ins.type) {
			case INSTRUCTION_TYPE_COMMENT:
				OUTPUT ("  /* %s */\n", ins.name.c_str());
				break;
			case INSTRUCTION_TYPE_INLINE_COMMENT:
				inline_comment = ins;
				break;
			case INSTRUCTION_TYPE_LABEL:
				if (ins.name != func.name)
					OUTPUT ("  %s:\n", ins.name.c_str());
				break;
			case INSTRUCTION_TYPE_PREPROCESSOR:
			case INSTRUCTION_TYPE_INSTRUCTION:
				{
					int i;
					for (i = 0; instruction_set[i].instruction; i++) {
						if (instruction_set[i].type == ins.type &&
							ins.name == instruction_set[i].instruction) {
							HandlerResult result;
							if (!instruction_set[i].check_operands (ins)) {
								ERROR ("Assertion : Wrong number of operands for instruction : %s\n", ins.name.c_str());
								DEBUG("Wrong number of args : %s%s%s%s%s%s\n",
									ins.name.c_str(),
									ins.operands[0] != ""? (" " + ins.operands[0]).c_str() : "",
									ins.operands[1] != ""? (" " + ins.operands[1]).c_str() : "",
									ins.operands[2] != ""? (" " + ins.operands[2]).c_str() : "",
									ins.operands[3] != ""? (" " + ins.operands[3]).c_str() : "",
									ins.operands[4] != ""? (" " + ins.operands[4]).c_str() : "");
								return false;
							}
							instruction_set[i].handler (func, ins, &result);

							if (result.c_code != "") {
							  OUTPUT ("%s%s%s\n",
									ins.type == INSTRUCTION_TYPE_INSTRUCTION ? "  " : "",
									result.c_code.c_str(),
									inline_comment.type != INSTRUCTION_TYPE_NONE? ("; // " + inline_comment.name).c_str() : ";");
							} else if (inline_comment.type != INSTRUCTION_TYPE_NONE) {
								OUTPUT("  // %s\n", inline_comment.name.c_str());
							}
							inline_comment.type = INSTRUCTION_TYPE_NONE;
							break;
						}
					}
					if (instruction_set[i].instruction == NULL) {
						//ERROR ("Error: Unknown instruction : %s\n", ins.name.c_str());
						//return false;
						OUTPUT ("  /* Unknown instruction : %s%s%s%s%s%s */\n",
							ins.name.c_str(),
							ins.operands[0] != ""? (" " + ins.operands[0]).c_str() : "",
							ins.operands[1] != ""? (" " + ins.operands[1]).c_str() : "",
							ins.operands[2] != ""? (" " + ins.operands[2]).c_str() : "",
							ins.operands[3] != ""? (" " + ins.operands[3]).c_str() : "",
							ins.operands[4] != ""? (" " + ins.operands[4]).c_str() : "");
					}
				}
				break;
			case INSTRUCTION_TYPE_FLOW:
				OUTPUT ("  goto %s;\n", ins.name.c_str());
				break;
			default:
				ERROR ("Error: Unexpected instruction type\n");
				return false;
			}
		}

		OUTPUT ("}\n\n");
	}
	return true;
}

int idaapi PluginStartup(void)
{
  // PPC To C only works with PPC code :)
  if ( ph.id != PLFM_PPC )
    return PLUGIN_SKIP;
	
  // if PPC then this plugin is OK to use
  return PLUGIN_OK;
}


void idaapi PluginShutdown(void)
{
  // any cleanup code that needs to be done on exit goes here
}


void idaapi PluginMain(int param)
{

	clock_t begin = clock();

	functions.clear();
	parse_function (get_screen_ea(), true);

    OUTPUT ("#include <stdint.h>\n\n");
	for (list<Function>::iterator it = functions.begin(); it != functions.end(); it++) {
		generate_prototype (*it);
		OUTPUT (";\n");
	}
	generate_functions ();

	clock_t end=clock();
	double diffms = ((double)(end-begin)*1000)/CLOCKS_PER_SEC;
	msg("Found %d functions in : %2d:%3d\n", functions.size(), (int)diffms/1000, (int)diffms%1000);
}


const char G_PLUGIN_COMMENT[]	=	"PPC To C Converter";
const char G_PLUGIN_HELP[]	=	"This plugin converts a function in PPC instructions into their relevant C code.\n";
const char G_PLUGIN_NAME[]	=	"Convert PPC To C";
const char G_PLUGIN_HOTKEY[]	=	"F10";

plugin_t PLUGIN =
  {
    // values
    IDP_INTERFACE_VERSION,
    0,						// plugin flags	
	
    // functions
    PluginStartup,			// initialize
    PluginShutdown,			// terminate. this pointer may be NULL.
    PluginMain,				// invoke plugin
	
    // strings
    (char*)G_PLUGIN_COMMENT,// long comment about the plugin (may appear on status line or as a hint)
    (char*)G_PLUGIN_HELP,	// multiline help about the plugin
    (char*)G_PLUGIN_NAME,	// the preferred short name of the plugin, used by menu system
    (char*)G_PLUGIN_HOTKEY	// the preferred hotkey to run the plugin
  };

