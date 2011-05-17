/*
 *
 * PowerPC Jump Tables analysis Module
 *
 * The PowerPC processor module in IDA Pro 4.8 does not handle jump tables.
 * This module will try to find the jump tables and tell IDA about them
 * so the function analysis can be as good as possible.
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

/* 
    3/22/11 - mas - fixed include and added makefile (compiles fine for IDA 6 / OSX)
*/

/*

8  cmplwi  crX, %r5, <jsize - 1>
  ...
7  bgt     crX, loc_jdefault
OR
7  ble     crX, loc_jtable

  ....
6  lwz     %r2, off_xyz
5  rldic   %r4, %r5, 2,30
4  lwzx    %r3, %r4, %r2 // interchangeable
3  extsw   %r1, %r3
2  add     %r0, %r1, %r2 // interchangeable
1  mtctr   %r0
0  bctr

OR
4 <skip>
3 lwax     %r1, %r4, %r2
*/



#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <auto.hpp>
#include <offset.hpp>

//#define JUMP_DEBUG
#include "../../module/jptcmn.cpp"


#define PPCJT_VERSION	"v0.2"

#define G_STR_SIZE	256
char g_mnem[G_STR_SIZE];
char g_opnd_s0[G_STR_SIZE];
char g_opnd_s1[G_STR_SIZE];
char g_opnd_s2[G_STR_SIZE];
bool (idaapi* orig_is_switch)(switch_info_ex_t *si);


bool decode_insn_to_mnem(ea_t ea) {
  if (decode_insn(ea) != 0) {
    g_mnem[0] = 0;
    ua_mnem(cmd.ea, g_mnem, sizeof(g_mnem));

    *g_opnd_s0 = 0;
    ua_outop2(cmd.ea, g_opnd_s0, sizeof(g_opnd_s0), 0);
    tag_remove(g_opnd_s0, g_opnd_s0, sizeof(g_opnd_s0));

    *g_opnd_s1 = 0;
    ua_outop2(cmd.ea, g_opnd_s1, sizeof(g_opnd_s1), 1);
    tag_remove(g_opnd_s1, g_opnd_s1, sizeof(g_opnd_s1));

    *g_opnd_s2 = 0;
    ua_outop2(ea, g_opnd_s2, sizeof(g_opnd_s2), 2);
    tag_remove(g_opnd_s2, g_opnd_s2, sizeof(g_opnd_s2));

    return true;
  }
  return false;
}


void print_ins(ea_t ea) {
  if (decode_insn_to_mnem(ea)) {
    jmsg("0x%a: instruction is : %s -- %s -- %s -- %s\n",
        ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2);
    jmsg("0x%a: itype = %d - flags = %d - auxpref.high = %d -- .low = %d\n",
	ea, cmd.itype, cmd.flags, cmd.auxpref_chars.high, cmd.auxpref_chars.low);
  } else {
    jmsg("0x%a: Not an instruction\n", ea);
  }
}

class ppc_jump_pattern_t : public jump_pattern_t
{
public:
  ea_t jtable;
  ea_t jump;
  ea_t jtdefault;
  ushort jtsize;
  bool pattern_found;

  static const char *ppc_roots;
  static const char (*ppc_depends)[2];
  ppc_jump_pattern_t(switch_info_ex_t &si) :
    jump_pattern_t (ppc_roots, ppc_depends, si)
  {
    jtable = 0;
    jump = 0;
    jtdefault = 0;
    jtsize = 0;
    pattern_found = false;
  }

  virtual bool handle_mov(void) {
    jmsg("%a: Handling move \n", cmd.ea);
    if (decode_insn_to_mnem(cmd.ea)) {
      for (int i = 0; i < 6; i++) {
	if (r[i] != -1 &&
	    qstrcmp(g_mnem, "mr") == 0 &&
	    cmd.Op1.reg == r[i]) {
	  r[i] = cmd.Op2.reg;
	  return true;
	}
      }
    }
    return false;
  }

  virtual bool jpi0(void) {
    jmsg("%a: Checking for jpi 0\n", cmd.ea);
    if (decode_insn_to_mnem(cmd.ea) &&
	qstrcmp(g_mnem, "b") == 0 &&
	qstrcmp(g_opnd_s0, "lt") == 0 &&
	qstrcmp(g_opnd_s1, "ctr") == 0 &&
	cmd.auxpref_chars.high == 6 && // bctr == 0x600, bctrl == 0x608
	cmd.auxpref_chars.low == 0) {
      jmsg("Found bctr\n");
      jump = cmd.ea;
      jtable = cmd.ea + 4;
      return true;
    }
    return false;
  }
  virtual bool jpi1(void) {
    jmsg("%a: Checking for jpi 1\n", cmd.ea);
    if (decode_insn_to_mnem(cmd.ea)) {
      if (qstrcmp(g_mnem, "mts") == 0 &&
	  qstrcmp(g_opnd_s0, "CTR") == 0) {
	r[0] = cmd.Op2.reg;
	jmsg("Found mtctr. r[0] == %d\n", r[0]);
	return true;
      }
      if (qstrcmp(g_mnem, "mtctr") == 0 &&
	  qstrcmp(g_opnd_s0, "ctr") == 0) {
	r[0] = cmd.Op2.reg;
	jmsg("Found mtctr. r[0] == %d\n", r[0]);
	return true;
      }
    }
    return false;
  }
  virtual bool jpi2(void) {
    jmsg("%a: Checking for jpi 2\n", cmd.ea);
    if (decode_insn_to_mnem(cmd.ea) &&
	qstrcmp(g_mnem, "add") == 0 &&
	cmd.Op1.reg == r[0]) {
      r[1] = cmd.Op2.reg;
      r[2] = cmd.Op3.reg;
      jmsg("Found add. r[1] == %d -- r[2] == %d\n", r[1], r[2]);
      return true;
    }
    return false;
  }
  virtual bool jpi3(void) {
    jmsg("%a: Checking for jpi 3\n", cmd.ea);
    if (decode_insn_to_mnem(cmd.ea)) {
      if (qstrcmp(g_mnem, "extsw") == 0 &&
	  cmd.Op1.reg == r[1]) {
	r[3] = cmd.Op2.reg;
	jmsg("Found extsw. r[3] == %d\n", r[3]);
	return true;
      }
      if (qstrcmp(g_mnem, "extsw") == 0 &&
	  cmd.Op1.reg == r[2]) {
	uint16 reg_tmp = r[1];
	r[1] = r[2];
	r[2] = reg_tmp;
	r[3] = cmd.Op2.reg;
	jmsg("Found extsw. Switched r[1] and r[2]. r[3] == %d\n", r[3]);
	return true;
      }
      if (qstrcmp(g_mnem, "lwax") == 0) {
	if (cmd.Op1.reg == r[1] &&
	    cmd.Op2.reg == r[2]) {
	  r[4] = cmd.Op3.reg;
	  skip[4] = true;
	  pattern_found = true;
	  jmsg("Found lwax. Skipping jpi5. r[4] is second operand. r[4] == %d\n",
	       r[4]);
	  return true;
	}
	if (cmd.Op1.reg == r[1] &&
	    cmd.Op3.reg == r[2]) {
	  r[4] = cmd.Op2.reg;
	  skip[4] = true;
	  pattern_found = true;
	  jmsg("Found lwzx. Skipping jpi5. r[4] is first operand. r[4] == %d\n",
	       r[4]);
	  return true;
	}
	if (cmd.Op1.reg == r[2] &&
	    cmd.Op2.reg == r[1]) {
	  uint16 reg_tmp = r[1];
	  r[1] = r[2];
	  r[2] = reg_tmp;
	  r[4] = cmd.Op3.reg;
	  skip[4] = true;
	  pattern_found = true;
	  jmsg("Found lwax. Skipping jpi5. Switched r[1] and r[2]. "
	       "r[4] is second operand. r[4] == %d\n", r[4]);
	  return true;
	}
	if (cmd.Op1.reg == r[2] &&
	    cmd.Op3.reg == r[1]) {
	  uint16 reg_tmp = r[1];
	  r[1] = r[2];
	  r[2] = reg_tmp;
	  r[4] = cmd.Op2.reg;
	  skip[4] = true;
	  pattern_found = true;
	  jmsg("Found lwzx. Skipping jpi5. Switched r[1] and r[2]. "
	       "r[4] is first operand. r[4] == %d\n", r[4]);
	  return true;
	}
      }
    }
    return false;
  }
  virtual bool jpi4(void) {
    jmsg("%a: Checking for jpi 4\n", cmd.ea);
    if (decode_insn_to_mnem(cmd.ea)) {
      if (qstrcmp(g_mnem, "lwzx") == 0 &&
	  cmd.Op1.reg == r[3] &&
	  cmd.Op2.reg == r[2]) {
	r[4] = cmd.Op3.reg;
	jmsg("Found lwzx. r[4] is second operand. r[4] == %d\n", r[4]);
	pattern_found = true;
	return true;
      }
      if (qstrcmp(g_mnem, "lwzx") == 0 &&
	  cmd.Op1.reg == r[3] &&
	  cmd.Op3.reg == r[2]) {
	r[4] = cmd.Op2.reg;
	jmsg("Found lwzx. r[4] is first operand. r[4] == %d\n", r[4]);
	pattern_found = true;
	return true;
      }
    }
    return false;
  }
  virtual bool jpi5(void) {
    jmsg("%a: Checking for jpi 5\n", cmd.ea);
    print_ins (cmd.ea);
    if (decode_insn_to_mnem(cmd.ea)) {
      if (qstrcmp(g_mnem, "rldic") == 0 &&
	  cmd.Op1.reg == r[4] &&
	  qstrcmp(g_opnd_s2, "2,30") == 0) {
	r[5] = cmd.Op2.reg;
	jmsg("Found rldic. r[5] == %d\n", r[5]);
	return true;
      }
      if (qstrcmp(g_mnem, "rldicr") == 0 &&
	  cmd.Op1.reg == r[4] &&
	  qstrcmp(g_opnd_s2, "2,61") == 0) {
	r[5] = cmd.Op2.reg;
	jmsg("Found rldic. r[5] == %d\n", r[5]);
	return true;
      }
      if (qstrcmp(g_mnem, "clrlslwi") == 0 &&
	  cmd.Op1.reg == r[4]) {
	r[5] = cmd.Op2.reg;
	jmsg("Found clrlslwi. r[5] == %d\n", r[5]);
	return true;
      }
    }
    return false;
  }
  virtual bool jpi6(void) {
    jmsg("%a: Checking for jpi 6\n", cmd.ea);
    if (decode_insn_to_mnem(cmd.ea)) {
      print_ins(cmd.ea);
      if (qstrcmp(g_mnem, "lwz") == 0 &&
          cmd.Op1.reg == r[2]) {
        jmsg("Found lwz.\n");
        return true;
      }
      if (qstrcmp(g_mnem, "ld") == 0 &&
          cmd.Op1.reg == r[2]) {
        jmsg("Found ld.\n");
        return true;
      }
    }
    return false;
  }
  virtual bool jpi7(void) {
    jmsg("%a: Checking for jpi 7\n", cmd.ea);
    if (decode_insn_to_mnem(cmd.ea)) {
      if (qstrcmp(g_mnem, "bgt") == 0) {
	jtdefault = cmd.Op2.addr;
	jmsg("Found bgt. jtdefault : 0x%a\n", jtdefault);
	return true;
      }
      if (qstrcmp(g_mnem, "ble") == 0) {
	jtdefault = cmd.ea + 4;
	jmsg("Found ble. jtdefault : 0x%a\n", jtdefault);
	return true;
      }
    }
    return false;
  }
  virtual bool jpi8(void) {
    jmsg("%a: Checking for jpi 8\n", cmd.ea);
    if (decode_insn_to_mnem(cmd.ea) &&
	(qstrcmp(g_mnem, "cmplwi") == 0 ||
	 qstrcmp(g_mnem, "cmpldi") == 0)) {
      jtsize = ushort(cmd.Op3.value) + 1;
      jmsg("Found cmplwi. Jump table size : %d\n", jtsize);
      return true;
    }
    return false;
  }

  void fill_si(void) {
    si.flags = SWI_EXTENDED | SWI_SIGNED | SWI_ELBASE | SWI_DEFAULT;
    si.flags2 = 0;
    si.jumps = jtable;
    si.ncases = ushort(jtsize);
    si.startea = jump;
    si.elbase = jtable;

    si.set_jtable_element_size(4);
    si.set_shift(0);
    si.defjump = jtdefault;
    si.lowcase = 0;
  }
};

static const char s_ppc_roots[] = {1, 7, 0};
static const char s_ppc_depends[][2] = {
  {1, 0}, // 0
  {2, 0}, // 1
  {3, 6}, // 2
  {4, 0}, // 3
  {5, 6}, // 4
  {8, 0}, // 5
  {0, 0}, // 6
  {8, 0}, // 7
  {0, 0}, // 8
};
const char *ppc_jump_pattern_t::ppc_roots = s_ppc_roots;
const char (*ppc_jump_pattern_t::ppc_depends)[2] = s_ppc_depends;

bool idaapi ppcjt_is_switch (switch_info_ex_t *si) {
  ea_t ea = cmd.ea;
  ppc_jump_pattern_t *p = new ppc_jump_pattern_t(*si);

  if (p->match(ea)) {
    msg("Found Jump Table at : 0x%a with %d cases\n", ea, p->jtsize);
    p->fill_si();
    return true;
  } else if (p->pattern_found) {
    msg("Couldn't recognize jump table at 0x%a\n", ea);
  }

  decode_insn(ea);
  if (orig_is_switch)
    return orig_is_switch(si);
  else
    return false;
}

int idaapi PluginStartup(void)
{
  // PPCJT only works with PPC code :)
  if ( ph.id != PLFM_PPC )
    return PLUGIN_SKIP;

  msg("Loading PPC Jump Table plugin %s\n", PPCJT_VERSION);

  orig_is_switch = ph.is_switch;
  ph.is_switch = ppcjt_is_switch;

  // if PPC then this plugin is OK to use
  return PLUGIN_KEEP;
}


void idaapi PluginShutdown(void)
{
  msg("Shutting down PPC Jump Table plugin\n");

  /* If not on PPC, then don't overwrite is_switch */
  if (ph.id == PLFM_PPC) {
    ph.is_switch = orig_is_switch;
    orig_is_switch = NULL;
  }
}


void idaapi PluginMain(int param)
{
}



/************************************************************
*
* Strings required for IDA Pro's PLUGIN descriptor block
*
************************************************************/

const char G_PLUGIN_COMMENT[] = "PPC Jump Table fix";
const char G_PLUGIN_HELP[] = "This plugin adds Jump Table support to the PowerPC process module"
  "of IDA, resolving switch/cases into properly analyzed code.";
const char G_PLUGIN_NAME[] = "PPC JP: Jump table size";
const char G_PLUGIN_HOTKEY[] = "";


/**********************************************************************
*
*  This 'PLUGIN' data block is how IDA Pro interfaces with this plugin.
*
**********************************************************************/
plugin_t PLUGIN =
{
	// values
	IDP_INTERFACE_VERSION,
	0,				// plugin flags

	// functions
	PluginStartup,			// initialize
	PluginShutdown,			// terminate. this pointer may be NULL.
	PluginMain,			// invoke plugin

	// strings
	(char*)G_PLUGIN_COMMENT,	// long comment about the plugin
	(char*)G_PLUGIN_HELP,		// multiline help about the plugin
	(char*)G_PLUGIN_NAME,		// the preferred short name
	(char*)G_PLUGIN_HOTKEY		// the preferred hotkey
};

