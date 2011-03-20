// 
// PPC Jump Tables
// 
// 

/*

  cmplwi  crX, %rXY, <jsize - 1>
  ...
  bgt     crX, loc_jdefault  ;// OR ble  crX, loc_jtable

  ....
  lwz     %r11, off_xyz
  rldic   %r9, %rXY, 2,30
  lwzx    %r0, %r9, %r11
  extsw   %r0, %r0
  add     %r0, %r0, %r11
  mtctr   %r0
  bctr
*/



#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <auto.hpp>


#define PPCJP_VERSION	"v0.1"

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
    msg("0x%llX: instruction is : %s -- %s -- %s -- %s\n", ea, g_mnem, g_opnd_s0, g_opnd_s1, g_opnd_s2);
    msg("0x%llX: itype = %d - flags = %d - auxpref.high = %d -- auxpref.low = %d\n",
	ea, cmd.itype, cmd.flags, cmd.auxpref_chars.high, cmd.auxpref_chars.low);
  } else {
    msg("0x%llX: Not an instruction\n", ea);
  }
}

bool is_lwz_off_x(ea_t ea, uint16 reg_off) {
  if (decode_insn_to_mnem(ea) &&
      qstrcmp(g_mnem, "lwz") == 0 &&
      cmd.Op1.reg == reg_off) {
    return true;
  }
  return false;
}

bool is_rldic_idx_size_2_30(ea_t ea, uint16 reg_idx, uint16 *reg_size) {
  if (decode_insn_to_mnem(ea) &&
      qstrcmp(g_mnem, "rldic") == 0 &&
      cmd.Op1.reg == reg_idx &&
      qstrcmp(g_opnd_s2, "2,30") == 0) {
    *reg_size = cmd.Op2.reg;
    return true;
  }
  return false;
}

bool is_lwzx_r0_off_idx(ea_t ea, uint16 reg_off, uint16 *reg_idx) {
  if (decode_insn_to_mnem(ea) &&
      qstrcmp(g_mnem, "lwzx") == 0 &&
      qstrcmp(g_opnd_s0, "%r0") == 0 &&
      cmd.Op2.reg == reg_off) {
    *reg_idx = cmd.Op3.reg;
    return true;
  }
  if (decode_insn_to_mnem(ea) &&
      qstrcmp(g_mnem, "lwzx") == 0 &&
      qstrcmp(g_opnd_s0, "%r0") == 0 &&
      cmd.Op3.reg == reg_off) {
    *reg_idx = cmd.Op2.reg;
    return true;
  }
  return false;
}

bool is_extsw_r0_r0(ea_t ea) {
  if (decode_insn_to_mnem(ea) &&
      qstrcmp(g_mnem, "extsw") == 0 &&
      qstrcmp(g_opnd_s0, "%r0") == 0 &&
      qstrcmp(g_opnd_s1, "%r0") == 0) {
    return true;
  }
  return false;
}

bool is_add_r0_r0_off(ea_t ea, uint16 *reg_off) {
  if (decode_insn_to_mnem(ea) &&
      qstrcmp(g_mnem, "add") == 0 &&
      qstrcmp(g_opnd_s0, "%r0") == 0 &&
      qstrcmp(g_opnd_s1, "%r0") == 0 ) {
    *reg_off = cmd.Op3.reg;
    return true;
  }
  return false;
}

bool is_mtctr_r0(ea_t ea) {
  if (decode_insn_to_mnem(ea) &&
      qstrcmp(g_mnem, "mts") == 0 &&
      qstrcmp(g_opnd_s0, "CTR") == 0 &&
      qstrcmp(g_opnd_s1, "%r0") == 0 ) {
    return true;
  }
  if (decode_insn_to_mnem(ea) &&
      qstrcmp(g_mnem, "mtctr") == 0 &&
      qstrcmp(g_opnd_s0, "ctr") == 0 &&
      qstrcmp(g_opnd_s1, "%r0") == 0 ) {
    return true;
  }
  return false;
}

bool is_bctr(ea_t ea) {
  if (decode_insn_to_mnem(ea) &&
      qstrcmp(g_mnem, "b") == 0 &&
      qstrcmp(g_opnd_s0, "lt") == 0 &&
      qstrcmp(g_opnd_s1, "ctr") == 0 &&
      cmd.auxpref_chars.high == 6 && // bctr == 0x600, bctrl == 0x608
      cmd.auxpref_chars.low == 0) {
    return true;
  }
  return false;
}

bool is_cmplwi_crx_rxy_x(ea_t ea, char *cr, uint16 reg) {

  if (decode_insn_to_mnem(ea) &&
      qstrcmp(g_mnem, "cmplwi") == 0 &&
      qstrcmp(g_opnd_s0, cr) == 0 &&
      cmd.Op2.reg == reg) {
    return true;
  }
  return false;
}

bool is_mr_rxy_rxy(ea_t ea, uint16 reg) {

  if (decode_insn_to_mnem(ea) &&
      qstrcmp(g_mnem, "mr") == 0 &&
      cmd.Op1.reg == reg) {
    return true;
  }
  return false;
}


int FindCmplwi (ea_t ea, char *cr, uint16 reg) {
  bool res;
  xrefblk_t xb;
  int size = -1;

  for (res = xb.first_to(ea, XREF_ALL); res; res = xb.next_to()) {
    if (xb.to - xb.from != 4) {
      break;
    }
    if (is_cmplwi_crx_rxy_x(xb.from, cr, reg)) {
      size = cmd.Op3.value + 1;
      break;
    } else {
      if (is_mr_rxy_rxy(xb.from, reg))
	reg = cmd.Op2.reg;
      size = FindCmplwi(xb.from, cr, reg);
      if (size != -1)
	break;
    }
  }

  return size;
}

bool idaapi ppcjt_is_switch (switch_info_ex_t *si) {
  ea_t ea = cmd.ea;
  ea_t jtable = 0;
  ea_t jump = 0;
  ea_t jtdefault = 0;
  int jtsize = -1;
  uint16 reg_idx;
  uint16 reg_jtoff;
  uint16 reg_jtsize = 0;

  if (!isCode(get_flags_novalue(ea + 4)) &&
      is_bctr(ea) &&
      is_mtctr_r0(ea - 4) &&
      is_add_r0_r0_off(ea - 8, &reg_jtoff) &&
      is_extsw_r0_r0(ea - 12) &&
      is_lwzx_r0_off_idx(ea - 16, reg_jtoff, &reg_idx) &&
      ((is_lwz_off_x(ea - 24, reg_jtoff) &&
	is_rldic_idx_size_2_30(ea - 20, reg_idx, &reg_jtsize)) || 
       (is_rldic_idx_size_2_30(ea - 24, reg_idx, &reg_jtsize) &&
	is_lwz_off_x(ea - 20, reg_jtoff)))) {
    xrefblk_t xb;
    ea_t ea2;
    char cr[G_STR_SIZE];

    jtable = ea + 4;
    jump = ea;

    if (xb.first_to(ea - 24, XREF_ALL)) {
      ea2 = xb.from;
      if (decode_insn_to_mnem(ea2)) {
	if (qstrcmp(g_mnem, "bgt") == 0) {
	  if (ea2 != ea - 28) {
	    msg("Couldn't recognize jump table at 0x%llX\n", jump);
	    goto error;
	  }
	  jtdefault = cmd.Op2.addr;
	  qstrncpy(cr, g_opnd_s0, G_STR_SIZE);
	} else if (qstrcmp(g_mnem, "ble") == 0) {
	  if (cmd.Op2.addr != ea - 24) {
	    msg("Couldn't recognize jump table at 0x%llX\n", jump);
	    goto error;
	  }
	  jtdefault = ea2 + 4;
	  qstrncpy(cr, g_opnd_s0, G_STR_SIZE);
	} else {
	  msg("Couldn't recognize jump table at 0x%llX\n", jump);
	  goto error;
	}
      } else {
	msg("Couldn't recognize jump table at 0x%llX\n", jump);
	goto error;
      }

      jtsize = FindCmplwi (ea2, cr, reg_jtsize);
      if (jtsize < 0) {
	msg("Couldn't recognize jump table at 0x%llX\n", jump);
	goto error;
      }

      msg("Found Jump Table at : 0x%llX with %d cases\n", jtable, jtsize);

      si->flags = SWI_EXTENDED | SWI_SIGNED | SWI_ELBASE | SWI_DEFAULT;
      si->flags2 = 0;
      si->jumps = jtable;
      si->ncases = ushort(jtsize);
      si->startea = jump;
      si->elbase = jtable;

      si->set_jtable_element_size(4);
      si->set_shift(0);
      si->defjump = jtdefault;
      si->lowcase = 0;
      return true;
    } else {
      msg("Couldn't recognize jump table at 0x%llX\n", jump);
      goto error;
    }
  }

 error:
  decode_insn(ea);
  if (orig_is_switch)
    return orig_is_switch(si);
  else
    return false;
}

/************************************************************************
*
*	FUNCTION		PluginStartup
*
*	DESCRIPTION		Determines whether this plugin will work with the current database.
*
*					IDA will call this function only once. If this function returns PLUGIN_SKIP,
*					IDA will never load it again. If it returns PLUGIN_OK, IDA will unload the plugin
*					but remember that the plugin agreed to work with the database. The plugin will
*					be loaded again if the user invokes it by pressing the hotkey or selecting it
*					from the menu. After the second load, the plugin will stay in memory.
*
******************************************************************/

int idaapi PluginStartup(void)
{
  // PPC JP only works with PPC code :)
  if ( ph.id != PLFM_PPC )
    return PLUGIN_SKIP;

  msg("Loading PPC Jump Table plugin\n");

  orig_is_switch = ph.is_switch;
  ph.is_switch = ppcjt_is_switch;

  // if PPC then this plugin is OK to use
  return PLUGIN_KEEP;
}



/*************************************************
*
*	FUNCTION		PluginShutdown
*
*	DESCRIPTION		IDA will call this function when the user asks to exit. This function is *not*
*					called in the case of emergency exits.
*
*******************************************************************/

void idaapi PluginShutdown(void)
{
  msg("Shutting down PPC Jump Table plugin\n");
  ph.is_switch = orig_is_switch;
  orig_is_switch = NULL;
}



/***************************************************************************************************
*
*	FUNCTION		PluginMain
*
*	DESCRIPTION		This is the main function of plugin.
*					Param is an input arguement specified in plugins.cfg file.
*                   (The default is zero.)
*
***************************************************************************************************/

void idaapi PluginMain(int param)
{
}



/************************************************************
*
* Strings required for IDA Pro's PLUGIN descriptor block
*
************************************************************/

const char G_PLUGIN_COMMENT[] = "PPC Jump Table fix";
const char G_PLUGIN_HELP[] = "This plugin will fix PPC Jump Tables for "
  "proper analysis.\n";
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

