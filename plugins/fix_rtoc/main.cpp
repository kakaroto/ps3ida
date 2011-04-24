//
// This is a template for easy creation of IDA Plugins using
// MS Visual Studio 2005 or later (ie VS2008 or VS2010)
// 
// This helps by setting all required settings, paths and preprocessor values
// required to create both 32bit and 64bit plugins from the same sourcecode.
// This will save work and time even for those with experience writing plugins,
// but it is of most use for those who are new to it and don't know where to start.
// 
// All that you as a plugin writer needs to do now is fill in your own values
// for the strings and functions in the "plugin_t PLUGIN" structure below.
//
// Note: When building these samples, your plugin file will be created in the
// "idasdk/bin/plugins" directory. To install the plugin copy the created files
// to the "IDA/plugins" directory.
//
// Zak Stanborough - October 2009
// 


// A bunch of required headers from the IDA SDK
#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>
#include <allins.hpp>
#include <pro.h>



// Determines whether this plugin will work with the current database.
// 
// IDA will call this function only once. If this function returns PLUGIN_SKIP,
// IDA will never load it again. If it returns PLUGIN_OK, IDA will unload the plugin
// but remember that the plugin agreed to work with the database. The plugin will
// be loaded again if the user invokes it by pressing the hotkey or selecting it
// from the menu. After the second load, the plugin will stay in memory.
// 
// returns:	PLUGIN_OK if plugin is supported, PLUGIN_SKIP if plugin isn't supported
int idaapi PluginStartup(void)
{
	// Insert tests here to determine if this plugin can be used
	// with the database being loaded. A common test is to check the
	// processor type for plugins that only support particular processors.
	
	// This tests if the processor type is PPC
	// If it is PPC then return OK to show that the plugin is supported
	if ( ph.id == PLFM_PPC )
		return PLUGIN_OK;
	
	// If the processor isn't PPC then this plugin should not be used
	// with the database being loaded, so return SKIP.
	return PLUGIN_SKIP;
}


// IDA will call this function when the user asks to exit. This function is *not*
// called in the case of emergency exits.
void idaapi PluginShutdown(void)
{
	// Any cleanup code that needs to be done on exit goes here
}

#define GPR_COUNT 32
#define FPR_COUNT 32
#define G_STR_SIZE 256
char g_insn[G_STR_SIZE];
char g_mnem[G_STR_SIZE];
char g_opnd[UA_MAXOP][G_STR_SIZE];
typedef qvector<bool> coverage;
coverage func_map;

void ProcessFunction(func_t *p_func, ea_t rtoc_ea, const unsigned long *in_gpr = NULL, const bool *in_act = NULL);
void ProcessFunction(ea_t start_ea, ea_t end_ea, ea_t rtoc_ea, const unsigned long *in_gpr = NULL, const bool *in_act = NULL);

// This is the main plugin function. This code gets executed everytime
// your plugin is executed.
// 
// args:	param: Input argument specified in the "plugins.cfg" file.
void idaapi PluginMain(int param)
{
// 	func_t* p_func = get_func(get_screen_ea());
// 	if(p_func)
// 	{
// 		// process the current function
// 		ProcessFunction(p_func, 0xA90BF0);
// 		return;
// 	}

	segment_t *p_seg = get_segm_by_name(".opd");

	if(p_seg == NULL)
	{
		info(".opd segment not found, so can't run PS3 %rtoc Fixer!\n");
		return;
	}

	ea_t seg_start = p_seg->startEA;
	ea_t seg_end = p_seg->endEA;
	ea_t seg_ea = seg_end;
	do
	//for(ea_t seg_ea=seg_start; seg_ea<seg_end; seg_ea+=8)
	{
		seg_ea -= 8;

		ea_t func_ea = get_long(seg_ea);
		ea_t rtoc_ea = get_long(seg_ea + 4);

		func_t* p_func = get_func(func_ea);

		if (!p_func ||
			p_func->startEA != func_ea)
		{
			if (p_func)
			{
				del_func(p_func->startEA);
			}
			add_func(func_ea, BADADDR);
			p_func = get_func(func_ea);
		}

		if(p_func)
		{
			// resize function map
			func_map.resize((p_func->endEA - p_func->startEA) >> 2);
			// clear processed status
			memset(&func_map.front(), 0, sizeof(bool) * func_map.size());
			// inform user of processing progress
			msg("[%08d/%08d] Processing Function - [0x%08X - 0x%08X]...", get_func_num(func_ea), get_func_qty(), p_func->startEA, p_func->endEA);
			// process the current function
			ProcessFunction(p_func, rtoc_ea);
			// function processing complete
			msg("completed.\n");
		}
	}
	while (seg_ea > seg_start);
}

void ProcessFunction(func_t *p_func, ea_t rtoc_ea, const unsigned long *in_gpr, const bool *in_act)
{
	ProcessFunction(p_func->startEA, p_func->endEA, rtoc_ea, in_gpr, in_act);
}
void ProcessFunction(ea_t start_ea, ea_t end_ea, ea_t rtoc_ea, const unsigned long *in_gpr, const bool *in_act)
{
	unsigned long g_gpr[GPR_COUNT*8];
	bool g_act[GPR_COUNT*8];

	if (in_gpr)
		memcpy(g_gpr, in_gpr, sizeof(g_gpr));
	else
		memset(g_gpr, 0, sizeof(g_gpr));

	if (in_act)
		memcpy(g_act, in_act, sizeof(g_act));
	else
		memset(g_act, 0, sizeof(g_act));

	// special case for code relocated after end of function
	// may cause false positives
	if (!g_act[2])
	{
		// initialize %rtoc register
		g_gpr[2] = rtoc_ea;
		g_act[2] = true;
	}

	func_t *p_func = get_func(start_ea);

	// scan entire function
	ea_t start = start_ea;
	ea_t end = end_ea;
	for(ea_t ea=start; ea<end; ea+=4)
	{
		ea_t ea_loc = (ea - p_func->startEA) >> 2;

		if(!decode_insn(ea) || func_map[ea_loc])
			continue;

		func_map[ea_loc] = true;

		insn_t l_cmd = cmd;

		// get mnemonic
		//ua_mnem(ea, g_mnem, sizeof(g_mnem));

		bool reg_used = false;

		int iOp = 0;
		for (; iOp < UA_MAXOP; ++iOp)
		{
			g_opnd[iOp][0] = 0;
			if (l_cmd.Operands[iOp].type == o_void)
				break;

			optype_t type = l_cmd.Operands[iOp].type;
			uint16 reg = l_cmd.Operands[iOp].reg;

			switch (type)
			{
			case o_reg:
			case o_phrase:
			case o_displ:
				{
					reg_used = (reg < (GPR_COUNT + FPR_COUNT)) && (reg_used || ((reg == 2) || g_act[reg]));
				}
				break;
			case o_far:
			case o_near:
				{
					switch (l_cmd.itype)
					{
					case PPC_b:          // Branch
					case PPC_bc:         // Branch Conditional
					case PPC_bdnz:       // CTR--; branch if CTR non-zero
					case PPC_bdz:        // CTR--; branch if CTR zero
					case PPC_blt:        // Branch if less than
					case PPC_ble:        // Branch if less than or equal
					case PPC_beq:        // Branch if equal
					case PPC_bge:        // Branch if greater than or equal
					case PPC_bgt:        // Branch if greater than
					case PPC_bne:        // Branch if not equal
						{
							reg_used = true;
						}
						break;
					default:
						{
							reg_used = reg_used || false;
						}
						break;
					}
				}
				break;
			}

			// get operand string
			//ua_outop2(ea, &g_opnd[iOp][0], sizeof(g_opnd[iOp]), iOp);
			//tag_remove(&g_opnd[iOp][0], &g_opnd[iOp][0], sizeof(g_opnd[iOp]));
			//ua_outop2(ea, g_insn, sizeof(g_insn), iOp);
			//tag_remove(g_insn, g_insn, 0);
		}

		if (iOp > 0 && reg_used)
		{
			switch (l_cmd.itype)
			{
			case PPC_mr:
				{
					if (g_act[l_cmd.Op2.reg])
					{
						g_gpr[l_cmd.Op1.reg] = g_gpr[l_cmd.Op2.reg];
						g_act[l_cmd.Op1.reg] = true;
					}
				}
				break;
			case PPC_addi:
				{
					if (g_act[l_cmd.Op2.reg])
					{
						g_gpr[l_cmd.Op1.reg] = g_gpr[l_cmd.Op2.reg] + l_cmd.Op3.value;
						g_act[l_cmd.Op1.reg] = true;
					}
				}
				break;
			case PPC_addis:
				{
					if (g_act[l_cmd.Op2.reg])
					{
						g_gpr[l_cmd.Op1.reg] = g_gpr[l_cmd.Op2.reg] + (l_cmd.Op3.value << 16);
						g_act[l_cmd.Op1.reg] = true;
					}
				}
				break;
			case PPC_bc:         // Branch Conditional
				{
					ea_t addr = l_cmd.Op3.addr;
					func_t *p_branch = get_func(addr);
					if ((p_func == p_branch) && (ea < addr))
					{
						ea_t addr_loc = (addr - p_func->startEA) >> 2;
						if (!func_map[addr_loc])
						{
							ProcessFunction(addr, end, (ea_t)g_gpr[2], g_gpr, g_act);
						}
					}
				}
				break;
			case PPC_bdnz:       // CTR--; branch if CTR non-zero
			case PPC_bdz:        // CTR--; branch if CTR zero
			case PPC_blt:        // Branch if less than
			case PPC_ble:        // Branch if less than or equal
			case PPC_beq:        // Branch if equal
			case PPC_bge:        // Branch if greater than or equal
			case PPC_bgt:        // Branch if greater than
			case PPC_bne:        // Branch if not equal
				{
					ea_t addr = l_cmd.Op2.addr;
					func_t *p_branch = get_func(addr);
					if ((p_func == p_branch) && (ea < addr))
					{
						ea_t addr_loc = (addr - p_func->startEA) >> 2;
						if (!func_map[addr_loc])
						{
							ProcessFunction(addr, end, (ea_t)g_gpr[2], g_gpr, g_act);
						}
					}
				}
				break;
			case PPC_b:          // Branch
				{
					ea_t addr = l_cmd.Op1.addr;
					func_t *p_branch = get_func(addr);
					if ((p_func == p_branch) && (ea < addr))
					{
						ea_t addr_loc = (addr - p_func->startEA) >> 2;
						if (!func_map[addr_loc])
						{
							ProcessFunction(addr, end, (ea_t)g_gpr[2], g_gpr, g_act);
						}
					}
				}
				break;
			case PPC_or:
				{
					if (g_act[l_cmd.Op1.reg] = (g_act[l_cmd.Op2.reg] && g_act[l_cmd.Op3.reg]))
						g_gpr[l_cmd.Op1.reg] = g_gpr[l_cmd.Op2.reg] | g_gpr[l_cmd.Op3.reg];
				}
				break;
			case PPC_ori:
				{
					if (g_act[l_cmd.Op1.reg] = g_act[l_cmd.Op2.reg])
						g_gpr[l_cmd.Op1.reg] = g_gpr[l_cmd.Op2.reg] | l_cmd.Op3.value;
				}
				break;
			case PPC_oris:
				{
					if (g_act[l_cmd.Op1.reg] = g_act[l_cmd.Op2.reg])
						g_gpr[l_cmd.Op1.reg] = g_gpr[l_cmd.Op2.reg] | (l_cmd.Op3.value << 16);
				}
				break;
			case PPC_ld:
				{
					if (l_cmd.Op1.reg == 2 && l_cmd.Op2.reg == 1)
					{
						// assuming restoring from saved stack address
						g_act[l_cmd.Op1.reg] = true;
					}
					else //if (g_act[l_cmd.Op2.reg])
					{
						// safety net, better to miss detection than falsely detect
						// special consideration taken for %r30
						if (l_cmd.Op1.reg != 30)
						{
							g_gpr[l_cmd.Op1.reg] = 0;
							g_act[l_cmd.Op1.reg] = false;
						}
					}
				}
				break;
			case PPC_li:
				{
					g_gpr[l_cmd.Op1.reg] = l_cmd.Op2.value;
					g_act[l_cmd.Op1.reg] = true;
				}
				break;
			case PPC_lis:
				{
					g_gpr[l_cmd.Op1.reg] = l_cmd.Op2.value << 16;
					g_act[l_cmd.Op1.reg] = true;
				}
				break;
			case PPC_lfs:
			case PPC_lwz:
			case PPC_lhz:
			case PPC_lbz:
				{
					if (l_cmd.Op1.reg == 2 && l_cmd.Op2.reg == 1)
						;
					else if ((l_cmd.Op2.reg == 2) || (g_act[l_cmd.Op2.reg]))
					{
						ea_t addr = g_gpr[l_cmd.Op2.reg] + l_cmd.Op2.addr;

						if (g_act[l_cmd.Op1.reg] = isEnabled(addr))
						{
							flags_t flags = get_flags_novalue(addr);
							add_dref(ea, addr, (dref_t)(/*XREF_USER|*/dr_R));

							if (g_act[l_cmd.Op1.reg] = isLoaded(addr))
							{
								uint32 value = 0; //get_long(addr);
								switch (l_cmd.itype)
								{
								case PPC_lfs:
								case PPC_lwz:
									value = get_long(addr);
									break;
								case PPC_lhz:
									value = get_word(addr);
									break;
								case PPC_lbz:
								default:
									value = get_byte(addr);
									break;
								}
								g_gpr[l_cmd.Op1.reg] = value;
							}
						}
					}
					else
					{
						// safety net, better to miss detection than falsely detect
						// special consideration taken for %r30
						if (l_cmd.Op1.reg != 30)
						{
							g_gpr[l_cmd.Op1.reg] = 0;
							g_act[l_cmd.Op1.reg] = false;
						}
					}
				}
				break;
			default:
				{
					if (l_cmd.Op1.type == o_reg && g_act[l_cmd.Op1.reg])
					{
						// if not storing the value...
						if (!((l_cmd.itype >= PPC_b     && l_cmd.itype <= PPC_cmpli) ||
							(  l_cmd.itype >= PPC_cmpwi && l_cmd.itype <= PPC_cmpld) ||
							(  l_cmd.itype >= PPC_stb   && l_cmd.itype <= PPC_stwx)))
						{
							// safety net, better to miss detection than falsely detect
							// special consideration taken for %r30
							if (l_cmd.Op1.reg != 30)
							{
								g_gpr[l_cmd.Op1.reg] = 0;
								g_act[l_cmd.Op1.reg] = false;
							}
						}
					}
				}
				break;
			}

			// special case for code relocated after end of function
			// may cause false positives
			if (!g_act[2])
			{
				// initialize %rtoc register
				g_gpr[2] = rtoc_ea;
				//g_act[2] = true;
			}
		}
	}
}



// 
// Strings required for IDA Pro's PLUGIN descriptor block
// 

const char G_PLUGIN_COMMENT[]	=	"IDA PS3 %rtoc Fixer Plugin";
const char G_PLUGIN_HELP[]		=	"This is a plugin to help fix references to addresses"
									"made through the PS3 %rtoc register.\n";
const char G_PLUGIN_NAME[]		=	"PS3 %rtoc Fixer";
const char G_PLUGIN_HOTKEY[]	=	"Ctrl-F11";



// 
// This 'PLUGIN' data block is how IDA Pro interfaces with this plugin.
// 
plugin_t PLUGIN =
{
	// values
	IDP_INTERFACE_VERSION,
	0,						// plugin flags
	
	// functions
	PluginStartup,			// initialize and test if plugin is supported
	PluginShutdown,			// terminate. this pointer may be NULL.
	PluginMain,				// invoke plugin
	
	// strings
	(char*)G_PLUGIN_COMMENT,// long comment about the plugin (may appear on status line or as a hint)
	(char*)G_PLUGIN_HELP,	// multiline help about the plugin
	(char*)G_PLUGIN_NAME,	// the preferred short name of the plugin, used by menu system
	(char*)G_PLUGIN_HOTKEY	// the preferred hotkey to run the plugin
};
