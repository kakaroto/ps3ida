/**************************************************************************************************
*
*	$Header::                                                                                     $
*
*	PowerPC Altivec/VMX Extension Module
*
*	The PowerPC processor module in IDA Pro 4.8 does not handle Altivec/VMX instructions. Many 
*	well-known PowerPC implementations include support for Altivec (such as the Apple G4/G5 range, 
*	or the majority of next generation game consoles). Fortunately IDA Pro supports the concept of
*	extension modules that can add support for non-standard instructions, so this extension adds 
*	support for the Altivec instruction set.
*
*
*	INSTALLATION
*	------------
*
*	Place the two processor extension modules (ppcAltivec.plw and ppcAltivec.p64) within your
*	IDA Pro 'plugins' directory. By default the plugin is active when dealing with PPC code, but
*	you can disable/re-enable the plugin by using the entry in the Edit/Plugins menu. If you want 
*	the plugin to be disabled on load, you will have to edit this source code. Change the value of
*	g_HookState to 'kDisabled' and rebuild.  
*
*
*	NOTES
*	-----
*	
*	The versions of ppc.w32 and ppc64.w64 that were in initial distributions of IDA Pro 4.8 contain
*	a flaw that will trigger an illegal read of memory when used with this extension. If you happen
*	to encounter crashes in these modules, I would recommend that you contact Data Rescue, 
*	specifically Ilfak Guilfanov - ig@datarescue.com - to obtaining corrected versions of these
*	modules, as I did.
*
*
*	CHANGES
*	-------
*
*	27.03.05	Dean		V1.0	Created
*
*	14.05.05	Dean		V1.1	Correction to operand register number extraction.
*									Correction to operand order for vmaddfp.
*									Now handles initial analysis without any additional hassle. 
*									Added support for Altivec opcodes with 4 parameters.
*
*	22.05.05	Dean		V1.2	Added support for auto comments.
*
*	26.09.05	Dean		V1.3	Support for IDA Pro 4.9
*
*	07.12.10	xorloser	V1.8	Support for Gekko instructions merged from the Gekko
*									extension module created by HyperIris. Also incldued
*									support for SPRG names for PS3 as added by Tridentsx.
*
***************************************************************************************************/

#define	PPCALTIVEC_VERSION	"V1.8"

/***************************************************************************************************
*
*	Strings required for IDA Pro's PLUGIN descriptor block
*
***************************************************************************************************/

char	g_pluginName[]	=	"PowerPC Altivec Extension " PPCALTIVEC_VERSION " with support for VMX128, Xbox360(Xenon), PS3(CellBE) and GC/WII(Gekko).";
char	g_pluginHelp[]	=	"This plugin enables recognition of many extra processor specific instructions\n"
							"when using IDA Pro's PowerPC processor module.\n"
							"The added instructions support Altivec, VMX128, Xbox360(Xenon), PS3(CellBE) and GC/WII(Gekko).\n";


// SDK 4.8's "pro.h" (line 718) has a signed/unsigned mismatch, so we disable this warning..
#pragma warning( disable:4018 )		

#include <ida.hpp>
#include <idp.hpp>
#include <name.hpp>
#include <bytes.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

/***************************************************************************************************
*
*	Data needed to maintain plugin state
*
***************************************************************************************************/

enum	HookState
{
	kDefault,
	kEnabled,
	kDisabled,
};

static HookState	g_HookState = kEnabled;
static netnode		g_AltivecNode;
static const char	g_AltivecNodeName[] = "$ PowerPC Altivec Extension Parameters";



// -------------------------------------------------------------------------------------------------
// Operand identifiers (they map into g_altivecOperands array)

enum	altivec_operand_id
{	
	NO_OPERAND,
	VA,
	VB,
	VC,
	VD,		VS = VD,
	SIMM,
	UIMM,
	SHB,
	RA,
	RB,
	STRM,

	// Takires: Added operand identifiers
	RS,		RT = RS,
	L15,
	L9_10,	LS = L9_10,
	L10,	L = L10,
	VD128,	VS128 = VD128,
	CRM,
	VA128,
	VB128,
	VC128,
	VPERM128,
	VD3D0,
	VD3D1,
	VD3D2,
	RA0,

//	LEV,
//	FL1,
//	FL2,
//	SV,
//	SVC_LEV,
	SPR,
	
	// gekko specific
	FA,
	FB,
	FC,
	FD,
	FS = FD,
	
	crfD,

	WB,
	IB,
	WC,
	IC,
//	D,

//	RA,
//	RB,
	DRA,
	DRB,
};

// -------------------------------------------------------------------------------------------------
// Structure used to define an operand 

struct	cbea_sprg
{
	int					sprg;
	const char*				shortName;
	const char*				comment;
};

cbea_sprg g_cbeaSprgs[] =
{
	{	1023, "PIR",				"Processor Identification Register" },
	{	1022, "BP_VR",				"CBEA-Compliant Processor Version Register" },
	{	1017, "HID6",				"Hardware Implementation Register 6" },
	{	1015, "DABRX",				"Data Address Breakpoint Register Extension" },
	{	1013, "DABR",				"Data Address Breakpoint Register" },
	{	1012, "HID4",				"Hardware Implementation Register 4" },
	{	1009, "HID1",				"Hardware Implementation Register 1" },
	{	1008, "HID0",				"Hardware Implementation Register 0"},
	{	981, "ICIDR",				"Instruction Class ID Register 1" },
	{	980, "IRMR1",				"Instruction Range Mask Register 1" },
	{	979, "IRSR1",				"Instruction Range Start Register 1" },
	{	978, "ICIDR0",				"Instruction Class ID Register 0" },
	{	977, "IRMR0",				"Instruction Range Mask Register 0" },
	{	976, "IRSR0",				"Instruction Range Start Register 0" },
	{	957, "DCIDR1",				"Data Class ID Register 1" },
	{	956, "DRMR1",				"Data Range Mask Register 1" },
	{	955, "DRSR1",				"Data Range Start Register 1" },
	{	954, "DCIDR0",				"Data Class ID Register 0" },
	{	953, "DRMR0",				"Data Range Mask Register 0" },
	{	952, "DRSR0",				"Data Range Start Register 0" },
	{	951, "PPE_TLB_RMT",			"PPE Translation Lookaside Buffer RMT Register" },
	{	949, "PPE_TLB_RPN",			"PPE Translation Lookaside Buffer Real-Page Number" },
	{	948, "PPE_TLB_VPN",			"PPE Translation Lookaside Buffer Virtual-Page Number" },
	{	947, "PPE_TLB_Index",		"PPE Translation Lookaside Buffer Index Register" },
	{	946, "PPE_TLB_Index_Hint",	"PPE Translation Lookaside Buffer Index Hint Register" },
	{	922, "TTR",					"Thread Switch Timeout Register" },
	{	921, "TSCR",				"Thread Switch Control Register" },
	{	897, "TSRR",				"Thread Status Register Remote" },
	{	896, "TSRL",				"Thread Status Register Local" },
	{	319, "LPIDR",				"Logical Partition Identity Register" },
	{	318, "LPCR",				"Logical Partition Control Register" },
	{	315, "HSRR1",				"Hypervisor Machine Status Save/Restore Register 1" },
	{	314, "HSRR0",				"Hypervisor Machine Status Save/Restore Register 0" },
	{	313, "HRMOR",				"Hypervisor Real Mode Offset Register" },
	{	312, "RMOR",				"Real Mode Offset Register" },
	{	310, "HDEC",				"Hypervisor Decrementer Register" },
	{	305, "HSPRG1",				"Hypervisor Software Use Special Purpose Register 1" },
	{	304, "HSPRG0",				"Hypervisor Software Use Special Purpose Register 0" },
	{	287, "PVR",					"PPE Processor Version Register" },
	{	285, "TBU",					"Time Base Upper Register - Write Only" },
	{	284, "TBL",					"Time Base Lower Register - Write Only" },
	{	275, "SPRG3",				"Software Use Special Purpose Register 3" },
	{	274, "SPRG2",				"Software Use Special Purpose Register 2" },
	{	273, "SPRG1",				"Software Use Special Purpose Register 1" },
	{	272, "SPRG0",				"Software Use Special Purpose Register 0" },
	{	269, "TBU",					"Time Base Upper Register - Read Only" },
	{	268, "TB",					"Time Base Register - Read Only" },
	{	259, "SPRG3",				"Software Use Special Purpose Register 3" },
	{	256, "VRSAVE",				"VXU Register Save" },
	{	152, "CTRL",				"Control Register Write" },
	{	136, "CTRL",				"Control Register Read" },
	{	29, "ACCR",					"Address Compare Control Register" },
	{	27, "SRR1",					"Machine Status Save/Restore Register 1" },
	{	26, "SRR0",					"Machine Status Save/Restore Register 0" },
	{	25, "SDR1",					"Storage Description Register 1" },
	{	22, "DEC",					"Decrementer Register" },
	{	19, "DAR",					"Data Address Register" },
	{	18, "DSISR",				"Data Storage Interrupt Status Register" },
	{	9, "CTR",					"Count Register" },
	{	8, "LR",					"Link Register" },
	{	1, "XER",					"Fixed-Point exception Register" },
};

struct	altivec_operand
{
	int					bits;
	int					shift;
};

altivec_operand	g_altivecOperands[] =  // {Length, Start bit}
{
	{ 0, 0		},	// No Operand
	{ 5, 16		},	// VA
	{ 5, 11		},	// VB
	{ 5, 6		},	// VC
	{ 5, 21		},	// VD / VS
	{ 5, 16		},	// SIMM
	{ 5, 16		},	// UIMM
	{ 4, 6		},	// SHB
	{ 5, 16		},	// RA
	{ 5, 11		},	// RB
	{ 2, 21		},	// STRM

	// Takires: Added operands
	{ 5, 21		},	// RS / RT
	{ 1, 16		},	// L15
	{ 2, 21		},	// L9_10
	{ 1, 21		},	// L10
	{ 0, 0		},	// VD128 / VS128
	{ 8, 12		},	// CRM
	{ 0, 0		},	// VA128
	{ 0, 0		},	// VB128
	{ 3, 8		},	// VC128
	{ 0, 0		},	// VPERM128
	{ 3, 18		},	// VD3D0
	{ 2, 16		},	// VD3D1
	{ 2, 6		},	// VD3D2
	{ 5, 16		},	// RA0
//	{ 7, 5      },	// LEV
//	{ 4, 12     },	// FL1
//	{ 3, 2      },	// FL2
//	{ 14, 2     },	// SV
//	{ 7, 5      },	// SVC_LEV
	{ 10,11     },	// SPR


	// gekko specific
	{ 5, 16	},	// FA
	{ 5, 11	},	// FB
	{ 5, 6	},	// FC
	{ 5, 21	},	// FD/FS

	{ 3, 23	},	//crfD,


	{ 1, 16	},	//WB,
	{ 3, 12	},	//IB,
	{ 1, 10	},	//WC,
	{ 3, 7	},	//IC,
//	{ 12, 0	},	//D,

//	{ 5, 16	},	// RA
//	{ 5, 11	},	// RB
	{ 5, 16 },//DRA,
	{ 5, 11 },//DRB,
};




// -------------------------------------------------------------------------------------------------
// Macros used to define opcode table

#define OP(x)				((((unsigned long)(x)) & 0x3f) << 26)
#define OP_MASK				OP(0x3f)
#define SC(op, sa, lk)		(OP(op)  | ((((unsigned long)(sa)) & 1) << 1) | ((lk) & 1))
#define SC_MASK				(OP_MASK | (((unsigned long)0x3ff) << 16) | (((unsigned long)1) << 1) | 1)
#define VX(op, xop)			(OP(op)  | (((unsigned long)(xop)) & 0x7ff))
#define VX_MASK				VX(0x3f, 0x7ff)
#define VXR(op, xop, rc)	(OP(op)  | (((rc) & 1) << 10) | (((unsigned long)(xop)) & 0x3ff))
#define VXR_MASK			VXR(0x3f, 0x3ff, 1)
#define X(op, xop)			(OP(op)  | ((((unsigned long)(xop)) & 0x3ff) << 1))
#define X_MASK				XRC (0x3f, 0x3ff, 1)
#define RA_MASK				(0x1f << 16)
#define RB_MASK				(0x1f << 11)
#define RT_MASK				(0x1f << 21)
#define VXA(op, xop)		(OP(op)  | (((unsigned long)(xop)) & 0x03f))
#define VXA_MASK			VXA(0x3f, 0x3f)
#define XDSS(op, xop, a)	(X((op), (xop)) | ((((unsigned long)(a)) & 1) << 25))
#define XDSS_MASK			XDSS(0x3f, 0x3ff, 1)

#define VX128(op, xop)		(OP(op) | (((unsigned long)(xop)) & 0x3d0))
#define VX128_MASK			VX(0x3f, 0x3d0)
#define VX128_1(op, xop)	(OP(op) | (((unsigned long)(xop)) & 0x7f3))
#define VX128_1_MASK		VX(0x3f, 0x7f3)
#define VX128_2(op, xop)	(OP(op) | (((unsigned long)(xop)) & 0x210))
#define VX128_2_MASK		VX(0x3f, 0x210)
#define VX128_3(op, xop)	(OP(op) | (((unsigned long)(xop)) & 0x7f0))
#define VX128_3_MASK		VX(0x3f, 0x7f0)
#define VX128_P(op, xop)	(OP(op) | (((unsigned long)(xop)) & 0x630))
#define VX128_P_MASK		VX(0x3f, 0x630)
#define VX128_4(op, xop)	(OP(op) | (((unsigned long)(xop)) & 0x730))
#define VX128_4_MASK		VX(0x3f, 0x730)
#define VX128_5(op, xop)	(OP(op) | (((unsigned long)(xop)) & 0x10))
#define VX128_5_MASK		VX(0x3f, 0x10)

#define XFX(op, xop, a)		(X(op, xop) | ((((unsigned long)(a)) & 1) << 20))
#define XFX_MASK			XFX(0x3f, 0x3ff, 1)
#define XRT(op, xop, rt)	(X(op, xop) | ((((unsigned long)(rt)) & 0x1F) << 21))
#define XRT_MASK			XRT(0x3f, 0x3ff, 0x1f)
#define XRA(op, xop, ra)	(X(op, xop) | ((((unsigned long)(ra)) & 0x1F) << 16))
#define XRA_MASK			(X_MASK | RA_MASK)
#define XRC(op, xop, rc)	(X((op), (xop)) | ((rc) & 1))
#define XRARB_MASK			(X_MASK | RA_MASK | RB_MASK)
#define XRLARB_MASK			(XRARB_MASK & ~((unsigned long) 1 << 16))
#define XSYNC(op, xop, l)	(X(op, xop) | ((((unsigned long)(l)) & 3) << 21))
#define XRTRA_MASK			(X_MASK | RT_MASK | RA_MASK)
#define XRTLRA_MASK			(XRTRA_MASK & ~((unsigned long) 1 << 21))


// gekko specific

#define OPS(op, xop)		(OP (op) | ((((unsigned long)(xop)) & 0x1f) << 1))
#define OPSC(op, xop, rc)	(OPS ((op), (xop)) | ((rc) & 1))
//#define OPSC(op, xop, rc)	(OPS ((op), (xop)) | rc)
#define OPS_MASK			OPSC (0x3f, 0x1f, 1)
#define OPS_MASK_DOT		OPSC (0x3f, 0x1f, 1)

#define OPM(op, xop)		(OP (op) | ((((unsigned long)(xop)) & 0x3f) << 1))
#define OPMC(op, xop, rc)	(OPM ((op), (xop)) | ((rc) & 1))
#define OPM_MASK			OPMC (0x3f, 0x3f, 0)

#define OPL(op, xop)		(OP (op) | ((((unsigned long)(xop)) & 0x3ff) << 1))
#define OPLC(op, xop, rc)	(OPL ((op), (xop)) | ((rc) & 1))
//#define OPLC(op, xop, rc)	(OPL ((op), (xop)) | rc)
#define OPL_MASK			OPLC (0x3f, 0x3ff, 1)
#define OPL_MASK_DOT		OPLC (0x3f, 0x3ff, 1)



// -------------------------------------------------------------------------------------------------
// Opcode identifiers (they map into g_altivecOpcodes array)

enum altivec_insn_type_t
{
	altivec_insn_start = CUSTOM_CMD_ITYPE,

	altivec_lvebx = altivec_insn_start,
	altivec_lvehx,
	altivec_lvewx,
	altivec_lvsl,
	altivec_lvsr,
	altivec_lvx,
	altivec_lvxl,
	altivec_stvebx,
	altivec_stvehx,
	altivec_stvewx,
	altivec_stvx,
	altivec_stvxl,
	altivec_dst,	
	altivec_dstt,	
	altivec_dstst,	
	altivec_dststt,	
	altivec_dss,	
	altivec_dssall,	
	altivec_mfvscr,
	altivec_mtvscr,
	altivec_vaddcuw,	
	altivec_vaddfp,
	altivec_vaddsbs,
	altivec_vaddshs,
	altivec_vaddsws,
	altivec_vaddubm,
	altivec_vaddubs,
	altivec_vadduhm,
	altivec_vadduhs,
	altivec_vadduwm,
	altivec_vadduws,
	altivec_vand,
	altivec_vandc,
	altivec_vavgsb,
	altivec_vavgsh,
	altivec_vavgsw,
	altivec_vavgub,
	altivec_vavguh,
	altivec_vavguw,
	altivec_vcfsx,
	altivec_vcfux,
	altivec_vcmpbfp,
	altivec_vcmpbfp_c,
	altivec_vcmpeqfp,
	altivec_vcmpeqfp_c,
	altivec_vcmpequb,
	altivec_vcmpequb_c,
	altivec_vcmpequh,
	altivec_vcmpequh_c,
	altivec_vcmpequw,
	altivec_vcmpequw_c,
	altivec_vcmpgefp,
	altivec_vcmpgefp_c,
	altivec_vcmpgtfp,
	altivec_vcmpgtfp_c,
	altivec_vcmpgtsb,
	altivec_vcmpgtsb_c,
	altivec_vcmpgtsh,
	altivec_vcmpgtsh_c,
	altivec_vcmpgtsw,
	altivec_vcmpgtsw_c,
	altivec_vcmpgtub,
	altivec_vcmpgtub_c,
	altivec_vcmpgtuh,
	altivec_vcmpgtuh_c,
	altivec_vcmpgtuw,
	altivec_vcmpgtuw_c,
	altivec_vctsxs,
	altivec_vctuxs,
	altivec_vexptefp,
	altivec_vlogefp,
	altivec_vmaddfp,
	altivec_vmaxfp,
	altivec_vmaxsb,
	altivec_vmaxsh,
	altivec_vmaxsw,
	altivec_vmaxub,
	altivec_vmaxuh,
	altivec_vmaxuw,
	altivec_vmhaddshs,
	altivec_vmhraddshs,
	altivec_vminfp,
	altivec_vminsb,
	altivec_vminsh,
	altivec_vminsw,
	altivec_vminub,
	altivec_vminuh,
	altivec_vminuw,
	altivec_vmladduhm,
	altivec_vmrghb,
	altivec_vmrghh,
	altivec_vmrghw,
	altivec_vmrglb,
	altivec_vmrglh,
	altivec_vmrglw,
	altivec_vmsummbm,
	altivec_vmsumshm,
	altivec_vmsumshs,
	altivec_vmsumubm,
	altivec_vmsumuhm,
	altivec_vmsumuhs,
	altivec_vmulesb,
	altivec_vmulesh,
	altivec_vmuleub,
	altivec_vmuleuh,
	altivec_vmulosb,
	altivec_vmulosh,
	altivec_vmuloub,
	altivec_vmulouh,
	altivec_vnmsubfp,
	altivec_vnor, 
	altivec_vor,
	altivec_vperm,
	altivec_vpkpx,
	altivec_vpkshss,
	altivec_vpkshus,
	altivec_vpkswss,
	altivec_vpkswus,
	altivec_vpkuhum,
	altivec_vpkuhus,
	altivec_vpkuwum,
	altivec_vpkuwus,
	altivec_vrefp,
	altivec_vrfim,
	altivec_vrfin,
	altivec_vrfip,
	altivec_vrfiz,
	altivec_vrlb, 
	altivec_vrlh,
	altivec_vrlw, 
	altivec_vrsqrtefp,
	altivec_vsel,
	altivec_vsl,
	altivec_vslb, 
	altivec_vsldoi,
	altivec_vslh, 
	altivec_vslo, 
	altivec_vslw, 
	altivec_vspltb,
	altivec_vsplth,
	altivec_vspltisb,
	altivec_vspltish,
	altivec_vspltisw,
	altivec_vspltw,
	altivec_vsr,
	altivec_vsrab,
	altivec_vsrah,
	altivec_vsraw,
	altivec_vsrb,
	altivec_vsrh, 
	altivec_vsro, 
	altivec_vsrw,
	altivec_vsubcuw,
	altivec_vsubfp,
	altivec_vsubsbs,
	altivec_vsubshs,
	altivec_vsubsws,
	altivec_vsububm,
	altivec_vsububs,
	altivec_vsubuhm,
	altivec_vsubuhs,
	altivec_vsubuwm,
	altivec_vsubuws,
	altivec_vsumsws,
	altivec_vsum2sws,
	altivec_vsum4sbs,
	altivec_vsum4shs,
	altivec_vsum4ubs,
	altivec_vupkhpx,
	altivec_vupkhsb,
	altivec_vupkhsh,
	altivec_vupklpx,
	altivec_vupklsb,
	altivec_vupklsh,
	altivec_vxor,

	// Takires: Added opcode identifiers
	vmx128_vsldoi128,
	vmx128_lvsl128,
	vmx128_lvsr128,
	vmx128_lvewx128,
	vmx128_lvx128,
	vmx128_stvewx128,
	vmx128_stvx128,
	vmx128_lvxl128,
	vmx128_stvxl128,
	vmx128_lvlx128,
	vmx128_lvrx128,
	vmx128_stvlx128,
	vmx128_stvrx128,
	vmx128_lvlxl128,
	vmx128_lvrxl128,
	vmx128_stvlxl128,
	vmx128_stvrxl128,
	vmx128_vperm128,
	vmx128_vaddfp128,
	vmx128_vsubfp128,
	vmx128_vmulfp128,
	vmx128_vmaddfp128,
	vmx128_vmaddcfp128,
	vmx128_vnmsubfp128,
	vmx128_vmsum3fp128,
	vmx128_vmsum4fp128,
	vmx128_vpkshss128,
	vmx128_vand128,
	vmx128_vpkshus128,
	vmx128_vandc128,
	vmx128_vpkswss128,
	vmx128_vnor128,
	vmx128_vpkswus128,
	vmx128_vor128,
	vmx128_vpkuhum128,
	vmx128_vxor128,
	vmx128_vpkuhus128,
	vmx128_vsel128,
	vmx128_vpkuwum128,
	vmx128_vslo128,
	vmx128_vpkuwus128,
	vmx128_vsro128,

	vmx128_vpermwi128,
	vmx128_vcfpsxws128,
	vmx128_vcfpuxws128,
	vmx128_vcsxwfp128,
	vmx128_vcuxwfp128,
	vmx128_vrfim128,
	vmx128_vrfin128,
	vmx128_vrfip128,
	vmx128_vrfiz128,
	vmx128_vpkd3d128,
	vmx128_vrefp128,
	vmx128_vrsqrtefp128,
	vmx128_vexptefp128,
	vmx128_vlogefp128,
	vmx128_vrlimi128,
	vmx128_vspltw128,
	vmx128_vspltisw128,
	vmx128_vupkd3d128,
	vmx128_vcmpeqfp128,
	vmx128_vcmpeqfp128c,
	vmx128_vrlw128,
	vmx128_vcmpgefp128,
	vmx128_vcmpgefp128c,
	vmx128_vslw128,
	vmx128_vcmpgtfp128,
	vmx128_vcmpgtfp128c,
	vmx128_vsraw128,
	vmx128_vcmpbfp128,
	vmx128_vcmpbfp128c,
	vmx128_vsrw128,
	vmx128_vcmpequw128,
	vmx128_vcmpequw128c,
	vmx128_vmaxfp128,
	vmx128_vminfp128,
	vmx128_vmrghw128,
	vmx128_vmrglw128,
	vmx128_vupkhsb128,
	vmx128_vupklsb128,

	vmx128_lvlx,
	vmx128_lvlxl,
	vmx128_lvrx,
	vmx128_lvrxl,
	vmx128_stvlx,
	vmx128_stvlxl,
	vmx128_stvrx,
	vmx128_stvrxl,

	std_attn,
	std_dbcz128,
	std_hvsc,
	std_mtspr, // To decode the SPR name
	std_mfspr, // To decode the SPR name
	std_ldbrx,
	std_mfocrf,
	std_mtmsr,
	std_mtmsrd,
	std_mtocrf,
	std_slbmte,
	std_stdbrx,
//	std_svc,
//	std_svcl,
//	std_svca,
//	std_svcla,
	std_lwsync,
	std_ptesync,
	std_sync,
	std_tlbiel,
	std_tlbie,
	std_tlbi,
	std_slbie,
	
	spec_callthru,
	spec_cctpl,
	spec_cctpm,
	spec_cctph,
	spec_db8cyc,
	spec_db10cyc,
	spec_db12cyc,
	spec_db16cyc,
	spec_02002000,
	
	
	// gekko specific
	gekko_psq_lx,
	gekko_psq_stx,
	gekko_psq_lux,
	gekko_psq_stux,
	gekko_psq_l,
	gekko_psq_lu,
	gekko_psq_st,
	gekko_psq_stu,

	gekko_ps_div,
	gekko_ps_div_dot,
	gekko_ps_sub,
	gekko_ps_sub_dot,
	gekko_ps_add,
	gekko_ps_add_dot,
	gekko_ps_sel,
	gekko_ps_sel_dot,
	gekko_ps_res,
	gekko_ps_res_dot,
	gekko_ps_mul,
	gekko_ps_mul_dot,
	gekko_ps_rsqrte,
	gekko_ps_rsqrte_dot,
	gekko_ps_msub,
	gekko_ps_msub_dot,
	gekko_ps_madd,
	gekko_ps_madd_dot,
	gekko_ps_nmsub,
	gekko_ps_nmsub_dot,
	gekko_ps_nmadd,
	gekko_ps_nmadd_dot,
	gekko_ps_neg,
	gekko_ps_neg_dot,
	gekko_ps_mr,
	gekko_ps_mr_dot,
	gekko_ps_nabs,
	gekko_ps_nabs_dot,
	gekko_ps_abs,
	gekko_ps_abs_dot,

	gekko_ps_sum0,
	gekko_ps_sum0_dot,
	gekko_ps_sum1,
	gekko_ps_sum1_dot,
	gekko_ps_muls0,
	gekko_ps_muls0_dot,
	gekko_ps_muls1,
	gekko_ps_muls1_dot,
	gekko_ps_madds0,
	gekko_ps_madds0_dot,
	gekko_ps_madds1,
	gekko_ps_madds1_dot,
	gekko_ps_cmpu0,
	gekko_ps_cmpo0,
	gekko_ps_cmpu1,
	gekko_ps_cmpo1,
	gekko_ps_merge00,
	gekko_ps_merge00_dot,
	gekko_ps_merge01,
	gekko_ps_merge01_dot,
	gekko_ps_merge10,
	gekko_ps_merge10_dot,
	gekko_ps_merge11,
	gekko_ps_merge11_dot,
	gekko_ps_dcbz_l,
};

// -------------------------------------------------------------------------------------------------
// Structure used to define an opcode

#define MAX_OPERANDS		6

struct	altivec_opcode
{
	altivec_insn_type_t	insn;
	const char*			name;
	unsigned int		opcode;
	unsigned int		mask;	
	unsigned char		operands[MAX_OPERANDS];
	const char*			description;			
};

altivec_opcode	g_altivecOpcodes[] = 
{
	{	altivec_lvebx,		"lvebx",		X(31, 7),		X_MASK,		{ VD, RA, RB },			"Load Vector Element Byte Indexed"	},
	{	altivec_lvehx,		"lvehx",		X(31, 39),		X_MASK,		{ VD, RA, RB },			"Load Vector Element Half Word Indexed"	},
	{	altivec_lvewx,		"lvewx",		X(31, 71),		X_MASK,		{ VD, RA, RB },			"Load Vector Element Word Indexed"	},
	{	altivec_lvsl,		"lvsl",			X(31, 6),		X_MASK,		{ VD, RA, RB },			"Load Vector for Shift Left"	},
	{	altivec_lvsr, 		"lvsr",			X(31, 38),		X_MASK,		{ VD, RA, RB },			"Load Vector for Shift Right"	},
	{	altivec_lvx,		"lvx",			X(31, 103), 	X_MASK,		{ VD, RA, RB },			"Load Vector Indexed"	},
	{	altivec_lvxl,		"lvxl",			X(31, 359), 	X_MASK,		{ VD, RA, RB },			"Load Vector Indexed LRU"	},
	{	altivec_stvebx,		"stvebx",		X(31, 135), 	X_MASK,		{ VS, RA, RB },			"Store Vector Element Byte Indexed"	},
	{	altivec_stvehx,		"stvehx",		X(31, 167), 	X_MASK,		{ VS, RA, RB },			"Store Vector Element Half Word Indexed"	},
	{	altivec_stvewx,		"stvewx",		X(31, 199), 	X_MASK,		{ VS, RA, RB },			"Store Vector Element Word Indexed"	},
	{	altivec_stvx,		"stvx",			X(31, 231), 	X_MASK,		{ VS, RA, RB },			"Store Vector Indexed"	},
	{	altivec_stvxl,		"stvxl",		X(31, 487), 	X_MASK,		{ VS, RA, RB },			"Store Vector Indexed LRU"	},
	{	altivec_dst,		"dst",			XDSS(31,342,0),	XDSS_MASK,	{ RA, RB, STRM },		"Data Stream Touch"	},
	{	altivec_dstt,		"dstt",			XDSS(31,342,1),	XDSS_MASK,	{ RA, RB, STRM },		"Data Stream Touch Transient"	},
	{	altivec_dstst,		"dstst",		XDSS(31,374,0),	XDSS_MASK,	{ RA, RB, STRM },		"Data Stream Touch for Store"	},
	{	altivec_dststt,		"dststt",		XDSS(31,374,1),	XDSS_MASK,	{ RA, RB, STRM },		"Data Stream Touch for Store Transient"	},
	{	altivec_dss,		"dss",			XDSS(31,822,0),	XDSS_MASK,	{ STRM },				"Data Stream Stop"	},
	{	altivec_dssall,		"dssall",		XDSS(31,822,1),	XDSS_MASK,	{ 0 },					"Data Stream Stop All"	},
	{	altivec_mfvscr,		"mfvscr",		VX(4, 1540),	VX_MASK,	{ VD },					"Move from Vector Status and Control Register"	},
	{	altivec_mtvscr,		"mtvscr",		VX(4, 1604),	VX_MASK,	{ VD },					"Move to Vector Status and Control Register"	},
	{	altivec_vaddcuw,	"vaddcuw",		VX(4, 384),		VX_MASK,	{ VD, VA, VB },			"Vector Add Carryout Unsigned Word"	},
	{	altivec_vaddfp,		"vaddfp",		VX(4, 10),		VX_MASK,	{ VD, VA, VB },			"Vector Add Floating Point"	},
	{	altivec_vaddsbs,	"vaddsbs",		VX(4, 768),		VX_MASK,	{ VD, VA, VB },			"Vector Add Signed Byte Saturate"	},
	{	altivec_vaddshs,	"vaddshs",		VX(4, 832),		VX_MASK,	{ VD, VA, VB },			"Vector Add Signed Half Word Saturate"	},
	{	altivec_vaddsws,	"vaddsws",		VX(4, 896),		VX_MASK,	{ VD, VA, VB },			"Vector Add Signed Word Saturate"	},
	{	altivec_vaddubm,	"vaddubm",		VX(4, 0),		VX_MASK,	{ VD, VA, VB },			"Vector Add Unsigned Byte Modulo"	},
	{	altivec_vaddubs,	"vaddubs",		VX(4, 512),		VX_MASK,	{ VD, VA, VB },			"Vector Add Unsigned Byte Saturate"	},
	{	altivec_vadduhm,	"vadduhm",		VX(4, 64),		VX_MASK,	{ VD, VA, VB },			"Vector Add Unsigned Half Word Modulo"	},
	{	altivec_vadduhs,	"vadduhs",		VX(4, 576),		VX_MASK,	{ VD, VA, VB },			"Vector Add Unsigned Half Word Saturate"	},
	{	altivec_vadduwm,	"vadduwm",		VX(4, 128),		VX_MASK,	{ VD, VA, VB },			"Vector Add Unsigned Word Modulo"	},
	{	altivec_vadduws,	"vadduws",		VX(4, 640),		VX_MASK,	{ VD, VA, VB },			"Vector Add Unsigned Word Saturate"	},
	{	altivec_vand,		"vand",			VX(4, 1028),	VX_MASK,	{ VD, VA, VB },			"Vector Logical AND"	},
	{	altivec_vandc,		"vandc",		VX(4, 1092),	VX_MASK,	{ VD, VA, VB },			"Vector Logical AND with Complement"	},
	{	altivec_vavgsb,		"vavgsb",		VX(4, 1282),	VX_MASK,	{ VD, VA, VB },			"Vector Average Signed Byte"	},
	{	altivec_vavgsh,		"vavgsh",		VX(4, 1346),	VX_MASK,	{ VD, VA, VB },			"Vector Average Signed Half Word"	},
	{	altivec_vavgsw,		"vavgsw",		VX(4, 1410),	VX_MASK,	{ VD, VA, VB },			"Vector Average Signed Word"	},
	{	altivec_vavgub,		"vavgub",		VX(4, 1026),	VX_MASK,	{ VD, VA, VB },			"Vector Average Unsigned Byte"	},
	{	altivec_vavguh,		"vavguh",		VX(4, 1090),	VX_MASK,	{ VD, VA, VB },			"Vector Average Unsigned Half Word"	},
	{	altivec_vavguw,		"vavguw",		VX(4, 1154),	VX_MASK,	{ VD, VA, VB },			"Vector Average Unsigned Word"	},
	{	altivec_vcfsx,		"vcfsx",		VX(4, 842),		VX_MASK,	{ VD, VB, UIMM },		"Vector Convert from Signed Fixed-Point Word"	},
	{	altivec_vcfux,		"vcfux",		VX(4, 778),		VX_MASK,	{ VD, VB, UIMM },		"Vector Convert from Unsigned Fixed-Point Word"	},
	{	altivec_vcmpbfp,	"vcmpbfp",		VXR(4, 966, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Bounds Floating Point"	},
	{	altivec_vcmpbfp_c,	"vcmpbfp.",		VXR(4, 966, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Bounds Floating Point (set CR6)"	},
	{	altivec_vcmpeqfp,	"vcmpeqfp",		VXR(4, 198, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Equal-to Floating Point"	},
	{	altivec_vcmpeqfp_c,	"vcmpeqfp.",	VXR(4, 198, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Equal-to Floating Point (set CR6)"	},
	{	altivec_vcmpequb,	"vcmpequb",		VXR(4, 6, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Equal-to Unsigned Byte"	},
	{	altivec_vcmpequb_c,	"vcmpequb.",	VXR(4, 6, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Equal-to Unsigned Byte (set CR6)"	},
	{	altivec_vcmpequh,	"vcmpequh",		VXR(4, 70, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Equal-to Unsigned Half Word"	},
	{	altivec_vcmpequh_c,	"vcmpequh.",	VXR(4, 70, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Equal-to Unsigned Half Word (set CR6)"	},
	{	altivec_vcmpequw,	"vcmpequw",		VXR(4, 134, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Equal-to Unsigned Word"	},
	{	altivec_vcmpequw_c,	"vcmpequw.",	VXR(4, 134, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Equal-to Unsigned Word (set CR6)"	},
	{	altivec_vcmpgefp,	"vcmpgefp",		VXR(4, 454, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than-or-Equal-to Floating Point"	},
	{	altivec_vcmpgefp_c,	"vcmpgefp.",	VXR(4, 454, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than-or-Equal-to Floating Point (set CR6)"	},
	{	altivec_vcmpgtfp,	"vcmpgtfp",		VXR(4, 710, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Floating Point"	},
	{	altivec_vcmpgtfp_c,	"vcmpgtfp.",	VXR(4, 710, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Floating Point (set CR6)"	},
	{	altivec_vcmpgtsb,	"vcmpgtsb",		VXR(4, 774, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Signed Byte"	},
	{	altivec_vcmpgtsb_c,	"vcmpgtsb.",	VXR(4, 774, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Signed Byte (set CR6)"	},
	{	altivec_vcmpgtsh,	"vcmpgtsh",		VXR(4, 838, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Signed Half Word"	},
	{	altivec_vcmpgtsh_c,	"vcmpgtsh.",	VXR(4, 838, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Signed Half Word (set CR6)"	},
	{	altivec_vcmpgtsw,	"vcmpgtsw",		VXR(4, 902, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Signed Word"	},
	{	altivec_vcmpgtsw_c,	"vcmpgtsw.",	VXR(4, 902, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Signed Word (set CR6)"	},
	{	altivec_vcmpgtub,	"vcmpgtub",		VXR(4, 518, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Unsigned Byte"	},
	{	altivec_vcmpgtub_c,	"vcmpgtub.",	VXR(4, 518, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Unsigned Byte (set CR6)"	},
	{	altivec_vcmpgtuh,	"vcmpgtuh",		VXR(4, 582, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Unsigned Half Word"	},
	{	altivec_vcmpgtuh_c,	"vcmpgtuh.",	VXR(4, 582, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Unsigned Half Word (set CR6)"	},
	{	altivec_vcmpgtuw,	"vcmpgtuw",		VXR(4, 646, 0),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Unsigned Word"	},
	{	altivec_vcmpgtuw_c,	"vcmpgtuw.",	VXR(4, 646, 1),	VXR_MASK,	{ VD, VA, VB },			"Vector Compare Greater-Than Unsigned Word (set CR6)"	},
	{	altivec_vctsxs,		"vctsxs",		VX(4, 970),		VX_MASK,	{ VD, VB, UIMM },		"Vector Convert to Signed Fixed-Point Word Saturate"	},
	{	altivec_vctuxs,		"vctuxs",		VX(4, 906),		VX_MASK,	{ VD, VB, UIMM },		"Vector Convert to Unsigned Fixed-Point Word Saturate"	},
	{	altivec_vexptefp,	"vexptefp",		VX(4, 394),		VX_MASK,	{ VD, VB },				"Vector 2 Raised to the Exponent Estimate Floating Point"	},
	{	altivec_vlogefp,	"vlogefp",		VX(4, 458),		VX_MASK,	{ VD, VB },				"Vector Log2 Estimate Floating Point"	},
	{	altivec_vmaddfp,	"vmaddfp",		VXA(4, 46),		VXA_MASK,	{ VD, VA, VC, VB },		"Vector Multiply-Add Floating Point"	},
	{	altivec_vmaxfp,		"vmaxfp",		VX(4, 1034),	VX_MASK,	{ VD, VA, VB },			"Vector Maximum Floating Point"	},
	{	altivec_vmaxsb,		"vmaxsb",		VX(4, 258),		VX_MASK,	{ VD, VA, VB },			"Vector Maximum Signed Byte"	},
	{	altivec_vmaxsh,		"vmaxsh",		VX(4, 322),		VX_MASK,	{ VD, VA, VB },			"Vector Maximum Signed Half Word"	},
	{	altivec_vmaxsw,		"vmaxsw",		VX(4, 386),		VX_MASK,	{ VD, VA, VB },			"Vector Maximum Signed Word"	},
	{	altivec_vmaxub,		"vmaxub",		VX(4, 2),		VX_MASK,	{ VD, VA, VB },			"Vector Maximum Unsigned Byte"	},
	{	altivec_vmaxuh,		"vmaxuh",		VX(4, 66),		VX_MASK,	{ VD, VA, VB },			"Vector Maximum Unsigned Half Word"	},
	{	altivec_vmaxuw,		"vmaxuw",		VX(4, 130),		VX_MASK,	{ VD, VA, VB },			"Vector Maximum Unsigned Word"	},
	{	altivec_vmhaddshs,	"vmhaddshs",	VXA(4, 32),		VXA_MASK,	{ VD, VA, VB, VC },		"Vector Multiply-High and Add Signed Signed Half Word Saturate"	},
	{	altivec_vmhraddshs,	"vmhraddshs",	VXA(4, 33),		VXA_MASK,	{ VD, VA, VB, VC },		"Vector Multiply-High Round and Add Signed Signed Half Word Saturate"	},
	{	altivec_vminfp,		"vminfp",		VX(4, 1098),	VX_MASK,	{ VD, VA, VB },			"Vector Minimum Floating Point"	},
	{	altivec_vminsb,		"vminsb",		VX(4, 770),		VX_MASK,	{ VD, VA, VB },			"Vector Minimum Signed Byte"	},
	{	altivec_vminsh,		"vminsh",		VX(4, 834),		VX_MASK,	{ VD, VA, VB },			"Vector Minimum Signed Half Word"	},
	{	altivec_vminsw,		"vminsw",		VX(4, 898),		VX_MASK,	{ VD, VA, VB },			"Vector Minimum Signed Word"	},
	{	altivec_vminub,		"vminub",		VX(4, 514),		VX_MASK,	{ VD, VA, VB },			"Vector Minimum Unsigned Byte"	},
	{	altivec_vminuh,		"vminuh",		VX(4, 578),		VX_MASK,	{ VD, VA, VB },			"Vector Minimum Unsigned Half Word"	},
	{	altivec_vminuw,		"vminuw",		VX(4, 642),		VX_MASK,	{ VD, VA, VB },			"Vector Minimum Unsigned Word"	},
	{	altivec_vmladduhm,	"vmladduhm",	VXA(4, 34),		VXA_MASK,	{ VD, VA, VB, VC },		"Vector Multiply-Low and Add Unsigned Half Word Modulo"	},
	{	altivec_vmrghb,		"vmrghb",		VX(4, 12),		VX_MASK,	{ VD, VA, VB },			"Vector Merge High Byte"	},
	{	altivec_vmrghh,		"vmrghh",		VX(4, 76),		VX_MASK,	{ VD, VA, VB },			"Vector Merge High Half Word"	},
	{	altivec_vmrghw,		"vmrghw",		VX(4, 140),		VX_MASK,	{ VD, VA, VB },			"Vector Merge High Word"	},
	{	altivec_vmrglb,		"vmrglb",		VX(4, 268),		VX_MASK,	{ VD, VA, VB },			"Vector Merge Low Byte"	},
	{	altivec_vmrglh,		"vmrglh",		VX(4, 332),		VX_MASK,	{ VD, VA, VB },			"Vector Merge Low Half Word"	},
	{	altivec_vmrglw,		"vmrglw",		VX(4, 396),		VX_MASK,	{ VD, VA, VB },			"Vector Merge Low Word"	},
	{	altivec_vmsummbm,	"vmsummbm",		VXA(4, 37),		VXA_MASK,	{ VD, VA, VB, VC },		"Vector Multiply-Sum Mixed-Sign Byte Modulo"	},
	{	altivec_vmsumshm,	"vmsumshm",		VXA(4, 40),		VXA_MASK,	{ VD, VA, VB, VC },		"Vector Multiply-Sum Signed Half Word Modulo"	},
	{	altivec_vmsumshs,	"vmsumshs",		VXA(4, 41),		VXA_MASK,	{ VD, VA, VB, VC },		"Vector Multiply-Sum Signed Half Word Saturate"	},
	{	altivec_vmsumubm,	"vmsumubm",		VXA(4, 36),		VXA_MASK,	{ VD, VA, VB, VC },		"Vector Multiply-Sum Unsigned Byte Modulo"	},
	{	altivec_vmsumuhm,	"vmsumuhm",		VXA(4, 38),		VXA_MASK,	{ VD, VA, VB, VC },		"Vector Multiply-Sum Unsigned Half Word Modulo"	},
	{	altivec_vmsumuhs,	"vmsumuhs",		VXA(4, 39),		VXA_MASK,	{ VD, VA, VB, VC },		"Vector Multiply-Sum Unsigned Half Word Saturate"	},
	{	altivec_vmulesb,	"vmulesb",		VX(4, 776),		VX_MASK,	{ VD, VA, VB },			"Vector Multiply Even Signed Byte"	},
	{	altivec_vmulesh,	"vmulesh",		VX(4, 840),		VX_MASK,	{ VD, VA, VB },			"Vector Multiply Even Signed Half Word"	},
	{	altivec_vmuleub,	"vmuleub",		VX(4, 520),		VX_MASK,	{ VD, VA, VB },			"Vector Multiply Even Unsigned Byte"	},
	{	altivec_vmuleuh,	"vmuleuh",		VX(4, 584),		VX_MASK,	{ VD, VA, VB },			"Vector Multiply Even Unsigned Half Word"	},
	{	altivec_vmulosb,	"vmulosb",		VX(4, 264),		VX_MASK,	{ VD, VA, VB },			"Vector Multiply Odd Signed Byte"	},
	{	altivec_vmulosh,	"vmulosh",		VX(4, 328),		VX_MASK,	{ VD, VA, VB },			"Vector Multiply Odd Signed Half Word"	},
	{	altivec_vmuloub,	"vmuloub",		VX(4, 8),		VX_MASK,	{ VD, VA, VB },			"Vector Multiply Odd Unsigned Byte"	},
	{	altivec_vmulouh,	"vmulouh",		VX(4, 72),		VX_MASK,	{ VD, VA, VB },			"Vector Multiply Odd Unsigned Half Word"	},
	{	altivec_vnmsubfp,	"vnmsubfp",		VXA(4, 47),		VXA_MASK,	{ VD, VA, VC, VB },		"Vector Negative Multiply-Subtract Floating Point"	},
	{	altivec_vnor, 		"vnor",			VX(4, 1284),	VX_MASK,	{ VD, VA, VB },			"Vector Logical NOR"	},
	{	altivec_vor,		"vor",			VX(4, 1156),	VX_MASK,	{ VD, VA, VB },			"Vector Logical OR"	},
	{	altivec_vperm,		"vperm",		VXA(4, 43),		VXA_MASK,	{ VD, VA, VB, VC },		"Vector Permute"	},
	{	altivec_vpkpx,		"vpkpx",		VX(4, 782),		VX_MASK,	{ VD, VA, VB },			"Vector Pack Pixel"	},
	{	altivec_vpkshss,	"vpkshss",		VX(4, 398),		VX_MASK,	{ VD, VA, VB },			"Vector Pack Signed Half Word Signed Saturate"	},
	{	altivec_vpkshus,	"vpkshus",		VX(4, 270),		VX_MASK,	{ VD, VA, VB },			"Vector Pack Signed Half Word Unsigned Saturate"	},
	{	altivec_vpkswss,	"vpkswss",		VX(4, 462),		VX_MASK,	{ VD, VA, VB },			"Vector Pack Signed Word Signed Saturate"	},
	{	altivec_vpkswus,	"vpkswus",		VX(4, 334),		VX_MASK,	{ VD, VA, VB },			"Vector Pack Signed Word Unsigned Saturate"	},
	{	altivec_vpkuhum,	"vpkuhum",		VX(4, 14),		VX_MASK,	{ VD, VA, VB },			"Vector Pack Unsigned Half Word Unsigned Modulo"	},
	{	altivec_vpkuhus,	"vpkuhus",		VX(4, 142),		VX_MASK,	{ VD, VA, VB },			"Vector Pack Unsigned Half Word Unsigned Saturate"	},
	{	altivec_vpkuwum,	"vpkuwum",		VX(4, 78),		VX_MASK,	{ VD, VA, VB },			"Vector Pack Unsigned Word Unsigned Modulo"	},
	{	altivec_vpkuwus,	"vpkuwus",		VX(4, 206),		VX_MASK,	{ VD, VA, VB },			"Vector Pack Unsigned Word Unsigned Saturate"	},
	{	altivec_vrefp,		"vrefp",		VX(4, 266),		VX_MASK,	{ VD, VB },				"Vector Reciprocal Estimate Floating Point"	},
	{	altivec_vrfim,		"vrfim",		VX(4, 714),		VX_MASK,	{ VD, VB },				"Vector Round to Floating-Point Integer toward Minus Infinity"	},
	{	altivec_vrfin,		"vrfin",		VX(4, 522),		VX_MASK,	{ VD, VB },				"Vector Round to Floating-Point Integer Nearest"	},
	{	altivec_vrfip,		"vrfip",		VX(4, 650),		VX_MASK,	{ VD, VB },				"Vector Round to Floating-Point Integer toward Plus Infinity"	},
	{	altivec_vrfiz,		"vrfiz",		VX(4, 586),		VX_MASK,	{ VD, VB },				"Vector Round to Floating-Point Integer toward Zero"	},
	{	altivec_vrlb, 		"vrlb",			VX(4, 4),		VX_MASK,	{ VD, VA, VB },			"Vector Rotate Left Integer Byte"	},
	{	altivec_vrlh,		"vrlh",			VX(4, 68),		VX_MASK,	{ VD, VA, VB },			"Vector Rotate Left Integer Half Word"	},
	{	altivec_vrlw, 		"vrlw",			VX(4, 132),		VX_MASK,	{ VD, VA, VB },			"Vector Rotate Left Integer Word"	},
	{	altivec_vrsqrtefp,	"vrsqrtefp",	VX(4, 330),		VX_MASK,	{ VD, VB },				"Vector Reciprocal Square Root Estimate Floating Point"	},
	{	altivec_vsel,		"vsel",			VXA(4, 42),		VXA_MASK,	{ VD, VA, VB, VC },		"Vector Conditional Select"	},
	{	altivec_vsl,		"vsl",			VX(4, 452),		VX_MASK,	{ VD, VA, VB },			"Vector Shift Left"	},
	{	altivec_vslb, 		"vslb",			VX(4, 260),		VX_MASK,	{ VD, VA, VB },			"Vector Shift Left Integer Byte"	},
	{	altivec_vsldoi,		"vsldoi",		VXA(4, 44),		VXA_MASK,	{ VD, VA, VB, SHB },	"Vector Shift Left Double by Octet Immediate"	},
	{	altivec_vslh, 		"vslh",			VX(4, 324),		VX_MASK,	{ VD, VA, VB },			"Vector Shift Left Integer Half Word"	},
	{	altivec_vslo, 		"vslo",			VX(4, 1036),	VX_MASK,	{ VD, VA, VB },			"Vector Shift Left by Octet"	},
	{	altivec_vslw, 		"vslw",			VX(4, 388),		VX_MASK,	{ VD, VA, VB },			"Vector Shift Left Integer Word"	},
	{	altivec_vspltb,		"vspltb",		VX(4, 524),		VX_MASK,	{ VD, VB, UIMM },		"Vector Splat Byte"	},
	{	altivec_vsplth,		"vsplth",		VX(4, 588),		VX_MASK,	{ VD, VB, UIMM },		"Vector Splat Half Word"	},
	{	altivec_vspltisb,	"vspltisb",		VX(4, 780),		VX_MASK,	{ VD, SIMM },			"Vector Splat Immediate Signed Byte"	},
	{	altivec_vspltish,	"vspltish",		VX(4, 844),		VX_MASK,	{ VD, SIMM },			"Vector Splat Immediate Signed Half Word"	},
	{	altivec_vspltisw,	"vspltisw",		VX(4, 908),		VX_MASK,	{ VD, SIMM },			"Vector Splat Immediate Signed Word"	},
	{	altivec_vspltw,		"vspltw",		VX(4, 652),		VX_MASK,	{ VD, VB, UIMM },		"Vector Splat Word"	},
	{	altivec_vsr,		"vsr",			VX(4, 708),		VX_MASK,	{ VD, VA, VB },			"Vector Shift Right"	},
	{	altivec_vsrab,		"vsrab",		VX(4, 772),		VX_MASK,	{ VD, VA, VB },			"Vector Shift Right Algebraic Byte"	},
	{	altivec_vsrah,		"vsrah",		VX(4, 836),		VX_MASK,	{ VD, VA, VB },			"Vector Shift Right Algebraic Half Word"	},
	{	altivec_vsraw,		"vsraw",		VX(4, 900),		VX_MASK,	{ VD, VA, VB },			"Vector Shift Right Algebraic Word"	},
	{	altivec_vsrb,		"vsrb",			VX(4, 516),		VX_MASK,	{ VD, VA, VB },			"Vector Shift Right Byte"	},
	{	altivec_vsrh, 		"vsrh",			VX(4, 580),		VX_MASK,	{ VD, VA, VB },			"Vector Shift Right Half Word"	},
	{	altivec_vsro, 		"vsro",			VX(4, 1100),	VX_MASK,	{ VD, VA, VB },			"Vector Shift Right Octet"	},
	{	altivec_vsrw,		"vsrw",			VX(4, 644),		VX_MASK,	{ VD, VA, VB },			"Vector Shift Right Word"	},
	{	altivec_vsubcuw,	"vsubcuw",		VX(4, 1408),	VX_MASK,	{ VD, VA, VB },			"Vector Subtract Carryout Unsigned Word"	},
	{	altivec_vsubfp,		"vsubfp",		VX(4, 74),		VX_MASK,	{ VD, VA, VB },			"Vector Subtract Floating Point"	},
	{	altivec_vsubsbs,	"vsubsbs",		VX(4, 1792),	VX_MASK,	{ VD, VA, VB },			"Vector Subtract Signed Byte Saturate"	},
	{	altivec_vsubshs,	"vsubshs",		VX(4, 1856),	VX_MASK,	{ VD, VA, VB },			"Vector Subtract Signed Half Word Saturate"	},
	{	altivec_vsubsws,	"vsubsws",		VX(4, 1920),	VX_MASK,	{ VD, VA, VB },			"Vector Subtract Signed Word Saturate"	},
	{	altivec_vsububm,	"vsububm",		VX(4, 1024),	VX_MASK,	{ VD, VA, VB },			"Vector Subtract Unsigned Byte Modulo"	},
	{	altivec_vsububs,	"vsububs",		VX(4, 1536),	VX_MASK,	{ VD, VA, VB },			"Vector Subtract Unsigned Byte Saturate"	},
	{	altivec_vsubuhm,	"vsubuhm",		VX(4, 1088),	VX_MASK,	{ VD, VA, VB },			"Vector Subtract Unsigned Half Word Modulo"	},
	{	altivec_vsubuhs,	"vsubuhs",		VX(4, 1600),	VX_MASK,	{ VD, VA, VB },			"Vector Subtract Unsigned Half Word Saturate"	},
	{	altivec_vsubuwm,	"vsubuwm",		VX(4, 1152),	VX_MASK,	{ VD, VA, VB },			"Vector Subtract Unsigned Word Modulo"	},
	{	altivec_vsubuws,	"vsubuws",		VX(4, 1664),	VX_MASK,	{ VD, VA, VB },			"Vector Subtract Unsigned Word Saturate"	},
	{	altivec_vsumsws,	"vsumsws",		VX(4, 1928),	VX_MASK,	{ VD, VA, VB },			"Vector Sum Across Signed Word Saturate"	},
	{	altivec_vsum2sws,	"vsum2sws",		VX(4, 1672),	VX_MASK,	{ VD, VA, VB },			"Vector Sum Across Partial (1/2) Signed Word Saturate"	},
	{	altivec_vsum4sbs,	"vsum4sbs",		VX(4, 1800),	VX_MASK,	{ VD, VA, VB },			"Vector Sum Across Partial (1/4) Signed Byte Saturate"	},
	{	altivec_vsum4shs,	"vsum4shs",		VX(4, 1608),	VX_MASK,	{ VD, VA, VB },			"Vector Sum Across Partial (1/4) Signed Half Word Saturate"	},
	{	altivec_vsum4ubs,	"vsum4ubs",		VX(4, 1544),	VX_MASK,	{ VD, VA, VB },			"Vector Sum Across Partial (1/4) Unsigned Byte Saturate"	},
	{	altivec_vupkhpx,	"vupkhpx",		VX(4, 846),		VX_MASK,	{ VD, VB },				"Vector Unpack High Pixel"	},
	{	altivec_vupkhsb,	"vupkhsb",		VX(4, 526),		VX_MASK,	{ VD, VB },				"Vector Unpack High Signed Byte"	},
	{	altivec_vupkhsh,	"vupkhsh",		VX(4, 590),		VX_MASK,	{ VD, VB },				"Vector Unpack High Signed Half Word"	},
	{	altivec_vupklpx,	"vupklpx",		VX(4, 974),		VX_MASK,	{ VD, VB },				"Vector Unpack Low Pixel"	},
	{	altivec_vupklsb,	"vupklsb",		VX(4, 654),		VX_MASK,	{ VD, VB },				"Vector Unpack Low Signed Byte"	},
	{	altivec_vupklsh,	"vupklsh",		VX(4, 718),		VX_MASK,	{ VD, VB },				"Vector Unpack Low Signed Half Word"	},
	{	altivec_vxor,		"vxor",			VX(4, 1220),	VX_MASK,	{ VD, VA, VB },			"Vector Logical XOR"	},

	// Takires: Added opcodes
	{	vmx128_vsldoi128,	"vsldoi128",	VX128_5(4, 16),		VX128_5_MASK,	{ VD128, VA128, VB128, SHB },			""	},
	{	vmx128_lvsl128,		"lvsl128",		VX128_1(4, 3),		VX128_1_MASK,	{ VD128, RA, RB },						""	},
	{	vmx128_lvsr128,		"lvsr128",		VX128_1(4, 67),		VX128_1_MASK,	{ VD128, RA, RB },						""	},
	{	vmx128_lvewx128,	"lvewx128",		VX128_1(4, 131),	VX128_1_MASK,	{ VD128, RA, RB },						""	},
	{	vmx128_lvx128,		"lvx128",		VX128_1(4, 195),	VX128_1_MASK,	{ VD128, RA, RB },						""	},
	{	vmx128_stvewx128,	"stvewx128",	VX128_1(4, 387),	VX128_1_MASK,	{ VS128, RA, RB },						""	},
	{	vmx128_stvx128,		"stvx128",		VX128_1(4, 451),	VX128_1_MASK,	{ VS128, RA, RB },						""	},
	{	vmx128_lvxl128,		"lvxl128",		VX128_1(4, 707),	VX128_1_MASK,	{ VD128, RA, RB },						""	},
	{	vmx128_stvxl128,	"stvxl128",		VX128_1(4, 963),	VX128_1_MASK,	{ VS128, RA, RB },						""	},
	{	vmx128_lvlx128,		"lvlx128",		VX128_1(4, 1027),	VX128_1_MASK,	{ VD128, RA, RB },						""	},
	{	vmx128_lvrx128,		"lvrx128",		VX128_1(4, 1091),	VX128_1_MASK,	{ VD128, RA, RB },						""	},
	{	vmx128_stvlx128,	"stvlx128",		VX128_1(4, 1283),	VX128_1_MASK,	{ VS128, RA, RB },						""	},
	{	vmx128_stvrx128,	"stvrx128",		VX128_1(4, 1347),	VX128_1_MASK,	{ VS128, RA, RB },						""	},
	{	vmx128_lvlxl128,	"lvlxl128",		VX128_1(4, 1539),	VX128_1_MASK,	{ VD128, RA, RB },						""	},
	{	vmx128_lvrxl128,	"lvrxl128",		VX128_1(4, 1603),	VX128_1_MASK,	{ VD128, RA, RB },						""	},
	{	vmx128_stvlxl128,	"stvlxl128",	VX128_1(4, 1795),	VX128_1_MASK,	{ VS128, RA, RB },						""	},
	{	vmx128_stvrxl128,	"stvrxl128",	VX128_1(4, 1859),	VX128_1_MASK,	{ VS128, RA, RB },						""	},
	{	vmx128_vperm128,	"vperm128",		VX128_2(5, 0),		VX128_2_MASK,	{ VD128, VA128, VB128, VC128 },			""	},
	{	vmx128_vaddfp128,	"vaddfp128",	VX128(5, 16),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vsubfp128,	"vsubfp128",	VX128(5,  80),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vmulfp128,	"vmulfp128",	VX128(5, 144),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vmaddfp128,	"vmaddfp128",	VX128(5, 208),		VX128_MASK,		{ VD128, VA128, VB128, VS128 },			""	},
	{	vmx128_vmaddcfp128,	"vmaddcfp128",	VX128(5, 272),		VX128_MASK,		{ VD128, VA128, VS128, VB128 },			""	},
	{	vmx128_vnmsubfp128,	"vnmsubfp128",	VX128(5, 336),		VX128_MASK,		{ VD128, VA128, VB128, VS128 },			""	},
	{	vmx128_vmsum3fp128,	"vmsum3fp128",	VX128(5, 400),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vmsum4fp128,	"vmsum4fp128",	VX128(5, 464),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vpkshss128,	"vpkshss128",	VX128(5, 512),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vand128,		"vand128",		VX128(5, 528),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vpkshus128,	"vpkshus128",	VX128(5, 576),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vandc128,	"vandc128",		VX128(5, 592),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vpkswss128,	"vpkswss128",	VX128(5, 640),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vnor128,		"vnor128",		VX128(5, 656),		VX128_MASK,		{ VD128, VA128, VB128 },				""  },
	{	vmx128_vpkswus128,	"vpkswus128",	VX128(5, 704),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vor128,		"vor128",		VX128(5, 720),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vpkuhum128,	"vpkuhum128",	VX128(5, 768),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vxor128,		"vxor128",		VX128(5, 784),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vpkuhus128,	"vpkuhus128",	VX128(5, 832),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vsel128,		"vsel128",		VX128(5, 848),		VX128_MASK,		{ VD128, VA128, VB128, VS128 },			""	},
	{	vmx128_vpkuwum128,	"vpkuwum128",	VX128(5, 896),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vslo128,		"vslo128",		VX128(5, 912),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vpkuwus128,	"vpkuwus128",	VX128(5, 960),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vsro128,		"vsro128",		VX128(5, 976),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},

	{	vmx128_vpermwi128,	"vpermwi128",	VX128_P(6, 528),	VX128_P_MASK,	{ VD128, VB128, VPERM128 },				""	},
	{	vmx128_vcfpsxws128,	"vcfpsxws128",	VX128_3(6, 560),	VX128_3_MASK,	{ VD128, VB128, SIMM },					""	},
	{	vmx128_vcfpuxws128,	"vcfpuxws128",	VX128_3(6, 624),	VX128_3_MASK,	{ VD128, VB128, UIMM },					""	},
	{	vmx128_vcsxwfp128,	"vcsxwfp128",	VX128_3(6, 688),	VX128_3_MASK,	{ VD128, VB128, SIMM },					""	},
	{	vmx128_vcuxwfp128,	"vcuxwfp128",	VX128_3(6, 752),	VX128_3_MASK,	{ VD128, VB128, UIMM },					""	},
	{	vmx128_vrfim128,	"vrfim128",		VX128_3(6, 816),	VX128_3_MASK,	{ VD128, VB128 },						""	},
	{	vmx128_vrfin128,	"vrfin128",		VX128_3(6, 880),	VX128_3_MASK,	{ VD128, VB128 },						""	},
	{	vmx128_vrfip128,	"vrfip128",		VX128_3(6, 944),	VX128_3_MASK,	{ VD128, VB128 },						""	},
	{	vmx128_vrfiz128,	"vrfiz128",		VX128_3(6, 1008),	VX128_3_MASK,	{ VD128, VB128 },						""	},
	{	vmx128_vpkd3d128,	"vpkd3d128",	VX128_4(6, 1552),	VX128_4_MASK,	{ VD128, VB128, VD3D0, VD3D1, VD3D2},	""	},
	{	vmx128_vrefp128,	"vrefp128",		VX128_3(6, 1584),	VX128_3_MASK,	{ VD128, VB128 },						""	},
	{	vmx128_vrsqrtefp128,"vrsqrtefp128",	VX128_3(6, 1648),	VX128_3_MASK,	{ VD128, VB128 },						""	},
	{	vmx128_vexptefp128,	"vexptefp128",	VX128_3(6, 1712),	VX128_3_MASK,	{ VD128, VB128 },						""	},
	{	vmx128_vlogefp128,	"vlogefp128",	VX128_3(6, 1776),	VX128_3_MASK,	{ VD128, VB128 },						""	},
	{	vmx128_vrlimi128,	"vrlimi128",	VX128_4(6, 1808),	VX128_4_MASK,	{ VD128, VB128, UIMM, VD3D2},			""	},
	{	vmx128_vspltw128,	"vspltw128",	VX128_3(6, 1840),	VX128_3_MASK,	{ VD128, VB128, UIMM },					""	},
	{	vmx128_vspltisw128,	"vspltisw128",	VX128_3(6, 1904),	VX128_3_MASK,	{ VD128, VB128, SIMM },					""	},
	{	vmx128_vupkd3d128,	"vupkd3d128",	VX128_3(6, 2032),	VX128_3_MASK,	{ VD128, VB128, UIMM },					""	},
	{	vmx128_vcmpeqfp128,	"vcmpeqfp128",	VX128(6, 0),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vcmpeqfp128c,"vcmpeqfp128.",	VX128(6, 64),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vrlw128,		"vrlw128",		VX128(6, 80),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vcmpgefp128,	"vcmpgefp128",	VX128(6, 128),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vcmpgefp128c,"vcmpgefp128.",	VX128(6, 192),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vslw128,		"vslw128",		VX128(6, 208),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vcmpgtfp128,	"vcmpgtfp128",	VX128(6, 256),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vcmpgtfp128c,"vcmpgtfp128.",	VX128(6, 320),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vsraw128,	"vsraw128",		VX128(6, 336),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vcmpbfp128,	"vcmpbfp128",	VX128(6, 384),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vcmpbfp128c,	"vcmpbfp128.",	VX128(6, 448),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vsrw128,		"vsrw128",		VX128(6, 464),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vcmpequw128,	"vcmpequw128",	VX128(6, 512),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vcmpequw128c,"vcmpequw128.",	VX128(6, 576),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vmaxfp128,	"vmaxfp128",	VX128(6, 640),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vminfp128,	"vminfp128",	VX128(6, 704),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vmrghw128,	"vmrghw128",	VX128(6, 768),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vmrglw128,	"vmrglw128",	VX128(6, 832),		VX128_MASK,		{ VD128, VA128, VB128 },				""	},
	{	vmx128_vupkhsb128,	"vupkhsb128",	VX128(6, 896),		VX128_MASK,		{ VD128, VB128 },						""	},
	{	vmx128_vupklsb128,	"vupklsb128",	VX128(6, 960),		VX128_MASK,		{ VD128, VB128 },						""  },

	{	vmx128_lvlx,		"lvlx",			X(31, 519),			X_MASK,			{ VD, RA0, RB },						""	},
	{	vmx128_lvlxl,		"lvlxl",		X(31, 775),			X_MASK,			{ VD, RA0, RB },						""	},
	{	vmx128_lvrx,		"lvrx",			X(31, 551),			X_MASK,			{ VD, RA0, RB },						""	},
	{	vmx128_lvrxl,		"lvrxl",		X(31, 807),			X_MASK,			{ VD, RA0, RB },						""	},
	{	vmx128_stvlx,		"stvlx",		X(31, 647),			X_MASK,			{ VS, RA0, RB },						""	},
	{	vmx128_stvlxl,		"stvlxl",		X(31, 903),			X_MASK,			{ VS, RA0, RB },						""	},
	{	vmx128_stvrx,		"stvrx",		X(31, 679),			X_MASK,			{ VS, RA0, RB },						""	},
	{	vmx128_stvrxl,		"stvrxl",		X(31, 935),			X_MASK,			{ VS, RA0, RB },						""	},

	{	std_attn,			"attn",			X(0, 256),			X_MASK,			{ 0 },									""	},
	{	std_dbcz128,		"dbcz128",		XRT(31, 1014, 1),	XRT_MASK,		{ RA, RB },								"Data Cache Block set to Zero (1)"	},
	
	// the normal PPC processor module handles normal syscalls,
	// so this just need to handle level 1 syscalls (hypercalls)
	{	std_hvsc,			"hvsc",			0x44000022,			0xFFFFFFFF,		{ 0 },									"Level1 Syscall (Hypercall)"	},
	
	// added entries for mfspr and mtspr to cover all spr's described in CEBA documentation
	{	std_mtspr,			"mtspr",		0x7C0003A6,			0xFC0007FE,		{ SPR, RS },							"Move to sprg, "	},/// XFX macro didnt work just put opcode + mask manually
	{	std_mfspr,			"mfspr",		0x7C0002A6,			0xFC0007FE,		{ RS, SPR },							"Move from sprg, "	},
	
	{	std_ldbrx,			"ldbrx",		X(31, 532),			X_MASK,			{ RT, RA0, RB },						"Load Doubleword Byte Reverse Indexed" },
	{	std_mfocrf,			"mfocrf",		XFX(31, 19, 1),		XFX_MASK,		{ RT, CRM },							"Move from One Condition Register Field"	},
	{	std_mtmsr,			"mtmsr",		X(31, 146),			XRLARB_MASK,	{ RS },									"Move to Machine State Register"	},
	{	std_mtmsrd,			"mtmsrd",		X(31, 178),			XRLARB_MASK,	{ RS, L15 },							"Move to Machine State Register Doubleword"	},
	{	std_mtocrf,			"mtocrf",		XFX(31, 144, 1),	XFX_MASK,		{ CRM, RS },							"Move to One Condition Register Field"	},
	{	std_slbmte,			"slbmte",		X(31, 402),			XRA_MASK,		{ RS, RB, 0 },							"SLB Move to Entry"	},
	{	std_stdbrx,			"stdbrx",		X(31, 660),			X_MASK,			{ RS, RA0, RB },						"Store Doubleword Byte Reverse Indexed" },
//	{	std_svc,			"svc",			SC(17, 0, 0),		SC_MASK,		{ SVC_LEV, FL1, FL2 },					"Synchronize"	},
//	{	std_svcl,			"svcl",			SC(17, 0, 1),		SC_MASK,		{ SVC_LEV, FL1, FL2 },					"Synchronize"	},
//	{	std_svca,			"svca",			SC(17, 1, 0),		SC_MASK,		{ SV },									"Synchronize"	},
//	{	std_svcla,			"svcla",		SC(17, 1, 1),		SC_MASK,		{ SV },									"Synchronize"	},
	{	std_lwsync,			"lwsync",		XSYNC(31, 598, 1),	0xffffffff,		{ 0 },									"Lightweight Synchronize"	},
	{	std_ptesync,		"ptesync",		XSYNC(31, 598, 2),	0xffffffff,		{ 0 },									"Synchronize"	},
	{	std_sync,			"sync",			X(31, 598),			X_MASK,			{ 0 },									"Synchronize"	},
	{	std_tlbiel,			"tlbiel",		X(31, 274),			X_MASK,			{ RB, L10 },							"TLB Invalidate Entry Local"	},
	{	std_tlbie,			"tlbie",		X(31, 306),			XRTLRA_MASK,	{ RB, L },								"TLB Invalidate Entry"	},
	{	std_tlbi,			"tlbi",			X(31, 306),			XRT_MASK,		{ RA, RB },								"TLB Invalidate"	},
	{	std_slbie,			"slbie",		X(31, 434),			XRTRA_MASK,		{ RB },									"SLB Invalidate Entry"	},
	
	// special instructions that don't seem to have full setup info
	{ spec_callthru,		"callthru",		0x000eaeb0,			0xffffffff,		{ 0 },									"SystemSim Callthru" },
	{ spec_cctpl,			"cctpl",		0x7c210b78,			0xffffffff,		{ 0 },									"" },
	{ spec_cctpm,			"cctpm",		0x7c421378,			0xffffffff,		{ 0 },									"" },
	{ spec_cctph,			"cctph",		0x7c631b78,			0xffffffff,		{ 0 },									"" },
	{ spec_db8cyc,			"db8cyc",		0x7f9ce378,			0xffffffff,		{ 0 },									"" },
	{ spec_db10cyc,			"db10cyc",		0x7fbdeb78,			0xffffffff,		{ 0 },									"" },
	{ spec_db12cyc,			"db12cyc",		0x7fdef378,			0xffffffff,		{ 0 },									"" },
	{ spec_db16cyc,			"db16cyc",		0x7ffffb78,			0xffffffff,		{ 0 },									"" },
	{ spec_02002000,		"opcode_02002000",0x02002000,		0xffffffff,		{ 0 },									"Unknown instruction - included to allow conversion to code" },
	
	// gekko specific
	{	gekko_psq_lx,			"psq_lx",		OPM(4, 6),			OPM_MASK,	{ FD, RA, RB, WC, IC },	"Paired Single Quantized Load Indexed"	},
	{	gekko_psq_stx,			"psq_stx",		OPM(4, 7),			OPM_MASK,	{ FS, RA, RB, WC, IC },	"Paired Single Quantized Store Indexed"	},
	{	gekko_psq_lux,			"psq_lux",		OPM(4, 38),			OPM_MASK,	{ FD, RA, RB, WC, IC },	"Paired Single Quantized Load with update Indexed"	},
	{	gekko_psq_stux,			"psq_stux",		OPM(4, 39),			OPM_MASK,	{ FS, RA, RB, WC, IC },	"Paired Single Quantized Store with update Indexed"	},
	
	{	gekko_psq_l, 			"psq_l",		OP(56),				OP_MASK,	{ FD, DRA, WB, IB },	"Paired Single Quantized Load"	},
	{	gekko_psq_lu,			"psq_lu",		OP(57), 			OP_MASK,	{ FD, DRA, WB, IB },	"Paired Single Quantized Load with Update"	},
	{	gekko_psq_st,			"psq_st",		OP(60), 			OP_MASK,	{ FS, DRA, WB, IB },	"Paired Single Quantized Store"	},
	{	gekko_psq_stu,			"psq_stu",		OP(61), 			OP_MASK,	{ FS, DRA, WB, IB },	"Paired Single Quantized Store with update"	},
	
	{	gekko_ps_div,			"ps_div",		OPSC(4, 18, 0),		OPS_MASK,		{ FD, FA, FB},		"Paired Single Divide"	},
	{	gekko_ps_div_dot,		"ps_div.",		OPSC(4, 18, 1),		OPS_MASK_DOT,	{ FD, FA, FB},		"Paired Single Divide"	},
	{	gekko_ps_sub,			"ps_sub",		OPSC(4, 20, 0),		OPS_MASK,		{ FD, FA, FB},		"Paired Single Subtract"	},
	{	gekko_ps_sub_dot,		"ps_sub.",		OPSC(4, 20, 1),		OPS_MASK_DOT,	{ FD, FA, FB},		"Paired Single Subtract"	},
	{	gekko_ps_add,			"ps_add",		OPSC(4, 21, 0),		OPS_MASK,		{ FD, FA, FB},		"Paired Single Add"	},
	{	gekko_ps_add_dot,		"ps_add.",		OPSC(4, 21, 1),		OPS_MASK_DOT,	{ FD, FA, FB},		"Paired Single Add"	},
	{	gekko_ps_sel,			"ps_sel",		OPSC(4, 23, 0),		OPS_MASK,		{ FD, FA, FC, FB},	"Paired Single Select"	},
	{	gekko_ps_sel_dot,		"ps_sel.",		OPSC(4, 23, 1),		OPS_MASK_DOT,	{ FD, FA, FC, FB},	"Paired Single Select"	},
	{	gekko_ps_res,			"ps_res",		OPSC(4, 24, 0),		OPS_MASK,		{ FD, FB},			"Paired Single Reciprocal Estimate"	},
	{	gekko_ps_res_dot,		"ps_res.",		OPSC(4, 24, 1),		OPS_MASK_DOT,	{ FD, FB},			"Paired Single Reciprocal Estimate"	},
	{	gekko_ps_mul,			"ps_mul",		OPSC(4, 25, 0),		OPS_MASK,		{ FD, FA, FC},		"Paired Single Multiply"	},
	{	gekko_ps_mul_dot,		"ps_mul.",		OPSC(4, 25, 1),		OPS_MASK_DOT,	{ FD, FA, FC},		"Paired Single Multiply"	},
	{	gekko_ps_rsqrte,		"ps_rsqrte",	OPSC(4, 26, 0),		OPS_MASK,		{ FD, FB},			"Paired Single Reciprocal Square Root Estimate"	},
	{	gekko_ps_rsqrte_dot,	"ps_rsqrte.",	OPSC(4, 26, 1),		OPS_MASK_DOT,	{ FD, FB},			"Paired Single Reciprocal Square Root Estimate"	},
	{	gekko_ps_msub,			"ps_msub",		OPSC(4, 28, 0),		OPS_MASK,		{ FD, FA, FC, FB},	"Paired Single Multiply-Subtract"	},
	{	gekko_ps_msub_dot,		"ps_msub.",		OPSC(4, 28, 1),		OPS_MASK_DOT,	{ FD, FA, FC, FB},	"Paired Single Multiply-Subtract"	},
	{	gekko_ps_madd,			"ps_madd",		OPSC(4, 29, 0),		OPS_MASK,		{ FD, FA, FC, FB},	"Paired Single Multiply-Add"	},
	{	gekko_ps_madd_dot,		"ps_madd.",		OPSC(4, 29, 1),		OPS_MASK_DOT,	{ FD, FA, FC, FB},	"Paired Single Multiply-Add"	},
	{	gekko_ps_nmsub,			"ps_nmsub",		OPSC(4, 30, 0),		OPS_MASK,		{ FD, FA, FC, FB},	"Paired Single Negative Multiply-Subtract"	},
	{	gekko_ps_nmsub_dot,		"ps_nmsub.",	OPSC(4, 30, 1),		OPS_MASK_DOT,	{ FD, FA, FC, FB},	"Paired Single Negative Multiply-Subtract"	},
	{	gekko_ps_nmadd,			"ps_nmadd",		OPSC(4, 31, 0),		OPS_MASK,		{ FD, FA, FC, FB},	"Paired Single Negative Multiply-Add"	},
	{	gekko_ps_nmadd_dot,		"ps_nmadd.",	OPSC(4, 31, 1),		OPS_MASK_DOT,	{ FD, FA, FC, FB},	"Paired Single Negative Multiply-Add"	},

	{	gekko_ps_neg,			"ps_neg",		OPLC(4, 40, 0),		OPL_MASK,		{ FD, FB },			"Paired Single Negate"	},
	{	gekko_ps_neg_dot,		"ps_neg.",		OPLC(4, 40, 1),		OPL_MASK_DOT,	{ FD, FB },			"Paired Single Negate"	},
	{	gekko_ps_mr,			"ps_mr",		OPLC(4, 72, 0),		OPL_MASK,		{ FD, FB },			"Paired Single Move Register"	},
	{	gekko_ps_mr_dot,		"ps_mr.",		OPLC(4, 72, 1),		OPL_MASK_DOT,	{ FD, FB },			"Paired Single Move Register"	},
	{	gekko_ps_nabs,			"ps_nabs",		OPLC(4, 136, 0),	OPL_MASK,		{ FD, FB },			"Paired Single Negative Absolute Value"	},
	{	gekko_ps_nabs_dot,		"ps_nabs.",		OPLC(4, 136, 1),	OPL_MASK_DOT,	{ FD, FB },			"Paired Single Negative Absolute Value"	},
	{	gekko_ps_abs,			"ps_abs",		OPLC(4, 264, 0),	OPL_MASK,		{ FD, FB },			"Paired Single Absolute Value"	},
	{	gekko_ps_abs_dot,		"ps_abs.",		OPLC(4, 264, 1),	OPL_MASK_DOT,	{ FD, FB },			"Paired Single Absolute Value"	},
	
	{	gekko_ps_sum0,			"ps_sum0",		OPSC(4, 10, 0),		OPS_MASK,		{ FD, FA, FC, FB },	"Paired Single vector SUM high"	},
	{	gekko_ps_sum0_dot,		"ps_sum0.",		OPSC(4, 10, 1),		OPS_MASK_DOT,	{ FD, FA, FC, FB },	"Paired Single vector SUM high"	},
	{	gekko_ps_sum1,			"ps_sum1",		OPSC(4, 11, 0),		OPS_MASK,		{ FD, FA, FC, FB },	"Paired Single vector SUM low"	},
	{	gekko_ps_sum1_dot,		"ps_sum1.",		OPSC(4, 11, 1),		OPS_MASK_DOT,	{ FD, FA, FC, FB },	"Paired Single vector SUM low"	},
	{	gekko_ps_muls0,			"ps_muls0",		OPSC(4, 12, 0),		OPS_MASK,		{ FD, FA, FC },		"Paired Single Multiply Scalar high"	},
	{	gekko_ps_muls0_dot,		"ps_muls0.",	OPSC(4, 12, 1),		OPS_MASK_DOT,	{ FD, FA, FC },		"Paired Single Multiply Scalar high"	},
	{	gekko_ps_muls1,			"ps_muls1",		OPSC(4, 13, 0),		OPS_MASK,		{ FD, FA, FC },		"Paired Single Multiply Scalar low"		},
	{	gekko_ps_muls1_dot,		"ps_muls1.",	OPSC(4, 13, 1),		OPS_MASK_DOT,	{ FD, FA, FC },		"Paired Single Multiply Scalar low"		},
	{	gekko_ps_madds0,		"ps_madds0",	OPSC(4, 14, 0),		OPS_MASK,		{ FD, FA, FC, FB },	"Paired Single Multiply-Add Scalar high"},
	{	gekko_ps_madds0_dot,	"ps_madds0.",	OPSC(4, 14, 1),		OPS_MASK_DOT,	{ FD, FA, FC, FB },	"Paired Single Multiply-Add Scalar high"},
	{	gekko_ps_madds1,		"ps_madds1",	OPSC(4, 15, 0),		OPS_MASK,		{ FD, FA, FC, FB },	"Paired Single Multiply-Add Scalar low"	},
	{	gekko_ps_madds1_dot,	"ps_madds1.",	OPSC(4, 15, 1),		OPS_MASK_DOT,	{ FD, FA, FC, FB },	"Paired Single Multiply-Add Scalar low"	},
	
	{	gekko_ps_cmpu0,			"ps_cmpu0",		OPL(4, 0),			OPL_MASK,		{ crfD, FA, FB },	"Paired Singles Compare Unordered High"	},
	{	gekko_ps_cmpo0,			"ps_cmpo0",		OPL(4, 32),			OPL_MASK,		{ crfD, FA, FB },	"Paired Singles Compare Ordered High"	},
	{	gekko_ps_cmpu1,			"ps_cmpu1",		OPL(4, 64),			OPL_MASK,		{ crfD, FA, FB },	"Paired Singles Compare Unordered Low"	},
	{	gekko_ps_cmpo1,			"ps_cmpo1",		OPL(4, 96),			OPL_MASK,		{ crfD, FA, FB },	"Paired Singles Compare Ordered Low"	},

	{	gekko_ps_merge00,		"ps_merge00",	OPLC(4, 528, 0),	OPL_MASK,		{ FD, FA, FB },		"Paired Single MERGE high"		},
	{	gekko_ps_merge00_dot,	"ps_merge00.",	OPLC(4, 528, 1),	OPL_MASK_DOT,	{ FD, FA, FB },		"Paired Single MERGE high"		},
	{	gekko_ps_merge01,		"ps_merge01",	OPLC(4, 560, 0),	OPL_MASK,		{ FD, FA, FB },		"Paired Single MERGE direct"	},
	{	gekko_ps_merge01_dot,	"ps_merge01.",	OPLC(4, 560, 1),	OPL_MASK_DOT,	{ FD, FA, FB },		"Paired Single MERGE direct"	},
	{	gekko_ps_merge10,		"ps_merge10",	OPLC(4, 592, 0),	OPL_MASK,		{ FD, FA, FB },		"Paired Single MERGE swapped"	},
	{	gekko_ps_merge10_dot,	"ps_merge10.",	OPLC(4, 592, 1),	OPL_MASK_DOT,	{ FD, FA, FB },		"Paired Single MERGE swapped"	},
	{	gekko_ps_merge11,		"ps_merge11",	OPLC(4, 624, 0),	OPL_MASK,		{ FD, FA, FB },		"Paired Single MERGE low"		},
	{	gekko_ps_merge11_dot,	"ps_merge11.",	OPLC(4, 624, 1),	OPL_MASK_DOT,	{ FD, FA, FB },		"Paired Single MERGE low"		},

	{	gekko_ps_dcbz_l,		"dcbz_l",		OPL(4, 1014),		OPL_MASK,		{ RA, RB },			"Data Cache Block Set to Zero Locked"	},
};




/***************************************************************************************************
*
*	FUNCTION		PluginAnalyse
*
*	DESCRIPTION		This is the main analysis function..
*
***************************************************************************************************/

int	PluginAnalyse( void )
{
	// Get the 
	int	codeBytes = get_long( cmd.ea );

	// When we check
	int opBytes = ( codeBytes & OP_MASK );

	// These signify the additional opcodes that this module supports
	if( ( opBytes == OP(  0 ) ) || 
		( opBytes == OP(  4 ) ) || 
		( opBytes == OP(  5 ) ) || 
		( opBytes == OP(  6 ) ) || 
 		( opBytes == OP( 17 ) ) || 
		( opBytes == OP( 31 ) ) ||
		 // gekko specific
		( opBytes == OP( 56 ) ) ||
		( opBytes == OP( 57 ) ) || 
		( opBytes == OP( 60 ) ) || 
		( opBytes == OP( 61 ) ) )
	{
		int	opcodeArraySize				= sizeof( g_altivecOpcodes ) / sizeof( altivec_opcode );
		altivec_opcode*	pCurrentOpcode	= g_altivecOpcodes;
		
		// Go through the entire opcode array looking for a match
		for ( int opcodeLoop = 0; opcodeLoop < opcodeArraySize; opcodeLoop++ )
		{
			// Is this a match?
			if ( ( codeBytes & pCurrentOpcode->mask ) == pCurrentOpcode->opcode ) 
			{
				// Ok, so we've got a match.. let's sort out the operands..
				int operandLoop = 0;
				while ( ( pCurrentOpcode->operands[ operandLoop ] != 0 ) && ( operandLoop < MAX_OPERANDS ) )
				{
					op_t*				operandData = &cmd.Operands[ operandLoop ];
					altivec_operand*	pCurrentOperand = &g_altivecOperands[ pCurrentOpcode->operands[ operandLoop ] ];

					int	rawBits			=	( codeBytes >> pCurrentOperand->shift ) & ( ( 1 <<  pCurrentOperand->bits ) - 1 );
					int	extendedBits	=	( rawBits << ( 32 - pCurrentOperand->bits ) ) >> ( 32 - pCurrentOperand->bits );

					switch ( pCurrentOpcode->operands[ operandLoop ] )
					{
						// These are the main Altivec registers
						case	VA:
						case	VB:
						case	VC:
						case	VD:	// VS
						{
							operandData->type		=	o_reg;
							operandData->reg		=	rawBits;
							operandData->specflag1	=	0x01;		// Mark the register as being an Altivec one.
							break;
						}
	
						// Signed immediate (extendedBits is sign extended into 32 bits)
						case	SIMM:
						{
							operandData->type	=	o_imm;
							operandData->dtyp	=	dt_byte;
							operandData->value	=	extendedBits;
							break;
						}

						// Unsigned immediate
						case	UIMM:
						{
							operandData->type	=	o_imm;
							operandData->dtyp	=	dt_byte;
							operandData->value	=	rawBits;
							break;
						}

						// Shift values are the same as unsigned immediates, but we separate for clarity
						case	SHB:
						{
							operandData->type	=	o_imm;
							operandData->dtyp	=	dt_byte;
							operandData->value	=	rawBits;
							break;
						}

						// Altivec memory loads are always via a CPU register
						case	RA:
						case	RB:
						{
							operandData->type		=	o_reg;
							operandData->reg		=	rawBits;
							operandData->specflag1	=	0x00;
							break;
						}

						// Altivec data stream ID
						case	STRM:
						{
							operandData->type	=	o_imm;
							operandData->dtyp	=	dt_byte;
							operandData->value	=	rawBits;
							break;
						}
						
						// Takires: Added operands
						case	L9_10:
						case	L10:
						case	L15:
						{
							operandData->type	=	o_imm;
							operandData->dtyp	=	dt_byte;
							operandData->value	=	rawBits;
							break;
						}

						case	RS:		// also RT
						{
							operandData->type		=	o_reg;
							operandData->reg		=	rawBits;
							operandData->specflag1	=	0x00;
							break;
						}
						
						case	VD128:	// also VS128
						{
							operandData->type		=	o_reg;
							operandData->reg		=	((codeBytes >> 21) & 0x1F) | ((codeBytes & 0x0C) << 3);
							operandData->specflag1	=	0x01;		// Mark the register as being an Altivec one.
							break;
						}

						case	VA128:
						{
							operandData->type		=	o_reg;
							operandData->reg		=	((codeBytes >> 16) & 0x1F) | (codeBytes & 0x20) | ((codeBytes >> 4) & 0x40);
							operandData->specflag1	=	0x01;		// Mark the register as being an Altivec one.
							break;
						}

						case	VB128:
						{
							operandData->type		=	o_reg;
							operandData->reg		=	((codeBytes << 5) & 0x60) | ((codeBytes >> 11) & 0x1F);
							operandData->specflag1	=	0x01;		// Mark the register as being an Altivec one.
							break;
						}

						case	VC128:
						{
							operandData->type		=	o_reg;
							operandData->reg		=	rawBits;
							operandData->specflag1	=	0x01;
							break;
						}

						case	CRM:
						{
							operandData->type		=	o_reg;
							operandData->reg		=	rawBits;
							operandData->specflag1	=	0x02;		// Mark the register as being a CRF.
							break;
						}

						case	VPERM128:
						{
							operandData->type		=	o_imm;
							operandData->dtyp		=	dt_byte;
							operandData->value		=	((codeBytes >> 1) & 0xE0) | ((codeBytes >> 16) & 0x1F);
							break;
						}
		
						case	VD3D0:
						case	VD3D1:
						case	VD3D2:
						{
							operandData->type		=	o_imm;
							operandData->dtyp		=	dt_byte;
							operandData->value		=	rawBits;
							break;
						}
	
						case	RA0:
						{
							if(rawBits == 0)
							{
							operandData->type		=	o_imm;
							operandData->dtyp		=	dt_byte;
							operandData->value		=	rawBits;
							}
							else
							{
							operandData->type		=	o_reg;
							operandData->reg		=	rawBits;
							operandData->specflag1	=	0;
							}
							break;
						}
						
						case	SPR:
						{
							operandData->type		=	o_reg;
							operandData->reg		=	(((rawBits & 0x3e0)>>5) + ((rawBits&0x1f)<<5));
							operandData->specflag1	=	0x04;		// Mark the register as being a SPR.
							break;
						}


						// gekko specific
						
						// These are the main Gekko registers
						case	FA:
						case	FB:
						case	FC:
						case	FD://FS
						//case	FS:
						{
							operandData->type		=	o_reg;
							operandData->reg		=	rawBits;
							operandData->specflag1	=	0x08;		// Mark the register as being a Gekko one.
							break;
						}
	
						case	crfD:
						case	WB:
						case	IB:
						case	WC:
						case	IC:
						{
							operandData->type	=	o_imm;
							operandData->dtyp	=	dt_byte;
							operandData->value	=	rawBits;
							break;
						}

						case	DRA:
						{
							unsigned short imm	= (unsigned short)(codeBytes & 0x7FF);
							unsigned short sign = (unsigned short)(codeBytes & 0x800);
							short displacement = 0;

							if (sign == 0)
								displacement = imm;
							else
								displacement = -1 * imm;


							operandData->type	=	o_displ;
							operandData->phrase	=	rawBits;
							operandData->addr	=	displacement;

							break;
						}


						default:
							break;
					}	

					// Next operand please..
					operandLoop++;
				}

				// Make a note of which opcode we are.. we need it to print our stuff out.
				cmd.itype	= pCurrentOpcode->insn;

				// The command is 4 bytes long.. 
				return 4;
			}	
	
			// We obviously didn't find our opcode this time round.. go test the next one.
			pCurrentOpcode++;
		}
	}

	// We didn't do anything.. honest.	
	return 0;
}


/***************************************************************************************************
*
*	FUNCTION		PluginExtensionCallback
*
*	DESCRIPTION		This callback is responsible for distributing work associated with each
*					intercepted event that we deal with. In our case we deal with the following
*					event identifiers.
*
*					custom_ana		:	Analyses a command (in 'cmd') to see if it is an Altivec 
*										instruction. If so, then it extracts information from the 
*										opcode in order to determine which opcode it is, along with
*										data relating to any used operands.
*
*					custom_mnem		:	Generates the mnemonic for our Altivec instructions, by looking
*										into our array of opcode information structures.
*
*					custom_outop	:	Outputs operands for Altivec instructions. In our case, we
*										have an alternate register set (vr0 to vr31), so our operands
*										may be marked as being Altivec registers.
*
*					may_be_func		:	It's perfectly OK for an Altivec instruction to be the start
*										of a function, so I figured I should return 100 here. The
*										return value is a percentage probability.. 
*
*					is_sane_insn	:	All our Altivec instructions (well, the ones we've identified
*										inside custom_ana processing), are ok.	
*
***************************************************************************************************/

static int idaapi PluginExtensionCallback( void * /*user_data*/, int event_id, va_list va )
{
	if ( event_id == ph.custom_ana)
	{
		// Analyse a command to see if it's an Altivec instruction.
		int length = PluginAnalyse();
		if ( length )
		{
			cmd.size = length;
			//return ( length + 1 );       // event processed
			return ( length );       // event processed
		}
	}
	else if ( event_id == ph.custom_mnem)	
	{
		// Obtain mnemonic for our Altivec instructions.
		if ( cmd.itype >= CUSTOM_CMD_ITYPE )
		{
			char *buf   = va_arg(va, char *);
			size_t size = va_arg(va, size_t);
			qstrncpy(buf, g_altivecOpcodes[ cmd.itype - altivec_lvebx ].name, size);
			return 2;
		}
	}
	else if ( event_id == ph.custom_outop)
	{
		// Display operands that differ from PPC ones.. like our Altivec registers.
		if ( cmd.itype >= CUSTOM_CMD_ITYPE )
		{
			op_t* operand = va_arg( va, op_t* );
			if ( ( operand->type == o_reg ) && ( operand->specflag1 & 0x01 ) )
			{
				char buf[ MAXSTR ];
				qsnprintf( buf, MAXSTR, "%%vr%d", operand->reg );					
				out_register( buf );
				return 2;
			} 
			else if ( ( operand->type == o_reg ) && ( operand->specflag1 & 0x02 ) )
			{
				char buf[ MAXSTR ];
				for (int i = 0; i < 8; i++)
				{
					if (operand->reg & (1 << i))
					{
						qsnprintf( buf, MAXSTR, "cr%d", 7 - i );
						out_register( buf );
						break;
					}
				}
				return 2;
			}
			// decode SPR Values
			else if ( ( operand->type == o_reg ) && ( operand->specflag1 & 0x04 ) )
			{
				int	sprgArraySize = sizeof( g_cbeaSprgs ) / sizeof( cbea_sprg );
				cbea_sprg*	pCurrentSprg	= g_cbeaSprgs;

				// Go through the entire special register array looking for a match
				for ( int sprgLoop = 0; sprgLoop < sprgArraySize; sprgLoop++ )
				{
					if(operand->reg == g_cbeaSprgs[sprgLoop].sprg)
					{
						out_register( g_cbeaSprgs[sprgLoop].shortName);
						return 2;
					}

				}
				char buf[ MAXSTR ];
				qsnprintf( buf, MAXSTR, "%x", operand->reg );					
				out_register( buf );
				return 2;
			}
			// decode fr values (gekko)
			else if ( ( operand->type == o_reg ) && ( operand->specflag1 & 0x08 ) )
			{
				char buf[ MAXSTR ];
				qsnprintf( buf, MAXSTR, "%%fr%d", operand->reg );					
				out_register( buf );
				return 2;
			}
		}
	}
	else if ( event_id == ph.custom_out)
	{
		// Custom output
		if ( cmd.itype >= CUSTOM_CMD_ITYPE )
		{
			char buf[ MAXSTR ];	
			init_output_buffer( buf, sizeof( buf ) );
		
			// Output mnemonic
			OutMnem();

			// Output operands
			if ( cmd.Op1.showed() && cmd.Op1.type != o_void )
			{
				 out_one_operand( 0 );
			}

			if ( cmd.Op2.showed() && cmd.Op2.type != o_void )
			{
				if ( cmd.Op1.showed() )
				{
					out_symbol(',');
					OutChar(' ');
				}
				out_one_operand( 1 );
			}
				
			if ( cmd.Op3.showed() && cmd.Op3.type != o_void )
			{
				if ( cmd.Op1.showed() || cmd.Op2.showed() )
				{
					out_symbol(',');
					OutChar(' ');
				}
				out_one_operand( 2 );
			}

			if ( cmd.Op4.showed() && cmd.Op4.type != o_void )
			{
				if ( cmd.Op1.showed() || cmd.Op2.showed() || cmd.Op3.showed() )
				{
					out_symbol(',');
					OutChar(' ');
				}
				out_one_operand( 3 );
			}

			if ( cmd.Op5.showed() && cmd.Op5.type != o_void )
			{
				if ( cmd.Op1.showed() || cmd.Op2.showed() || cmd.Op3.showed() || cmd.Op4.showed() )
				{
					out_symbol(',');
					OutChar(' ');
				}
				out_one_operand( 4 );
			}

			// Output auto comments
			if ( showAllComments() && ( get_cmt( cmd.ea, true, NULL, 0 ) == -1 ) )
			{
				for ( int indentLoop = (int)tag_strlen( buf ); indentLoop < ( inf.comment - inf.indent ); indentLoop++ )
					OutChar(' ');
				out_line( "# ", COLOR_AUTOCMT );
				out_line( g_altivecOpcodes[ cmd.itype - altivec_lvebx ].description, COLOR_AUTOCMT );// add a check for sprg
			}
			//else
				gl_comm = 1;

			term_output_buffer();

			MakeLine(buf);
			return 2;
		}
	}
	else if ( event_id == ph.may_be_func )
	{
		// Can this be the start of a function? 
		if ( cmd.itype >= CUSTOM_CMD_ITYPE )
		{
			return 100;
		}
	}
	else if ( event_id == ph.is_sane_insn )
	{
		// If we've identified the command as an Altivec instruction, it's good to go.
		if ( cmd.itype >= CUSTOM_CMD_ITYPE )
		{
			return 1;
		}
	}

	// We didn't process the event.. just let IDA handle it.
	return 0;
}


/***************************************************************************************************
*
*	FUNCTION		PluginStartup
*
*	DESCRIPTION		IDA will call this function only once. If this function returns PLUGIN_SKIP,
*					IDA will never load it again. If it returns PLUGIN_OK, IDA will unload the plugin
*					but remember that the plugin agreed to work with the database. The plugin will
*					be loaded again if the user invokes it by pressing the hotkey or selecting it
*					from the menu. After the second load, the plugin will stay in memory.
*
*	NOTES			In our Altivec case, we just hook into IDA'S callbacks if we need to be active
*					on plugin load. 
*
***************************************************************************************************/

int idaapi PluginStartup(void)
{
	if ( ph.id != PLFM_PPC )
		return PLUGIN_SKIP;

	// Debug stuff to identify auto-comment status
//	if ( showAllComments() )
//		msg( "All comments enabled\n" );
//	else
//		msg( "All comments disabled\n" );
	
	// Create our node...
	g_AltivecNode.create( g_AltivecNodeName );

	// Retrieve any existing hook state that may be in the database.
	HookState	databaseHookState = ( HookState )g_AltivecNode.altval( 0 );

	// altval() returns 0 (which maps to kDefault) when the value isn't there.. so handle it.
	if ( databaseHookState != kDefault )
		g_HookState = databaseHookState;	

	if ( g_HookState == kEnabled )
	{
		hook_to_notification_point( HT_IDP, PluginExtensionCallback, NULL );
		msg( "%s is enabled\n", g_pluginName);
		return PLUGIN_KEEP;
	}
	
	return PLUGIN_OK;
}

/***************************************************************************************************
*
*	FUNCTION		PluginShutdown
*
*	DESCRIPTION		IDA will call this function when the user asks to exit. This function is *not*
*					called in the case of emergency exits.
*
*   NOTES			All we can do here is to release from our callbacks..
*
***************************************************************************************************/

void idaapi PluginShutdown(void)
{
	unhook_from_notification_point( HT_IDP, PluginExtensionCallback );
}


/***************************************************************************************************
*
*	FUNCTION		PluginMain
*
*	DESCRIPTION		Our plugin is all about hooking callbacks.. 
*
***************************************************************************************************/

void idaapi PluginMain(int param)
{
	if ( g_HookState == kEnabled )
	{
		unhook_from_notification_point( HT_IDP, PluginExtensionCallback );
		g_HookState = kDisabled;
	}
	else
	if ( g_HookState == kDisabled )
	{
		hook_to_notification_point( HT_IDP, PluginExtensionCallback, NULL );
		g_HookState = kEnabled;
	}

	g_AltivecNode.create( g_AltivecNodeName );
	g_AltivecNode.altset( 0, g_HookState );

	static const char* pHookStateDescription[] = 
	{
		"default",
		"enabled",
		"disabled",
	};

	info(	"AUTOHIDE NONE\n"
			"%s is now %s", g_pluginName, pHookStateDescription[ g_HookState ] );
}


/***************************************************************************************************
*
*	This 'PLUGIN' data block is how IDA Pro interfaces with this plugin.
*
***************************************************************************************************/
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	0,						// plugin flags	
	
	PluginStartup,			// initialize
	PluginShutdown,			// terminate. this pointer may be NULL.
	PluginMain,				// invoke plugin
	
	g_pluginName,			// long comment about the plugin. It could appear in the status line or as a hint
	g_pluginHelp,			// multiline help about the plugin
	g_pluginName,			// the preferred short name of the plugin
	""						// the preferred hotkey to run the plugin
};
