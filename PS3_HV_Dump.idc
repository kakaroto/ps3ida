// 
// Automatically sets up the PS3 HV Dumps for easier reversing.
// 
// This should set up the function tables, resolve rtoc offsets
// and find some common functions amoung other things.
// 
// xorloser February 2010
// 

#include "idc.idc"


static setup_opd(name, startAddr, endAddr)
{
	auto offset, size, func_addr, struct_id;
	size = endAddr - startAddr;
	
	// create opd entry struct
	DelStruc( GetStrucIdByName("OPDEntry") );
	struct_id = AddStrucEx(-1, "OPDEntry", 0);
	AddStrucMember(struct_id, "addr",		 0, FF_QWRD|FF_DATA|FF_0OFF,	 0, 8);
	AddStrucMember(struct_id, "rtocVal",	 8, FF_QWRD|FF_DATA,			-1, 8);
	AddStrucMember(struct_id, "zero",		16, FF_QWRD|FF_DATA,			-1, 8);
	
	MakeNameEx(startAddr, name, SN_NOCHECK);
	for(offset=0; offset<size; offset=offset+24)
	{
		MakeUnknown(startAddr+offset, 24, 0);
		MakeStructEx(startAddr+offset, -1, "OPDEntry");
		
		// if this points to a function, then create it
		func_addr = Qword(startAddr+offset+0);
		if( func_addr != 0 )
		{
			MakeUnkn(func_addr, 0);
			MakeFunction(func_addr, BADADDR);
		}
	}
}

static setup_offset_table(name, startAddr, endAddr)
{
	auto offset, size;
	size = endAddr - startAddr;
	
	MakeNameEx(startAddr, name, SN_NOCHECK);
	for(offset=0; offset<size; offset=offset+8)
	{
		MakeUnknown(startAddr+offset, 8, 0);
		MakeQword(startAddr+offset);	OpOff(startAddr+offset, 0, 0);
	}
}

static setup_data(name, startAddr, endAddr)
{
	auto item_offset, num_items, array_size, array_name, size, addr;
	
	if(startAddr == BADADDR || endAddr == BADADDR)
		return;
	
	// 5000 is max number of items in an array
	// so make multiple arrays
	size = endAddr - startAddr;
	addr = startAddr;
	MakeUnknown(addr, size, 0);
	num_items = size/8;
	
	for(item_offset=0; item_offset<num_items; item_offset=item_offset+5000)
	{
		if((num_items-item_offset) < 5000)
			array_size = num_items-item_offset;
		else
			array_size = 5000;
		
		array_name = form("%s_%d", name, item_offset);
		MakeNameEx(addr, array_name, SN_NOCHECK);
		
		MakeQword(addr);
		MakeArray(addr, array_size);
		addr = addr + 5000*8;
	}
}


static fix_rtoc_usage(rtocVal, startAddr, endAddr)
{
	auto addr, instr, offset, fixed_addr;
	
	// setup cross references for rtoc usage
	for(addr=startAddr; addr<endAddr; addr=addr+4)
	{
		instr = Dword(addr);
		
		// lwz  %r?, -0x7FC0(%rtoc)
		if((instr & 0xFC1F0000) == 0x80020000)
		{
			offset = (instr & 0xFFFF);
			if(offset >= 0x8000)
				offset = -(0x10000 - offset);
			fixed_addr = rtocVal + offset;
			
			MakeUnknown(fixed_addr, 4, 0);
			MakeDword(fixed_addr);
			OpOff(fixed_addr, 0, 0);
			
			// add_dref(from, to, type)
			del_dref(addr, Dword(fixed_addr));
			add_dref(addr, Dword(fixed_addr), XREF_USER|dr_R);
		}
		
		// ld  %r?, -0x7FC0(%rtoc)
		if((instr & 0xFC1F0000) == 0xE8020000)
		{
			offset = (instr & 0xFFFF);
			if(offset >= 0x8000)
				offset = -(0x10000 - offset);
			fixed_addr = rtocVal + offset;
			
			MakeUnknown(fixed_addr, 8, 0);
			MakeQword(fixed_addr);
			OpOff(fixed_addr, 0, 0);
			
			// add_dref(from, to, type)
			del_dref(addr, Qword(fixed_addr));
			add_dref(addr, Qword(fixed_addr), XREF_USER|dr_R);
		}
	}
}


static get_hvcall_rawname(num)
{
	if(     num ==   0) return "allocate_memory";
	else if(num ==   1) return "write_htab_entry";
	else if(num ==   2) return "construct_virtual_address_space";
	else if(num ==   3) return "invalidate_htab_entries";
	else if(num ==   4) return "get_virtual_address_space_id_of_ppe";
	else if(num ==   5) return "undocumented_function_5";
	else if(num ==   6) return "query_logical_partition_address_region_info";
	else if(num ==   7) return "select_virtual_address_space";
	else if(num ==   8) return "undocumented_function_8";
	else if(num ==   9) return "pause";
	else if(num ==  10) return "destruct_virtual_address_space";
	else if(num ==  11) return "configure_irq_state_bitmap";
	else if(num ==  12) return "connect_irq_plug_ext";
	else if(num ==  13) return "release_memory";
	else if(num ==  15) return "put_iopte";
	else if(num ==  16) return "peek";
	else if(num ==  17) return "disconnect_irq_plug_ext";
	else if(num ==  18) return "construct_event_receive_port";
	else if(num ==  19) return "destruct_event_receive_port";
	else if(num ==  20) return "poke";
	else if(num ==  24) return "send_event_locally";
	else if(num ==  26) return "detect_pending_interrupts";
	else if(num ==  27) return "end_of_interrupt";
	else if(num ==  28) return "connect_irq_plug";
	else if(num ==  29) return "disconnect_irq_plug";
	else if(num ==  30) return "end_of_interrupt_ext";
	else if(num ==  31) return "did_update_interrupt_mask";
	else if(num ==  44) return "shutdown_logical_partition";
	else if(num ==  54) return "destruct_logical_spe";
	else if(num ==  57) return "construct_logical_spe";
	else if(num ==  61) return "set_spe_interrupt_mask";
	else if(num ==  62) return "undocumented_function_62";
	else if(num ==  64) return "set_spe_transition_notifier";
	else if(num ==  65) return "disable_logical_spe";
	else if(num ==  66) return "clear_spe_interrupt_status";
	else if(num ==  67) return "get_spe_interrupt_status";
	else if(num ==  69) return "get_logical_ppe_id";
	else if(num ==  73) return "set_interrupt_mask";
	else if(num ==  74) return "get_logical_partition_id";
	else if(num ==  75) return "undocumented_function_75";
	else if(num ==  77) return "configure_execution_time_variable";
	else if(num ==  78) return "get_spe_irq_outlet";
	else if(num ==  79) return "set_spe_privilege_state_area_1_register";
	else if(num ==  89) return "undocumented_function_89";
	else if(num ==  90) return "create_repository_node";
	else if(num ==  91) return "get_repository_node_value";
	else if(num ==  92) return "modify_repository_node_value";
	else if(num ==  93) return "remove_repository_node";
	else if(num ==  95) return "read_htab_entries";
	else if(num ==  96) return "set_dabr";
	else if(num ==  97) return "set_vmx_graphics_mode";
	else if(num ==  98) return "set_thread_switch_control_register";
	else if(num ==  99) return "undocumented_function_99";
	else if(num == 102) return "undocumented_function_102";
	else if(num == 105) return "undocumented_function_105";
	else if(num == 106) return "undocumented_function_106";
	else if(num == 107) return "undocumented_function_107";
	else if(num == 108) return "undocumented_function_108";
	else if(num == 109) return "undocumented_function_109";
	else if(num == 110) return "undocumented_function_110";
	else if(num == 111) return "undocumented_function_111";
	else if(num == 112) return "undocumented_function_112";
	else if(num == 114) return "undocumented_function_114";
	else if(num == 115) return "undocumented_function_115";
	else if(num == 116) return "allocate_io_segment";
	else if(num == 117) return "release_io_segment";
	else if(num == 118) return "allocate_ioid";
	else if(num == 119) return "release_ioid";
	else if(num == 120) return "construct_io_irq_outlet";
	else if(num == 121) return "destruct_io_irq_outlet";
	else if(num == 122) return "map_htab";
	else if(num == 123) return "unmap_htab";
	else if(num == 124) return "undocumented_function_124";
	else if(num == 125) return "undocumented_function_125";
	else if(num == 126) return "undocumented_function_126";
	else if(num == 127) return "get_version_info";
	else if(num == 134) return "undocumented_function_134";
	else if(num == 135) return "undocumented_function_135";
	else if(num == 136) return "undocumented_function_136";
	else if(num == 137) return "undocumented_function_137";
	else if(num == 138) return "undocumented_function_138";
	else if(num == 140) return "construct_lpm";
	else if(num == 141) return "destruct_lpm";
	else if(num == 142) return "start_lpm";
	else if(num == 143) return "stop_lpm";
	else if(num == 144) return "copy_lpm_trace_buffer";
	else if(num == 145) return "add_lpm_event_bookmark";
	else if(num == 146) return "delete_lpm_event_bookmark";
	else if(num == 147) return "set_lpm_interrupt_mask";
	else if(num == 148) return "get_lpm_interrupt_status";
	else if(num == 149) return "set_lpm_general_control";
	else if(num == 150) return "set_lpm_interval";
	else if(num == 151) return "set_lpm_trigger_control";
	else if(num == 152) return "set_lpm_counter_control";
	else if(num == 153) return "set_lpm_group_control";
	else if(num == 154) return "set_lpm_debug_bus_control";
	else if(num == 155) return "set_lpm_counter";
	else if(num == 156) return "set_lpm_signal";
	else if(num == 157) return "set_lpm_spr_trigger";
	else if(num == 158) return "insert_htab_entry";
	else if(num == 162) return "read_virtual_uart";
	else if(num == 163) return "write_virtual_uart";
	else if(num == 164) return "set_virtual_uart_param";
	else if(num == 165) return "get_virtual_uart_param";
	else if(num == 166) return "configure_virtual_uart_irq";
	else if(num == 167) return "undocumented_function_167";
	else if(num == 168) return "undocumented_function_168";
	else if(num == 170) return "open_device";
	else if(num == 171) return "close_device";
	else if(num == 172) return "map_device_mmio_region";
	else if(num == 173) return "unmap_device_mmio_region";
	else if(num == 174) return "allocate_device_dma_region";
	else if(num == 175) return "free_device_dma_region";
	else if(num == 176) return "map_device_dma_region";
	else if(num == 177) return "unmap_device_dma_region";
	else if(num == 178) return "read_pci_config";
	else if(num == 179) return "write_pci_config";
	else if(num == 180) return "read_pci_io";
	else if(num == 181) return "write_pci_io";
	else if(num == 182) return "undocumented_function_182";
	else if(num == 183) return "undocumented_function_183";
	else if(num == 185) return "net_add_multicast_address";
	else if(num == 186) return "net_remove_multicast_address";
	else if(num == 187) return "net_start_tx_dma";
	else if(num == 188) return "net_stop_tx_dma";
	else if(num == 189) return "net_start_rx_dma";
	else if(num == 190) return "net_stop_rx_dma";
	else if(num == 191) return "net_set_interrupt_status_indicator";
	else if(num == 193) return "net_set_interrupt_mask";
	else if(num == 194) return "net_control";
	else if(num == 195) return "undocumented_function_195";
	else if(num == 196) return "undocumented_function_196";
	else if(num == 197) return "connect_interrupt_event_receive_port";
	else if(num == 198) return "disconnect_interrupt_event_receive_port";
	else if(num == 199) return "get_spe_all_interrupt_statuses";
	else if(num == 200) return "undocumented_function_200";
	else if(num == 201) return "undocumented_function_201";
	else if(num == 202) return "deconfigure_virtual_uart_irq";
	else if(num == 207) return "enable_logical_spe";
	else if(num == 209) return "undocumented_function_209";
	else if(num == 210) return "gpu_open";
	else if(num == 211) return "gpu_close";
	else if(num == 212) return "gpu_device_map";
	else if(num == 213) return "gpu_device_unmap";
	else if(num == 214) return "gpu_memory_allocate";
	else if(num == 216) return "gpu_memory_free";
	else if(num == 217) return "gpu_context_allocate";
	else if(num == 218) return "gpu_context_free";
	else if(num == 221) return "gpu_context_iomap";
	else if(num == 222) return "undocumented_function_222";
	else if(num == 225) return "gpu_context_attribute";
	else if(num == 227) return "gpu_context_intr";
	else if(num == 228) return "gpu_attribute";
	else if(num == 231) return "undocumented_function_231";
	else if(num == 232) return "get_rtc";
	else if(num == 233) return "undocumented_function_233";
	else if(num == 240) return "set_ppe_periodic_tracer_frequency";
	else if(num == 241) return "start_ppe_periodic_tracer";
	else if(num == 242) return "stop_ppe_periodic_tracer";
	else if(num == 243) return "undocumented_function_243";
	else if(num == 244) return "undocumented_function_244";
	else if(num == 245) return "storage_read";
	else if(num == 246) return "storage_write";
	else if(num == 248) return "storage_send_device_command";
	else if(num == 249) return "storage_get_async_status";
	else if(num == 250) return "undocumented_function_250";
	else if(num == 251) return "undocumented_function_251";
	else if(num == 252) return "undocumented_function_252";
	else if(num == 253) return "undocumented_function_253";
	else if(num == 254) return "storage_check_async_status";
	else if(num == 255) return "panic";
	else				return form("undocumented_function_%d", num);
}

static get_hvcall_name(num)
{
	return "lv1_" + get_hvcall_rawname(num);
}

static get_mmcall_name(num)
{
	return "mm_" + get_hvcall_rawname(num);
}


static setup_hv_table(name, startAddr)
{
	auto size, addr, idx, count;
	count = 256;
	size = count * 8;
	
	MakeNameEx(startAddr, "", 0);
	MakeNameEx(startAddr, name, 0);
	MakeUnknown(startAddr, size, 0);
	for(idx=0; idx<count; idx=idx+1)
	{
		addr = startAddr + idx*8;
		MakeQword(addr);
		if(Qword(addr) != 0)
		{
			OpOff(addr, 0, 0);
			MakeNameEx(Qword(addr), "", 0);
			MakeNameEx(Qword(addr), get_hvcall_name(idx), 0);
			MakeFunction(Qword(addr), BADADDR);
		}
	}
	
	// fix these entries
	MakeNameEx(Qword(startAddr +  0*8), "lv1_mm_call", 0);
	MakeNameEx(Qword(startAddr + 14*8), "lv1_invalid_hvcall", 0);
}

static setup_mm_table(name, startAddr)
{
	auto size, addr, idx, count;
	count = 256;
	size = count * 8;
	
	MakeNameEx(startAddr, "", 0);
	MakeNameEx(startAddr, name, 0);
	MakeUnknown(startAddr, size, 0);
	for(idx=0; idx<count; idx=idx+1)
	{
		addr = startAddr + idx*8;
		MakeQword(addr);
		if(Qword(addr) != 0)
		{
			OpOff(addr, 0, 0);
			MakeNameEx(Qword(addr), "", 0);
			MakeNameEx(Qword(addr), get_mmcall_name(idx), 0);
			MakeFunction(Qword(addr), BADADDR);
		}
	}
}


static make_code(startAddr, endAddr, clearFirst)
{
	auto addr;
	if(clearFirst)
		MakeUnknown(startAddr, endAddr-startAddr, 0);
	for(addr=startAddr; addr<endAddr; addr=addr+4)
	{
		MakeCode(addr);
	}
}

static make_function(name, startAddr, endAddr, returns)
{
	MakeUnknown(startAddr, endAddr-startAddr, 0);
	MakeCode(startAddr);
	// this is done to support any instructions that do not disassemble correctly
	MakeFunction(startAddr, startAddr+4);
	SetFunctionEnd(startAddr, endAddr);
	
	make_code(startAddr, endAddr, 0);
	if( !returns ) SetFunctionFlags(startAddr, FUNC_NORET);
	
	MakeName(startAddr, name);
}

static make_function_simple(name, startAddr, returns)
{
	if(startAddr == BADADDR)
		return;
	
	MakeFunction(startAddr, BADADDR);
	MakeName(startAddr, name);
	if( !returns ) SetFunctionFlags(startAddr, FUNC_NORET);
}





// Find the address of the HV version
static find_version(startAddr, endAddr)
{
	auto addr;
	
	// NOTE: FindBinary is much faster than FindText and doesn't
	// require the string to be "setup" yet.
	
	// string is: "release build:"
	addr = FindBinary(startAddr, SEARCH_DOWN|SEARCH_CASE, "72 65 6c 65 61 73 65 20 62 75 69 6c 64 3a");
	if(addr == BADADDR)
		return BADADDR;
	
	// string is: "JST"
	addr = FindBinary(addr, SEARCH_DOWN|SEARCH_CASE, "4a 53 54");
	if(addr == BADADDR)
		return BADADDR;
	addr = addr + strlen("JST 200x") + 1;
	addr = addr + 8 - (addr%8);
	
	return addr;
}

static find_opd_start(versionAddr, endAddr)
{
	auto addr;
	
	for(addr=versionAddr+0x10; addr<endAddr; addr=addr+8)
	{
		if(Qword(addr) != 0)
			return addr;
	}
	
	return BADADDR;
}

static find_opd_end(opdStart, endAddr)
{
	auto addr, rtoc_val;
	rtoc_val = Qword(opdStart+8);
	
	for(addr=opdStart; addr<endAddr; addr=addr+0x18)
	{
		if(Qword(addr+8) != rtoc_val)
			return addr;
	}
	return BADADDR;
}

static find_toc_end(tocStart, endAddr)
{
	auto addr;
	
	for(addr=tocStart; addr<endAddr; addr=addr+8)
	{
		if(Qword(addr) == 0)
			return addr;
	}
	
	return BADADDR;
}

static find_text_end(versionAddr, startAddr)
{
	auto addr;
	
	// search for:
	// "mtlr %r0"
	// "blr"
	addr = FindBinary(versionAddr, SEARCH_CASE, "7c 08 03 a6 4e 80 00 20");
	if(addr == BADADDR)
		return BADADDR;
	addr = addr + 8;
	return addr;
}

static find_rtoc_addr(opdStart)
{
	return Qword(opdStart+8);
}

static find_lv2ldr_start(startAddr, endAddr)
{
	auto addr;
	addr = 0x020000;
	if(	Dword(addr+0) == 0x53434500 && Dword(addr+4) == 0x00000002 )
		return addr;
	return BADADDR;
}

static find_lv2ldr_end(startAddr, endAddr)
{
	auto addr;
	addr = startAddr;
	if( Dword(addr+0) == 0x53434500 && Dword(addr+4) == 0x00000002 )
		return startAddr + Qword(startAddr+0x10) + Qword(startAddr+0x18);
	return BADADDR;
}

static find_appldr_start(startAddr, endAddr)
{
	auto addr;
	addr = 0x037000;
	if(	Dword(addr+0) == 0x53434500 && Dword(addr+4) == 0x00000002 )
		return addr;
	return BADADDR;
}

static find_appldr_end(startAddr, endAddr)
{
	auto addr;
	addr = startAddr;
	if( Dword(addr+0) == 0x53434500 && Dword(addr+4) == 0x00000002 )
		return startAddr + Qword(startAddr+0x10) + Qword(startAddr+0x18);
	return BADADDR;
}

static find_isoldr_start(startAddr, endAddr)
{
	auto addr;
	addr = 0x055000;
	if(	Dword(addr+0) == 0x53434500 && Dword(addr+4) == 0x00000002 )
		return addr;
	return BADADDR;
}

static find_isoldr_end(startAddr, endAddr)
{
	auto addr;
	addr = startAddr;
	if( Dword(addr+0) == 0x53434500 && Dword(addr+4) == 0x00000002 )
		return startAddr + Qword(startAddr+0x10) + Qword(startAddr+0x18);
	return BADADDR;
}

static find_hvcall_start(startAddr, endAddr)
{
	auto offset, hvc_table_addr, invalid_call_addr;
	
	invalid_call_addr = FindBinary(startAddr, SEARCH_DOWN|SEARCH_CASE, "38 60 00 00 64 63 ff ff 60 63 ff ec 4e 80 00 20");
	if(invalid_call_addr == BADADDR)
		return BADADDR;
	
	for(offset=startAddr; offset<endAddr - 0x20; offset=offset+8)
	{
		if(	Qword(offset + 0x00) == invalid_call_addr &&
			Qword(offset + 0x08) == invalid_call_addr &&
			Qword(offset + 0x10) == invalid_call_addr &&
			Qword(offset + 0x18) != invalid_call_addr &&
			Qword(offset + 0x20) == invalid_call_addr )
		{
			return offset - (21*8);
		}
	}
	
	// not found
	return BADADDR;
}

static find_mmcall_start(hvcallAddr, endAddr)
{
	return hvcallAddr + (256*8);
}

static find_puts(hvcallAddr)
{
	auto addr, offset;
	
	addr = Qword(hvcallAddr + (210*8));
	addr = FindBinary(addr, SEARCH_CASE|SEARCH_DOWN, "4E 80 00 20");
	if(addr == BADADDR)
		return BADADDR;
	
	for(offset=0; offset<0x80; offset=offset+4)
	{
		if(	(Dword(addr+offset+0) & 0xFFFF0000) == 0xE8620000 &&
			(Dword(addr+offset+4) & 0xFC000000) == 0x48000000 )
		{
			addr = Rfirst0(addr+offset+4);
			return addr;
		}
	}
	
	return BADADDR;
}

static find_abend_print(hvcallAddr)
{
	auto addr, offset, puts_addr, puts_count;
	
	addr = Qword(hvcallAddr + (210*8));
	addr = FindBinary(addr, SEARCH_CASE|SEARCH_DOWN, "4E 80 00 20");
	if(addr == BADADDR)
		return BADADDR;
	
	puts_addr = 0;
	puts_count = 0;
	for(offset=0; offset<0x80; offset=offset+4)
	{
		// test for puts func call
		if(	puts_addr == 0 &&
			((Dword(addr+offset+0) & 0xFFFF0000) == 0xE8620000 &&
			 (Dword(addr+offset+4) & 0xFC000000) == 0x48000000) )
		{
			puts_addr = Rfirst0(addr+offset+4);
			if(puts_addr == BADADDR)
				return BADADDR;
		}
		// test if is a function call
		else if((Dword(addr+offset) & 0xFC000000) == 0x48000000)
		{
			if( puts_addr == Rfirst0(addr+offset) )
				puts_count = puts_count + 1;
			else if(puts_count == 3)
			{
				return Rfirst0(addr+offset);
			}
		}
		
	}
	
	return BADADDR;
}

static find_abend(hvcallAddr)
{
	auto addr, offset, count;
	
	addr = find_abend_print(hvcallAddr);
	if(addr == BADADDR)
		return BADADDR;
	
	count = 0;
	for(offset=0; offset<0x80; offset=offset+4)
	{
		if((Dword(addr+offset) & 0xFC000000) == 0x48000000)
			count++;
		if(count == 4)
			return Rfirst0(addr+offset);
	}
	
	return BADADDR;
}

static find_printf(versionAddr)
{
	auto addr, offset;
	
	addr = FindBinary(versionAddr, SEARCH_CASE, "30 31 32 33 34 35 36 37 38 39 61 62 63 64 65 66 67 68 69");
	if(addr == BADADDR)
		return BADADDR;
	
	addr = DfirstB(addr);
	if(addr == BADADDR)
		return BADADDR;
	
	addr = FindBinary(addr, SEARCH_CASE, "7D 80 00 26");
	
	addr = RfirstB0(addr);
	if(addr == BADADDR)
		return BADADDR;
	
	for(offset=0; offset<0x80; offset=offset+4)
	{
		if((Dword(addr-offset)&0xFFFF0000) == 0xF8210000)
			return addr-offset;
	}
	
	return BADADDR;
}

static handle_find_results(addr, name)
{
	if(addr == BADADDR)
	{
		Message("Error finding %s\n", name);
		return 0;
	}
	
	// success
	return 1;
}



static main()
{
	// search for version specific addresses in order to set up everything
	auto version_addr, text_start, text_end, opd_start, opd_end, limit_start, limit_end,
		got_start, got_end, toc_start, toc_end, rtoc_addr, lv2ldr_start, lv2ldr_end,
		appldr_start, appldr_end, isoldr_start, isoldr_end, hvcall_addr, mmcall_addr, yn;
	
	Message("\n\nPS3 HV Dump script  -  xorloser February 2010\n\n");
	
	limit_start	= 0x200000;
	limit_end	= 0x400000;
	
	version_addr = find_version(limit_start, limit_end);
	if( !handle_find_results(version_addr,	"HV version") ) return;
	Message("%08x: Version found:  v%x.%x.%x.%x\n", version_addr,
		Word(version_addr+4), Word(version_addr+6),
		Word(version_addr+12), Word(version_addr+14));
	
	// search for the opd
	opd_start = find_opd_start(version_addr, limit_end);
	if( !handle_find_results(opd_start,	"OPD start") ) return;
	opd_end = find_opd_end(opd_start, limit_end);
	if( !handle_find_results(opd_end,	"OPD end") ) return;
	Message("%08x: OPD limits(0x%x, 0x%x)\n", opd_start, opd_start, opd_end);
	
	// search for got
	got_start	= opd_end;
	if( !handle_find_results(got_start,	"GOT start") ) return;
	got_end		= got_start + 8;
	if( !handle_find_results(got_end,	"GOT end") ) return;
	Message("%08x: GOT limits(0x%x, 0x%x)\n", got_start, got_start, got_end);
	
	// search for toc
	toc_start	= got_end;
	if( !handle_find_results(toc_start,	"TOC start") ) return;
	toc_end		= find_toc_end(toc_start, limit_end);
	if( !handle_find_results(toc_end,	"TOC end") ) return;
	Message("%08x: TOC limits(0x%x, 0x%x)\n", toc_start, toc_start, toc_end);
	
	// search for text limits
	text_start	= limit_start;
	if( !handle_find_results(text_start,"TEXT start") ) return;
	text_end	= find_text_end(version_addr, limit_start);
	if( !handle_find_results(text_end,	"TEXT end") ) return;
	Message("%08x: Text limits(0x%x, 0x%x)\n", text_start, text_start, text_end);
	
	// search for the rtoc value
	rtoc_addr = find_rtoc_addr(opd_start);
	if( !handle_find_results(rtoc_addr,	"RTOC value") ) return;
	Message("%08x: RTOC: 0x%x\n", rtoc_addr, rtoc_addr);
	
	// search for hvcall table
	hvcall_addr	= find_hvcall_start(limit_start, limit_end);
	if( !handle_find_results(hvcall_addr,	"hvcall start") ) return;
	Message("%08x: hvcall limits(0x%x, 0x%x)\n", hvcall_addr, hvcall_addr, hvcall_addr+(256*8));

	// search for mmcall table
	mmcall_addr	= find_mmcall_start(hvcall_addr, limit_end);
	if( !handle_find_results(mmcall_addr,	"mmcall start") ) return;
	Message("%08x: mmcall limits(0x%x, 0x%x)\n", mmcall_addr, mmcall_addr, mmcall_addr+(256*8));
	
	// search for lv2ldr
	lv2ldr_start= find_lv2ldr_start(limit_start, limit_end);//if( !handle_find_results(lv2ldr_start,	"lv2ldr start") ) return;
	lv2ldr_end	= find_lv2ldr_end(lv2ldr_start, limit_end);	//if( !handle_find_results(lv2ldr_end,	"lv2ldr end") ) return;
	Message("%08x: lv2ldr limits(0x%x, 0x%x)\n", lv2ldr_start, lv2ldr_start, lv2ldr_end);
	
	// search for appldr
	appldr_start= find_appldr_start(limit_start, limit_end);//if( !handle_find_results(appldr_start,	"appldr start") ) return;
	appldr_end	= find_appldr_end(appldr_start, limit_end);	//if( !handle_find_results(appldr_end,	"appldr end") ) return;
	Message("%08x: appldr limits(0x%x, 0x%x)\n", appldr_start, appldr_start, appldr_end);
	
	// search for isoldr
	isoldr_start= find_isoldr_start(limit_start, limit_end);//if( !handle_find_results(isoldr_start,	"isoldr start") ) return;
	isoldr_end	= find_isoldr_end(isoldr_start, limit_end);	//if( !handle_find_results(isoldr_end,	"isoldr end") ) return;
	Message("%08x: isoldr limits(0x%x, 0x%x)\n", isoldr_start, isoldr_start, isoldr_end);
	
	
	// convert text section to code
	yn = AskYN(0,	"Do you want to force the entire text section to code?\n"
					"WARNING: This will remove any existing work done.");
	if(yn == -1)
	{
		Message("Cancelled by user\n");
		return;
	}
	else if(yn == 1)
	{
		Message("Forcing text to code...\n");
		make_code(text_start, text_end, 0);
	}
	
	// data sections that are not really part of the code
	// so set these up so they can be safely handled (ignored)
	setup_data(			"lv2ldr",		lv2ldr_start, lv2ldr_end);
	setup_data(			"appldr",		appldr_start, appldr_end);
	setup_data(			"isoldr",		isoldr_start, isoldr_end);
	
	// tables that can be used to setup a lot of functions
	setup_opd(			"opd_table",	opd_start, opd_end);
	setup_offset_table(	"got_table",	got_start, got_end);
	setup_offset_table(	"toc_table",	toc_start, toc_end);
	setup_hv_table(		"hvcall_table",	hvcall_addr);
	setup_mm_table(		"mmcall_table",	mmcall_addr);
	
	// fix rtoc usage so that data references are created
	yn = AskYN(0,	"Do you want to setup all rtoc usages?\n"
					"This may take a little while.");
	if(yn == -1)
	{
		Message("Cancelled by user\n");
		return;
	}
	else if(yn == 1)
	{
		Message("Setting up RTOC...\n");
		fix_rtoc_usage(rtoc_addr,		text_start, text_end);
	}
	
	make_function("INT_SystemReset",	0x100, 0x120, 1);
	make_function("INT_MachineCheck",	0x200, 0x208, 1);
	make_function("INT_DataStorage",	0x300, 0x304, 1);
	make_function("INT_DataSegment",	0x380, 0x384, 1);
	make_function("INT_InstrStorage",	0x400, 0x404, 1);
	make_function("INT_InstrSegment",	0x480, 0x484, 1);
	make_function("INT_External",		0x500, 0x528, 1);
	make_function("INT_Alignment",		0x600, 0x604, 1);
	make_function("INT_Program",		0x700, 0x704, 1);
	make_function("INT_FPUnavailable",	0x800, 0x804, 1);
	make_function("INT_Decrementer",	0x900, 0x938, 1);
	make_function("INT_HVDecrementer",	0x980, 0x9A8, 1);
	make_function("INT_Syscall",		0xC00, 0xC5C, 1);
	make_function("INT_Trace",			0xD00, 0xD40, 1);
	make_function("INT_VXUUnavailable",	0xF20, 0xF60, 1);
	make_function("INT_SystemError",	0x1200,0x1240,1);
	make_function("INT_Maitenance",		0x1600,0x1640,1);
	make_function("INT_ThermalMgmt",	0x1800,0x1840,1);
	
	make_function_simple("puts",		find_puts(hvcall_addr), 1);
	make_function_simple("abend_print",	find_abend_print(hvcall_addr), 0);
	make_function_simple("abend",		find_abend(hvcall_addr), 0);
	make_function_simple("printf",		find_printf(version_addr), 1);
	
	Message("\ndone\n");
}

