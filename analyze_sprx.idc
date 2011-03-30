/*
 * analyze_sprx.idc -- Analyzes a SPRX, find it's TOC, OPD and import/export structures.
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include "common.idh"

static FindToc(ea) {
  auto sub, toc, next_toc, consecutive_tocs;

  consecutive_tocs = 0;

  while (ea != BADADDR) {
    sub = Dword(ea);
    toc = Dword(ea + 0x04);
    next_toc = Dword(ea + 0x0C);
    //Message("0x%X: 0x%X - 0x%X - 0x%X - %d\n", ea, sub, toc, next_toc, consecutive_tocs);
    if (toc != 0x00 && toc == next_toc) {
      consecutive_tocs = consecutive_tocs + 1;
      ea = ea + 8;
    } else {
      if (consecutive_tocs > 10 && (toc - 0x8000) - (ea + 8) <= 0x10) {
	MakeName(toc, "TOC");
	break;
      }
      consecutive_tocs = 0;
      ea = ea + 4;
    }
    toc = 0;
  }

  return toc;
}



static FindImportsExports(opd, toc) {
  auto i, ea, module_name, import_start, import_end, export_start, export_end;
  auto imports, exports, name_ptr, name, fnid_ptr, fnid, stub_ptr, stub;

  CreateImportStructure();
  CreateExportStructure();

  Message("Finding Import/Export structure\n");

  ea = opd;
  /* Find import/export structure */
  while (ea != BADADDR && Dword(ea - 0x04) != toc) {
    ea = ea - 0x04;
  }
  if (ea == BADADDR) {
    Message("Couldn't find what I was looking for\n");
    return 0;
  }

  MakeDword(ea - 4);
  OpOff (ea - 4, 0, 0);
  MakeName(ea - 4, "TOC_ptr");
  MakeDword(ea);
  OpOff (ea, 0, 0);
  MakeName(ea, "Export_start");
  MakeDword(ea + 0x04);
  OpOff (ea + 0x04, 0, 0);
  MakeName(ea + 0x04, "Export_end");
  MakeDword(ea + 0x08);
  OpOff (ea + 0x08, 0, 0);
  MakeName(ea + 0x08, "Import_start");
  MakeDword(ea + 0x0C);
  OpOff (ea + 0x0C, 0, 0);
  MakeName(ea + 0x0C, "Import_end");

  export_start = Dword(ea);
  export_end = Dword(ea + 0x04);
  import_start = Dword(ea + 0x08);
  import_end = Dword(ea + 0x0C);
  Message("Found module Import/Export structure at 0x%X\n", ea);

  CreateImports(import_start, import_end);
  CreateExports(export_start, export_end);

  module_name = Dword(stub_ptr + (i*4)) + 4;
  MakeStr(module_name, BADADDR);
  MakeName(module_name,  "ModuleName");
  Message("Module name is : %s\n", GetString(module_name, -1, ASCSTR_C));

  return ea;
}

static main() {
  auto ea, toc, opd;
  
  //MakeUnknown(0, BADADDR, DOUNK_SIMPLE);
  ea = ScreenEA();
  ea = NextSeg(FirstSeg());

  toc = FindToc(ea);
  
   if (toc != 0) {
    Message("\nFound TOC at 0x%X\n", toc);
    opd = CreateOpd(toc);
    FindImportsExports(opd, toc);
    MakeName(toc, "TOC");
    Message("\TOC label at 0x%X\n", toc);
  } else {
    Message("Sorry, couldn't find the TOC");
  }
}
