/*
 * resolve_events.idc -- Resolve XMB Events from its structure
 *
 * Copyright (C) Youness Alaoui (KaKaRoTo)
 *
 * This software is distributed under the terms of the GNU General Public
 * License ("GPL") version 3, as published by the Free Software Foundation.
 *
 */

#include "common.idh"

static escape_name(str) {
  auto i;

  for (i = 0; i < strlen(str); i = i + 1) {
    if (str[i] == ":") {
      str[i] = "_";
    }
  }

  return str;
}

static CreateXMBEventStructure(void) {
  auto id;

  id = CreateStructure("XMBEvent_s");
  AddStrucMember(id, "name", 0x00, FF_DWRD | FF_0OFF, 0, 4);
  AddStrucMember(id, "opd", 0x04, FF_DWRD | FF_0OFF, 0, 4);
  AddStrucMember(id, "zero", 0x08, FF_DWRD, 0, 4);

  return 1;
}



static main() {
  auto ea, name, opd, func;
  
  ea = ScreenEA();

  Warning("Make sure you first find the Events table yourself, and set the cursor"
          " on the first entry in the table.\n"
          "The Events Table is passed as %r4 to _paf_9DB21A04");

  if (AskYN (1, form("Do you want to resolve address 0x%X as "
                     "the Event Table?", ea)) != 1)
    return;

  CreateXMBEventStructure();
  MakeName(ea, "XMBEvents");

  while (ea != BADADDR && Dword(ea) != 0) {
    MakeUnknown(ea, 0x0C, DOUNK_SIMPLE);
    MakeStructEx (ea, 0x0C, "XMBEvent_s");
    name = Dword(ea);
    opd = Dword(ea + 4);
    func = Dword(opd);

    MakeUnknown(name, 4, DOUNK_SIMPLE);
    MakeStr(name, BADADDR);
    name = GetString(name, -1, ASCSTR_C);
    Message("XMB Event : 0x%X : %s\n", func, name);
    name = escape_name(name);
    MakeName(opd, form("%s_opd", name));
    MakeName(func, name);
    MakeFunction(func, BADADDR);

    ea = ea + 0x0C;
  }


}
