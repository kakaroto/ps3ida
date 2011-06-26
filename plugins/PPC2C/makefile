#G++=gcc -D_FORTIFY_SOURCE=0

PROC=ppc2c
O1=ppc2c_engine
O2=ppc2c_handlers
!include ..\plugin.mak

# MAKEDEP dependency list ------------------
$(F)ppc2c$(O)     :  $(I)bytes.hpp $(I)auto.hpp $(I)loader.hpp       \
	          		 $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)name.hpp     \
	          		 $(I)offset.hpp ppc2c.cpp ppc2c_engine.cpp ppc2c_handlers.cpp
