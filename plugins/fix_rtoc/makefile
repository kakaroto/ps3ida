#G++=gcc -D_FORTIFY_SOURCE=0

PROC=fix_rtoc
!include ..\plugin.mak

# MAKEDEP dependency list ------------------
$(F)fix_rtoc$(O)     :  $(I)bytes.hpp $(I)loader.hpp       \
	          		 $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)name.hpp     \
	          		 $(I)pro.h  $(I)allins.hpp fix_rtoc.cpp
