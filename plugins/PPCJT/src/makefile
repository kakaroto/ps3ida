#G++=gcc -D_FORTIFY_SOURCE=0

PROC=ppcjt
!include ..\plugin.mak

# MAKEDEP dependency list ------------------
$(F)ppcjt$(O)     :  $(I)bytes.hpp $(I)auto.hpp $(I)loader.hpp       \
	          		 $(I)ida.hpp $(I)idp.hpp $(I)kernwin.hpp $(I)name.hpp     \
	          		 $(I)offset.hpp $(I)..\module\jptcmn.cpp ppcjt.cpp
