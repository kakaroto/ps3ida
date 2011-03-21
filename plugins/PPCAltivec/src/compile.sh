
g++ -g -D__LINUX__ -D_FORTIFY_SOURCE=0 -fvisibility=hidden -fvisibility-inlines-hidden --shared -D__EA64__ -I$HOME/idasdk/60/module -I$HOME/idasdk/60/include/ -DNO_OBSOLETE_FUNCS -D__IDP__ -pipe -c -o main.o64 main.cpp  && \
g++ -lrt -lpthread -D__LINUX__ -D_FORTIFY_SOURCE=0 -fvisibility=hidden -fvisibility-inlines-hidden --shared -Wl,--gc-sections -Wl,--no-undefined -o ppcaltivec.plx64 main.o64 -L$HOME/idasdk/60/bin/ -lida64

g++ -g -D__LINUX__ -D_FORTIFY_SOURCE=0 -fvisibility=hidden -fvisibility-inlines-hidden --shared -I$HOME/idasdk/60/module -I$HOME/idasdk/60/include/ -DNO_OBSOLETE_FUNCS -D__IDP__ -pipe -c -o main.o main.cpp  && \
g++ -lrt -lpthread -D__LINUX__ -D_FORTIFY_SOURCE=0 -fvisibility=hidden -fvisibility-inlines-hidden --shared -Wl,--gc-sections -Wl,--no-undefined -o ppcaltivec.plx main.o -L$HOME/idasdk/60/bin/ -lida
