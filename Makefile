CC := gcc

ifeq ($(DEBUG),1)
	CFLAGS := -g -Wall -DDEBUG
else
	CFLAGS := -Wall
endif

OBJS = net.o fileLib.o font16_st.o gb2unicode.o vmrp.o tsf_font.o utils.o debug.o \
	 rbtree.o bridge.o memory.o baseLib_cfunction.ext.o main.o sound.o encode.c

UNICORN = -lunicorn
CAPSTONE = -lcapstone
ifeq ($(OS),Windows_NT)
	UNICORN = ./windows/unicorn-1.0.2-win32/unicorn.lib
	CAPSTONE = ./windows/capstone-4.0.1-win32/capstone.dll
endif

SDL2 = ./windows/SDL2-2.0.10/i686-w64-mingw32
UNIPATH = ./windows/unicorn-1.0.2-win32/include/unicorn/


# -Wl,-subsystem,windows gets rid of the console window
# gcc  -o main.exe main.c -lmingw32 -Wl,-subsystem,windows -L./lib -lSDL2main -lSDL2 -fexec-charset=GBK -finput-charset=GBK 
main: $(OBJS)
	$(CC) $(CFLAGS) -m32 -DEXT_CALL  -o ./bin/$@ $^ $(UNICORN) $(CAPSTONE) -lpthread -lm -lz \
		-lws2_32 -lmingw32  -L$(SDL2)/lib/ -I$(UNIPATH) -lSDL2main -lSDL2 -lwinmm -liconv

ifeq (,$(wildcard ./bin/capstone.dll))
	cp $(CAPSTONE) ./bin/
	cp $(SDL2)/bin/SDL2.dll ./bin/
	cp ./windows/unicorn-1.0.2-win32/unicorn.dll ./bin/
	cp ./windows/unicorn-1.0.2-win32/libwinpthread-1.dll ./bin/
endif

%.o:%.c
	$(CC) $(CFLAGS) -m32 -c $^

.PHONY: clean
clean:
	-rm *.o



