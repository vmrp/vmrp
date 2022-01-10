CC := gcc
CFLAGS := -g -Wall -DNETWORK_SUPPORT -DVMRP
UNICORN = ./windows/unicorn-1.0.2-win32/unicorn.lib
SDL2 = ./windows/SDL2-2.0.10/i686-w64-mingw32
CAPSTONE := 

FILES := network.c fileLib.c vmrp.c utils.c rbtree.c bridge.c
ifeq ($(DEBUG),1)
	CFLAGS += -DDEBUG
	FILES += debug.c
	CAPSTONE := ./windows/capstone-4.0.1-win32/capstone.dll
ifeq (,$(wildcard ./bin/capstone.dll))
ifeq ($(DEBUG),1)
	cp $(CAPSTONE) ./bin/
endif
endif
endif

ifeq (,$(wildcard ./bin/SDL2.dll))
	cp $(SDL2)/bin/SDL2.dll ./bin/
	cp ./windows/unicorn-1.0.2-win32/unicorn.dll ./bin/
endif

LOCAL_CFLAGS_FULL := -DDSM_FULL -DMTK_MOD -DMR_PLAT_DRAWTEXT

LOCAL_SRC_FILES_FULL := src/mr_api.c \
                  src/mr_debug.c  \
                  src/mr_do.c     \
                  src/mr_dump.c   \
                  src/mr_func.c     \
                  src/mr_gc.c       \
                  src/mr_mem.c      \
                  src/mr_opcodes.c  \
                  src/mr_object.c  \
                  src/mr_state.c    \
                  src/mr_string.c   \
                  src/mr_table.c    \
                  src/mr_tm.c       \
                  src/mr_undump.c   \
                  src/mr_vm.c       \
                  src/mr_zio.c      \
                  src/lib/mr_auxiliar.c\
                  src/lib/mr_auxlib.c \
                  src/lib/mr_baselib.c\
                  src/lib/mr_iolib_target.c     \
                  src/lib/mr_socket_target.c     \
                  src/lib/mr_strlib.c     \
                  src/lib/mr_tablib.c   \
                  src/lib/mr_tcp_target.c

# 不带parser，无法运行lua文件
# LOCAL_SRC_FILES_FULL += src/parser/mr_noparser.c

# 带parser
LOCAL_SRC_FILES_FULL += src/parser/mr_code.c \
                src/parser/mr_lex.c \
                src/parser/mr_parser.c \
                src/parser/mr_tests.c

LOCAL_SRC_FILES_FULL += mythroad.c  encode.c  mr_pluto.c  mr_unzip.c  mr_base64.c  mr_graphics.c  mr_inflate.c \
                    string.c  printf.c  other.c  strtol.c  strtoul.c  dsm.c  md5.c  mem.c

LOCAL_SRC_FILES_FULL += tomr/tomr_to.c tomr/tomr_push.c #tomr/tomr_event.c tomr/tomr_is.c tomr/tomr_map.c  

ifeq ($(LUADEC),1)
LOCAL_SRC_FILES_FULL += luadec/luadec.c luadec/print.c luadec/StringBuffer.c luadec/structs.c luadec/proto.c 
LOCAL_CFLAGS_FULL += -DLUADEC
endif



full:
	$(CC) $(CFLAGS) -m32 -o ./bin/main.exe main.c $(FILES) $(LOCAL_CFLAGS_FULL) $(LOCAL_SRC_FILES_FULL) $(UNICORN) $(CAPSTONE) \
		-lpthread -lm -lws2_32 -lmingw32 -L$(SDL2)/lib/ -lSDL2main -lSDL2

#####################################################################

LOCAL_CFLAGS := -g -Wall -DMTK_MOD -DMR_PLAT_DRAWTEXT
LOCAL_SRC_FILES := mythroad_mini.c \
                    encode.c     \
                    mr_unzip.c	\
                    mr_base64.c	\
                    mr_inflate.c \
                    mr_graphics.c \
                    string.c \
                    printf.c	\
                    other.c	\
                    strtol.c	\
                    strtoul.c	\
                    dsm.c	\
                    fixR9.c	\
                    md5.c	\
                    mem.c	\
                    asm/r9r10.s	\

mini:
	gcc -o ../vmrp $(LOCAL_CFLAGS) $(LOCAL_SRC_FILES) main.c -lSDL2 -lm -lz




# -Wl,-subsystem,windows gets rid of the console window
# gcc  -o main.exe main.c -lmingw32 -Wl,-subsystem,windows -L./lib -lSDL2main -lSDL2
main:
	$(CC) $(CFLAGS) -m32 -o ./bin/main.exe main.c $(FILES) $(UNICORN) $(CAPSTONE) \
		-lpthread -lm -lws2_32 -lmingw32  -L$(SDL2)/lib/ -lSDL2main -lSDL2

.PHONY: clean
clean:
	-rm *.o



