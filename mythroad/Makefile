

LOCAL_CFLAGS_FULL := -DDSM_FULL -DTARGET_MOD -DMTK_MOD -DMR_VERSION=1968 -DMR_PLAT_DRAWTEXT

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
                  src/mr_noparser.c  \
                  src/lib/mr_auxiliar.c\
                  src/lib/mr_auxlib.c \
                  src/lib/mr_baselib.c\
                  src/lib/mr_iolib_target.c     \
                  src/lib/mr_socket_target.c     \
                  src/lib/mr_strlib.c     \
                  src/lib/mr_tablib.c   \
                  src/lib/mr_tcp_target.c

LOCAL_SRC_FILES_FULL += mythroad.c encode.c     mr_pluto.c	mr_unzip.c	mr_base64.c mr_graphics.c mr_inflate.c \
                    string.c	printf.c	other.c	strtol.c	strtoul.c	dsm.c	fixR9.c	md5.c	mem.c	asm/r9r10.s  asm/globalValue.s

LOCAL_SRC_FILES_FULL += tomr/tomr_to.c tomr/tomr_push.c #tomr/tomr_event.c tomr/tomr_is.c tomr/tomr_map.c  

ifeq ($(LUADEC),1)
LOCAL_SRC_FILES_FULL += luadec/luadec.c luadec/print.c luadec/StringBuffer.c luadec/structs.c luadec/proto.c 
LOCAL_CFLAGS_FULL += -DMRP_OPNAMES -DLUADEC
endif


# node genR9R10.js 1 1
# arm-none-eabi-gcc -s -o vmrp.elf $(LOCAL_CFLAGS_FULL) $(LOCAL_SRC_FILES_FULL) -nostdlib -nostartfiles -pie -fPIC -marm -march=armv5te --entry=dsm_init
.PHONY: vmrp.elf
vmrp.elf:
	arm-none-eabi-gcc -o vmrp.elf $(LOCAL_CFLAGS_FULL) $(LOCAL_SRC_FILES_FULL) -s -O3 -Wall -nostartfiles -pie -fPIC -marm -march=armv5te -mlong-calls -mthumb-interwork --entry=dsm_init


full:
	gcc -o ../vmrp $(LOCAL_CFLAGS_FULL) $(LOCAL_SRC_FILES_FULL) main.c -lSDL2 -lm -lz

#####################################################################

LOCAL_CFLAGS := -g -Wall -DTARGET_MOD -DMTK_MOD -DMR_VERSION=2011 -DMR_PLAT_DRAWTEXT
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
