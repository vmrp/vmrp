CC := gcc
AR := ar
# CFLAGS := -g -Wall -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast
CFLAGS := -g -Wall -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast -DDEBUG

OBJS = dsm.o engine.o fileLib.o font16_st.o gb2unicode.o vmrp.o tsf_font.o utils.o debug.o \
	rbtree.o bridge.o memory.o baseLib_cfunction.ext.o

UNICORN = -lunicorn
CAPSTONE = -lcapstone
ifeq ($(OS),Windows_NT)
	UNICORN = ./windows/unicorn-1.0.1-win64/unicorn.a
	UNICORN32 = ./windows/unicorn-1.0.1-win32/unicorn.a
	CAPSTONE = ./windows/capstone-4.0.1-win32/capstone.dll
endif

main: $(OBJS)
	$(CC) $(CFLAGS) -m32 $^ main.c -o $@ $(UNICORN32) -lz -lpthread -lm # build 32bit version

main_debug: $(OBJS)
	$(CC) $(CFLAGS) -m32 $^ main.c -o $@ $(UNICORN32) $(CAPSTONE) -lz -lpthread -lm # build 32bit version
	cp $(CAPSTONE) ./ # debug need capstone.dll

lib: $(OBJS)
	$(AR) crv ./GUI/libvmrp.a $^

%.o:%.c
	$(CC) $(CFLAGS) -m32 -c $^ # build 32bit version
	# $(CC) $(CFLAGS) -c $^

.PHONY: clean
clean:
	-rm $(OBJS) main.o main *.exe