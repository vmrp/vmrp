CC := gcc
AR := ar
CFLAGS := -g -Wall -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast 

OBJS = dsm.o engine.o fileLib.o font16_st.o gb2unicode.o vmrp.o tsf_font.o utils.o debug.o \
	rbtree.o bridge.o memory.o baseLib_cfunction.ext.o

UNICORN = -lunicorn
ifeq ($(OS),Windows_NT)
	UNICORN = ./windows/unicorn.a
endif

main: $(OBJS)
	$(CC) $^ main.c -o $@ $(UNICORN) -lz -lpthread -lm

lib: $(OBJS)
	$(AR) crv ./gui/libvmrp.a $^

%.o:%.c
	$(CC) $(CFLAGS) -c $^

.PHONY: clean
clean:
	-rm $(OBJS) main.o main *.exe