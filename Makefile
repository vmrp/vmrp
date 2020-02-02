CC := gcc
CFLAGS := -g -Wall -Wno-int-to-pointer-cast -Wno-pointer-to-int-cast 

OBJS = dsm.o engine.o fileLib.o font16_st.o gb2unicode.o main.o tsf_font.o utils.o debug.o \
	rbtree.o bridge.o memory.o

UNICORN = -lunicorn
ifeq ($(OS),Windows_NT)
	UNICORN = ./windows/unicorn.a
endif

main: $(OBJS)
	$(CC) $^ -o $@ $(UNICORN) -lz -lpthread -lm

%.o:%.c
	$(CC) $(CFLAGS) -c $^

.PHONY: clean
clean:
	-rm $(OBJS) main *.exe