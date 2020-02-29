
# -Wl,-subsystem,windows gets rid of the console window
# gcc  -o main.exe main.c -lmingw32 -Wl,-subsystem,windows -L./lib -lSDL2main -lSDL2

ifeq ($(OS),Windows_NT)
win32:
	gcc -Wall -Wno-pointer-to-int-cast -m32 -o $@ main.c \
		-L../ -lvmrp \
		../../windows/unicorn-1.0.1-win32/unicorn.a -lpthread -lm -lz \
		-lmingw32  -L../lib/SDL2-2.0.10/i686-w64-mingw32/lib/ -lSDL2main -lSDL2
	cp ../lib/SDL2-2.0.10/i686-w64-mingw32/bin/SDL2.dll ./

win32_debug:
	gcc -Wall -Wno-pointer-to-int-cast -m32 -o $@ main.c \
		-L../ -lvmrp \
		../../windows/unicorn-1.0.1-win32/unicorn.a -lpthread -lm -lz \
		../../windows/capstone-4.0.1-win32/capstone.dll \
		-lmingw32  -L../lib/SDL2-2.0.10/i686-w64-mingw32/lib/ -lSDL2main -lSDL2
	cp ../lib/SDL2-2.0.10/i686-w64-mingw32/bin/SDL2.dll ./
	cp ../../windows/capstone-4.0.1-win32/capstone.dll ./

win64:
	gcc -Wall -Wno-pointer-to-int-cast -o main_win64.exe main.c \
		-L../ -lvmrp \
		../../windows/unicorn-1.0.1-win64/unicorn.a -lpthread -lm -lz \
		-lmingw32  -L../lib/SDL2-2.0.10/x86_64-w64-mingw32/lib/ -lSDL2main -lSDL2
	cp ../lib/SDL2-2.0.10/x86_64-w64-mingw32/bin/SDL2.dll ./SDL2.dll

.PHONY: clean
clean:
	-rm ./*.exe ./SDL2.dll ./capstone.dll
else

main:
	gcc -Wall -Wno-pointer-to-int-cast -o main main.c \
		-L../ -lvmrp \
		-lunicorn -lpthread -lm -lz \
		-lSDL2

endif

