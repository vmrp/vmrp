
# -Wl,-subsystem,windows gets rid of the console window
# gcc  -o main.exe main.c -lmingw32 -Wl,-subsystem,windows -L./lib -lSDL2main -lSDL2

main_x86_64:
	gcc -Wall -o main_x86_64.exe main.c -lmingw32  -L../lib/SDL2-2.0.10/x86_64-w64-mingw32/lib/ -lSDL2main -lSDL2
	cp ../lib/SDL2-2.0.10/x86_64-w64-mingw32/bin/SDL2.dll ./SDL2.dll

main_i386:
	gcc -Wall -m32 -o main_i386.exe main.c -lmingw32  -L../lib/SDL2-2.0.10/i686-w64-mingw32/lib/ -lSDL2main -lSDL2
	cp ../lib/SDL2-2.0.10/i686-w64-mingw32/bin/SDL2.dll ./SDL2.dll


