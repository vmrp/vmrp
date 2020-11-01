


armcc -I. -c -O2 -Otime -cpu ARM7EJ-S -littleend -apcs /ropi/rwpi/interwork -fa -zo -o tmp/main.o src/main.c

armcc -I. -c -O2 -Otime -cpu ARM7EJ-S -littleend -apcs /ropi/rwpi/interwork -fa -zo -o tmp/r9.o src/r9.c

armcc -I. -c -O2 -Otime -cpu ARM7EJ-S -littleend -apcs /interwork -fa -zo -o tmp/lib.o src/lib.c

armlink -rwpi -ro-base 0x80000 -remove -first mr_c_function_load -entry mr_c_function_load -map -info sizes,totals,veneers -xref -symbols -list tmp/cfunction.txt -o tmp/cfunction.elf tmp/main.o tmp/r9.o tmp/lib.o

pause