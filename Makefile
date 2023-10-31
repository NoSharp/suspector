CC = gcc
CC_FLAGS = -O2 -Wall -Wextra


clean:
	del /Q /F /S *.o *.exe

suspector: clean main.o
	$(CC) -o suspector.exe main.o

main.o:
	$(CC) $(CC_FLAGS) -c src/main.c -o main.o
