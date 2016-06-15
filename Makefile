CC  :=   gcc
CFLAGS  =   -Wall -Wextra -Wpedantic -O3
TARGET = wol

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(TARGET).c

clean:
	$(RM) $(TARGET)