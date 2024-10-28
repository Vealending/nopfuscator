CC=gcc
CFLAGS=-Wall -Wno-main
TARGET=nop
SOURCES=nop.c
OBJECTS=$(SOURCES:.c=.o)
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJECTS)

clean:
	rm -f $(TARGET) $(OBJECTS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

debug:
	gdb $(TARGET)