CC := gcc

CFLAGS := -Wall -fPIC -g
LDFLAGS := -shared -ldl -lpthread

TARGET = nvmed_wrapper.so
SOURCES = nvmed_wrapper.c nvmed_wrapper_io.c

OBJECTS = $(SOURCES:.c=.o)

default: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $(TARGET) $(LDFLAGS) 

clean:
	rm -f $(TARGET) *.o

.PHONY: default clean 
