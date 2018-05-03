CC := gcc
CFLAGS = -g
LDFLAGS = -lpthread -lforestdb -lffs

OBJS = mkfs.o 
SRCS = $(OBJS:.o=.c)

mkfs.ffs: $(OBJS)
	$(CC) $(CLFAGS) $(OBJS) -o mkfs.ffs $(LDFLAGS)

clean:
	rm -f *~ *.o mkfs.ffs
