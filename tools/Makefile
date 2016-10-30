CC = clang
OBJ = modexp2pubkey.o
LIBS = -lssl -lcrypto

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

modexp2pubkey: $(OBJ)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f *.o
