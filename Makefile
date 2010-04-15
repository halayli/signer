CFLAGS =  -Wall -lcrypto

CC = gcc

SRC = signer.c signer_common.c
VTSRC = signer_common.c verifier.c verifier_unittest.c
VSRC = signer_common.c verifier.c

signer: $(SRC)
	$(CC) $(CFLAGS) $(SRC) -o $@

verifier_test: $(VTSRC)
	  $(CC) $(CFLAGS) $(VTSRC) -o $@

verifier.o: $(VSRC)
	  $(CC) -c $(VSRC) -o $@
	  ar rcs verifier.a $@

clean:
	rm *.o
