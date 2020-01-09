OPENSSL_DIR=/usr

CC=cc

OPENSSL_INCLUDE_DIR=$(OPENSSL_DIR)/include
OPENSSL_LIB_DIR=$(OPENSSL_DIR)/lib

CFLAGS=-O3 -mavx2 -I$(OPENSSL_INCLUDE_DIR)
LDFLAGS=-L$(OPENSSL_LIB_DIR) -lcrypto -lssl


all:

	$(CC) $(CFLAGS) -c -g rng.c encrypt.c mat_mul.c aes/aes.c aes/aes_c.c
	$(CC) $(CFLAGS) -o EMBLEM rng.o encrypt.o mat_mul.o aes/aes.o aes/aes_c.o $(LDFLAGS)
