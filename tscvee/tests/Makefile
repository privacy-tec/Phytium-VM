CC = gcc
CFLAGS = -Wall -Wextra -I../include
LDFLAGS = -lsodium

TEST_SRC = local_crypto_test.c ../host/cJSON.c
TEST_BIN = local_crypto_test

.PHONY: all clean test

all: $(TEST_BIN)

$(TEST_BIN): $(TEST_SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

test: $(TEST_BIN)
	./$(TEST_BIN) ../args/transferFrom.json

clean:
	rm -f $(TEST_BIN)