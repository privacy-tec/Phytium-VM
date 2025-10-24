/*
 * Local test for TSC-VEE bytecode encryption/decryption without actual TEE.
 * This test simulates the complete flow of encryption, chunked transfer,
 * and decryption to validate the crypto implementation.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "../host/cJSON.h"
#include "../include/tsc_privkey.h"

/* Maximum chunk size for simulated transfer */
#define MAX_CHUNK_SIZE 8192

/* 
 * Copied from host/main.c - encrypt plaintext using AES-256-GCM.
 * Returns 0 on success, -1 on failure. *out_buf is malloc'd on success.
 */
static int libsodium_aes_gcm_encrypt(const unsigned char *plaintext, size_t plaintext_len,
                                     const unsigned char *key32, unsigned char **out_buf, size_t *out_len)
{
    const size_t nonce_len = crypto_aead_aes256gcm_NPUBBYTES; /* 12 */
    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES];
    randombytes_buf(nonce, nonce_len);

    unsigned long long clen = 0;
    size_t ciphertext_len = plaintext_len + crypto_aead_aes256gcm_ABYTES; /* tag appended */

    unsigned char *ciphertext = malloc(ciphertext_len);
    if (!ciphertext) return -1;

    if (crypto_aead_aes256gcm_is_available()) {
        if (crypto_aead_aes256gcm_encrypt(ciphertext, &clen,
                                          plaintext, (unsigned long long)plaintext_len,
                                          NULL, 0, /* additional data */
                                          NULL,
                                          nonce, key32) != 0) {
            free(ciphertext);
            return -1;
        }
    } else {
        /* AES-GCM not available in this build of libsodium */
        free(ciphertext);
        return -1;
    }

    size_t total = nonce_len + (size_t)clen;
    unsigned char *buf = malloc(total);
    if (!buf) {
        free(ciphertext);
        return -1;
    }
    memcpy(buf, nonce, nonce_len);
    memcpy(buf + nonce_len, ciphertext, (size_t)clen);

    free(ciphertext);

    *out_buf = (unsigned char *)buf;
    *out_len = total;
    return 0;
}

/* Simulated chunked transfer of data */
static int transfer_in_chunks(const unsigned char *data, size_t data_len,
                             unsigned char **out_buf, size_t *out_len)
{
    *out_buf = malloc(data_len);
    if (!*out_buf) return -1;
    *out_len = data_len;

    size_t offset = 0;
    while (offset < data_len) {
        size_t chunk_size = (data_len - offset > MAX_CHUNK_SIZE) ?
                            MAX_CHUNK_SIZE : (data_len - offset);

        printf("Transferring chunk: offset=%zu, size=%zu\n",
               offset, chunk_size);

        /* In real code this would invoke TEEC commands; here we just copy */
        memcpy(*out_buf + offset, data + offset, chunk_size);
        offset += chunk_size;
    }

    return 0;
}

/* Decrypt a complete encrypted blob (host-side test version) */
static int decrypt_complete_blob(const unsigned char *encrypted, size_t encrypted_len,
                                const unsigned char *key32,
                                unsigned char **out_buf, size_t *out_len)
{
    if (encrypted_len < crypto_aead_aes256gcm_NPUBBYTES) {
        return -1;  /* too short for nonce */
    }

    const unsigned char *nonce = encrypted;
    const unsigned char *cipher = encrypted + crypto_aead_aes256gcm_NPUBBYTES;
    size_t cipher_len = encrypted_len - crypto_aead_aes256gcm_NPUBBYTES;

    /* Upper bound for plaintext */
    unsigned char *plaintext = malloc(cipher_len);
    if (!plaintext) return -1;

    unsigned long long mlen = 0;
    if (crypto_aead_aes256gcm_decrypt(plaintext, &mlen,
                                      NULL,
                                      cipher, (unsigned long long)cipher_len,
                                      NULL, 0,
                                      nonce, key32) != 0) {
        free(plaintext);
        return -1;
    }

    *out_buf = plaintext;
    *out_len = (size_t)mlen;
    return 0;
}

int main(int argc, char *argv[])
{
    if (argc != 2) {
        printf("Usage: %s <json_file_path>\n", argv[0]);
        printf("Example: %s ../args/transferFrom.json\n", argv[0]);
        return 1;
    }

    if (sodium_init() < 0) {
        printf("libsodium initialization failed\n");
        return 1;
    }

    /* Read and parse JSON input (similar to host's main.c) */
    FILE *fp = fopen(argv[1], "r");
    if (!fp) {
        printf("Failed to open %s\n", argv[1]);
        return 1;
    }

    fseek(fp, 0L, SEEK_END);
    long flen = ftell(fp);
    char *json_str = malloc(flen + 1);
    if (!json_str) {
        fclose(fp);
        printf("Failed to allocate JSON buffer\n");
        return 1;
    }

    fseek(fp, 0L, SEEK_SET);
    fread(json_str, flen, 1, fp);
    json_str[flen] = 0;
    fclose(fp);

    cJSON *root = cJSON_Parse(json_str);
    if (!root) {
        printf("Failed to parse JSON\n");
        free(json_str);
        return 1;
    }

    cJSON *bytecode = cJSON_GetObjectItem(root, "bytecode");
    if (!bytecode || !bytecode->valuestring) {
        printf("No bytecode field in JSON\n");
        cJSON_Delete(root);
        free(json_str);
        return 1;
    }

    printf("\n=== Original bytecode ===\n%s\n", bytecode->valuestring);
    size_t bytecode_len = strlen(bytecode->valuestring);

    /* Derive encryption key from private key */
    unsigned char key32[32];
    const char *privkey = TSC_PRIVKEY;  /* Use the same compile-time key */
    size_t privkey_len = strlen(privkey);
    crypto_generichash(key32, sizeof(key32),
                       (const unsigned char*)privkey,
                       (unsigned long long)privkey_len,
                       NULL, 0);

    /* Phase 1: Encrypt the bytecode */
    unsigned char *encrypted = NULL;
    size_t encrypted_len = 0;

    printf("\n=== Encrypting with AES-256-GCM ===\n");
    if (libsodium_aes_gcm_encrypt((const unsigned char*)bytecode->valuestring,
                                  bytecode_len, key32,
                                  &encrypted, &encrypted_len) != 0) {
        printf("Encryption failed\n");
        cJSON_Delete(root);
        free(json_str);
        return 1;
    }
    printf("Encrypted %zu bytes into %zu bytes (including nonce and tag)\n",
           bytecode_len, encrypted_len);

    /* Phase 2: Transfer in chunks (simulate the chunked transfer protocol) */
    unsigned char *received = NULL;
    size_t received_len = 0;

    printf("\n=== Simulating chunked transfer ===\n");
    if (transfer_in_chunks(encrypted, encrypted_len,
                           &received, &received_len) != 0) {
        printf("Chunked transfer simulation failed\n");
        free(encrypted);
        cJSON_Delete(root);
        free(json_str);
        return 1;
    }
    printf("Transferred %zu bytes in chunks\n", received_len);

    /* Phase 3: Decrypt the complete received blob */
    unsigned char *decrypted = NULL;
    size_t decrypted_len = 0;

    printf("\n=== Decrypting received data ===\n");
    if (decrypt_complete_blob(received, received_len,
                             key32, &decrypted, &decrypted_len) != 0) {
        printf("Decryption failed\n");
        free(received);
        free(encrypted);
        cJSON_Delete(root);
        free(json_str);
        return 1;
    }
    printf("Decrypted %zu bytes into %zu bytes\n",
           received_len, decrypted_len);

    /* Verify the decrypted content matches original */
    if (decrypted_len != bytecode_len ||
        memcmp(decrypted, bytecode->valuestring, bytecode_len) != 0) {
        printf("ERROR: Decrypted content does not match original!\n");
        free(decrypted);
        free(received);
        free(encrypted);
        cJSON_Delete(root);
        free(json_str);
        return 1;
    }

    printf("\n=== Test successful! ===\n");
    printf("Original bytecode length: %zu\n", bytecode_len);
    printf("Encrypted blob length: %zu\n", encrypted_len);
    printf("Final decrypted length: %zu\n", decrypted_len);
    printf("Content verified: decrypted matches original\n");

    free(decrypted);
    free(received);
    free(encrypted);
    cJSON_Delete(root);
    free(json_str);

    return 0;
}