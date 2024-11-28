/*
 * Copyright (c) 2024, TSC-VEE Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>
#include <stddef.h>

/* 'Words' here refers to uint64_t */
#define SHA3_KECCAK_SPONGE_WORDS \
	(((1600)/8/*bits to byte*/)/sizeof(uint64_t))
typedef struct sha3_context_ {
    uint64_t saved;             /* the portion of the input message that we
                                 * didn't consume yet */
    union {                     /* Keccak's state */
        uint64_t s[SHA3_KECCAK_SPONGE_WORDS];
        uint8_t sb[SHA3_KECCAK_SPONGE_WORDS * 8];
    } u;
    unsigned byteIndex;         /* 0..7--the next byte after the set one
                                 * (starts from 0; 0--none are buffered) */
    unsigned wordIndex;         /* 0..24--the next word to integrate input
                                 * (starts from 0) */
    unsigned capacityWords;     /* the double size of the hash output in
                                 * words (e.g. 16 for Keccak 512) */
} sha3_context;

enum SHA3_FLAGS {
    SHA3_FLAGS_NONE=0,
    SHA3_FLAGS_KECCAK=1
};

enum SHA3_RETURN {
    SHA3_RETURN_OK=0,
    SHA3_RETURN_BAD_PARAMS=1
};
typedef enum SHA3_RETURN sha3_return_t;

/* For Init or Reset call these: */
sha3_return_t sha3_Init(void *priv, unsigned bitSize);

void sha3_Init256(void *priv);
void sha3_Init384(void *priv);
void sha3_Init512(void *priv);

enum SHA3_FLAGS sha3_SetFlags(void *priv, enum SHA3_FLAGS);

void sha3_Update(void *priv, void const *bufIn, size_t len);

void const *sha3_Finalize(void *priv);

/* Single-call hashing */
sha3_return_t sha3_HashBuffer( 
    unsigned bitSize,   /* 256, 384, 512 */
    enum SHA3_FLAGS flags, /* SHA3_FLAGS_NONE or SHA3_FLAGS_KECCAK */
    const void *in, unsigned inBytes, 
    void *out, unsigned outBytes );     /* up to bitSize/8; truncation OK */

#endif