// SPDX-License-Identifier: GPL-2.0 OR MIT
/*
 * Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved.
 *
 * This is an implementation of the BLAKE2s hash and PRF functions.
 *
 * Information: https://blake2.net/
 *
 */

#include "blake2s.h"

#include <stdint.h>
#include <string.h>
#include <stdbool.h>


#ifndef __BYTE_ORDER__
#include <sys/param.h>
#if !defined(BYTE_ORDER) || !defined(BIG_ENDIAN) || !defined(LITTLE_ENDIAN)
#error "Unable to determine endianness."
#endif
#define __BYTE_ORDER__ BYTE_ORDER
#define __ORDER_BIG_ENDIAN__ BIG_ENDIAN
#define __ORDER_LITTLE_ENDIAN__ LITTLE_ENDIAN
#endif

#ifdef __linux__
#include <linux/types.h>
typedef __u64 u64;
typedef __u32 u32;
typedef __u8 u8;
typedef __s64 s64;
#else
typedef uint64_t u64, __le64;
typedef uint32_t u32, __le32;
typedef uint8_t u8;
typedef int64_t s64;
#endif
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define le32_to_cpus(a) __builtin_bswap32(a)
#define cpu_to_le32s(a) __builtin_bswap32(a)
#else
#define le32_to_cpus(a)
#define cpu_to_le32s(a)
#endif
#ifndef noinline
#define noinline __attribute__((noinline))
#endif
#ifndef __aligned
#define __aligned(x) __attribute__((aligned(x)))
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#endif
#ifndef DIV_ROUND_UP
#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#endif


static inline void le32_to_cpu_array(u32 *buf, unsigned int words)
{
	while (words--) {
		le32_to_cpus(buf);
		buf++;
	}
}

static inline void cpu_to_le32_array(u32 *buf, unsigned int words)
{
	while (words--) {
		cpu_to_le32s(buf);
		buf++;
	}
}

static inline __u32 ror32(__u32 word, unsigned int shift)
{
	return (word >> (shift & 31)) | (word << ((-shift) & 31));
}

static noinline void memzero_explicit(void *s, size_t count)
{
	memset(s, 0, count);
	asm volatile("": :"r"(s) : "memory");
}

static const u32 blake2s_iv[8] = {
	0x6A09E667UL, 0xBB67AE85UL, 0x3C6EF372UL, 0xA54FF53AUL,
	0x510E527FUL, 0x9B05688CUL, 0x1F83D9ABUL, 0x5BE0CD19UL
};

static const u8 blake2s_sigma[10][16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
	{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
	{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
	{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
	{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
	{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
	{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
	{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
	{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

static inline void blake2s_set_lastblock(struct blake2s_state *state)
{
	state->f[0] = -1;
}

static inline void blake2s_increment_counter(struct blake2s_state *state,
					     const u32 inc)
{
	state->t[0] += inc;
	state->t[1] += (state->t[0] < inc);
}

static inline void blake2s_init_param(struct blake2s_state *state,
				      const u32 param)
{
	int i;

	memset(state, 0, sizeof(*state));
	for (i = 0; i < 8; ++i)
		state->h[i] = blake2s_iv[i];
	state->h[0] ^= param;
}

void blake2s_init(struct blake2s_state *state, const size_t outlen)
{
	blake2s_init_param(state, 0x01010000 | outlen);
	state->outlen = outlen;
}

void blake2s_init_key(struct blake2s_state *state, const size_t outlen,
		      const void *key, const size_t keylen)
{
	u8 block[BLAKE2S_BLOCK_SIZE] = { 0 };

	blake2s_init_param(state, 0x01010000 | keylen << 8 | outlen);
	state->outlen = outlen;
	memcpy(block, key, keylen);
	blake2s_update(state, block, BLAKE2S_BLOCK_SIZE);
	memzero_explicit(block, BLAKE2S_BLOCK_SIZE);
}

static inline void blake2s_compress(struct blake2s_state *state,
				    const u8 *block, size_t nblocks,
				    const u32 inc)
{
	u32 m[16];
	u32 v[16];
	int i;

	while (nblocks > 0) {
		blake2s_increment_counter(state, inc);
		memcpy(m, block, BLAKE2S_BLOCK_SIZE);
		le32_to_cpu_array(m, ARRAY_SIZE(m));
		memcpy(v, state->h, 32);
		v[ 8] = blake2s_iv[0];
		v[ 9] = blake2s_iv[1];
		v[10] = blake2s_iv[2];
		v[11] = blake2s_iv[3];
		v[12] = blake2s_iv[4] ^ state->t[0];
		v[13] = blake2s_iv[5] ^ state->t[1];
		v[14] = blake2s_iv[6] ^ state->f[0];
		v[15] = blake2s_iv[7] ^ state->f[1];

#define G(r, i, a, b, c, d) do { \
	a += b + m[blake2s_sigma[r][2 * i + 0]]; \
	d = ror32(d ^ a, 16); \
	c += d; \
	b = ror32(b ^ c, 12); \
	a += b + m[blake2s_sigma[r][2 * i + 1]]; \
	d = ror32(d ^ a, 8); \
	c += d; \
	b = ror32(b ^ c, 7); \
} while (0)

#define ROUND(r) do { \
	G(r, 0, v[0], v[ 4], v[ 8], v[12]); \
	G(r, 1, v[1], v[ 5], v[ 9], v[13]); \
	G(r, 2, v[2], v[ 6], v[10], v[14]); \
	G(r, 3, v[3], v[ 7], v[11], v[15]); \
	G(r, 4, v[0], v[ 5], v[10], v[15]); \
	G(r, 5, v[1], v[ 6], v[11], v[12]); \
	G(r, 6, v[2], v[ 7], v[ 8], v[13]); \
	G(r, 7, v[3], v[ 4], v[ 9], v[14]); \
} while (0)
		ROUND(0);
		ROUND(1);
		ROUND(2);
		ROUND(3);
		ROUND(4);
		ROUND(5);
		ROUND(6);
		ROUND(7);
		ROUND(8);
		ROUND(9);

#undef G
#undef ROUND

		for (i = 0; i < 8; ++i)
			state->h[i] ^= v[i] ^ v[i + 8];

		block += BLAKE2S_BLOCK_SIZE;
		--nblocks;
	}
}

void blake2s_update(struct blake2s_state *state, const u8 *in, size_t inlen)
{
	const size_t fill = BLAKE2S_BLOCK_SIZE - state->buflen;

	if (!inlen)
		return;
	if (inlen > fill) {
		memcpy(state->buf + state->buflen, in, fill);
		blake2s_compress(state, state->buf, 1, BLAKE2S_BLOCK_SIZE);
		state->buflen = 0;
		in += fill;
		inlen -= fill;
	}
	if (inlen > BLAKE2S_BLOCK_SIZE) {
		const size_t nblocks = DIV_ROUND_UP(inlen, BLAKE2S_BLOCK_SIZE);
		/* Hash one less (full) block than strictly possible */
		blake2s_compress(state, in, nblocks - 1, BLAKE2S_BLOCK_SIZE);
		in += BLAKE2S_BLOCK_SIZE * (nblocks - 1);
		inlen -= BLAKE2S_BLOCK_SIZE * (nblocks - 1);
	}
	memcpy(state->buf + state->buflen, in, inlen);
	state->buflen += inlen;
}

void blake2s_final(struct blake2s_state *state, u8 *out)
{
	blake2s_set_lastblock(state);
	memset(state->buf + state->buflen, 0,
	       BLAKE2S_BLOCK_SIZE - state->buflen); /* Padding */
	blake2s_compress(state, state->buf, 1, state->buflen);
	cpu_to_le32_array(state->h, ARRAY_SIZE(state->h));
	memcpy(out, state->h, state->outlen);
	memzero_explicit(state, sizeof(*state));
}

void blake2s_hmac(u8 *out, const u8 *in, const u8 *key, const size_t outlen,
		  const size_t inlen, const size_t keylen)
{
	struct blake2s_state state;
	u8 x_key[BLAKE2S_BLOCK_SIZE] __aligned(__alignof__(u32)) = { 0 };
	u8 i_hash[BLAKE2S_HASH_SIZE] __aligned(__alignof__(u32));
	int i;

	if (keylen > BLAKE2S_BLOCK_SIZE) {
		blake2s_init(&state, BLAKE2S_HASH_SIZE);
		blake2s_update(&state, key, keylen);
		blake2s_final(&state, x_key);
	} else
		memcpy(x_key, key, keylen);

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] ^= 0x36;

	blake2s_init(&state, BLAKE2S_HASH_SIZE);
	blake2s_update(&state, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&state, in, inlen);
	blake2s_final(&state, i_hash);

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] ^= 0x5c ^ 0x36;

	blake2s_init(&state, BLAKE2S_HASH_SIZE);
	blake2s_update(&state, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&state, i_hash, BLAKE2S_HASH_SIZE);
	blake2s_final(&state, i_hash);

	memcpy(out, i_hash, outlen);
	memzero_explicit(x_key, BLAKE2S_BLOCK_SIZE);
	memzero_explicit(i_hash, BLAKE2S_HASH_SIZE);
}
