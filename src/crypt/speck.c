#include <stdint.h>

#include "cipher.h"

/*
*	SPECK-64/128 (Beaulieu et al., 2013)
*
*	block = (x, y), two 32-bit words, x is the high half
*	bytes are little endian: y = src[0..3], x = src[4..7]
*
*	round(x, y, k)
*		x = (rotr(x, 8) + y) ^ k
*		y = rotl(y, 3) ^ x
*
*	key schedule, key = (l2, l1, l0, k0), k0 = key[0..3]
*		rk[0] = k0
*		for i in 0 .. rounds - 2
*			l[i + 3]  = (rk[i] + rotr(l[i], 8)) ^ i
*			rk[i + 1] = rotl(rk[i], 3) ^ l[i + 3]
*	l[i + 3] only depends on l[i], so l is kept as a 3-word ring
*/

static uint32_t	rotl32(uint32_t x, unsigned n) {
	return (x << n) | (x >> (32 - n));
}

static uint32_t	rotr32(uint32_t x, unsigned n) {
	return (x >> n) | (x << (32 - n));
}

static uint32_t	load32(const uint8_t *src) {
	return (uint32_t)src[0] | (uint32_t)src[1] << 8
		| (uint32_t)src[2] << 16 | (uint32_t)src[3] << 24;
}

static void	store32(uint8_t *dst, uint32_t v) {
	dst[0] = (uint8_t)v;
	dst[1] = (uint8_t)(v >> 8);
	dst[2] = (uint8_t)(v >> 16);
	dst[3] = (uint8_t)(v >> 24);
}

static int	speck_setup(block_cipher_t *c, const uint8_t *key) {
	speck_ctx_t	*ctx = &c->ctx.speck;
	uint32_t	l[3];
	uint32_t	k = load32(key);

	l[0] = load32(key + 4);
	l[1] = load32(key + 8);
	l[2] = load32(key + 12);
	ctx->rk[0] = k;
	for (uint32_t i = 0; i < (uint32_t)c->params.rounds - 1; ++i) {
		l[i % 3] = (k + rotr32(l[i % 3], 8)) ^ i;
		k = rotl32(k, 3) ^ l[i % 3];
		ctx->rk[i + 1] = k;
	}
	return 0;
}

static void	speck_encrypt_block(const block_cipher_t *c, uint8_t *dst,
	const uint8_t *src) {
	const uint32_t	*rk = c->ctx.speck.rk;
	uint32_t		x = load32(src + 4);
	uint32_t		y = load32(src);

	for (int i = 0; i < c->params.rounds; ++i) {
		x = (rotr32(x, 8) + y) ^ rk[i];
		y = rotl32(y, 3) ^ x;
	}
	store32(dst, y);
	store32(dst + 4, x);
}

static void	speck_decrypt_block(const block_cipher_t *c, uint8_t *dst,
	const uint8_t *src) {
	const uint32_t	*rk = c->ctx.speck.rk;
	uint32_t		x = load32(src + 4);
	uint32_t		y = load32(src);

	for (int i = c->params.rounds - 1; i >= 0; --i) {
		y = rotr32(y ^ x, 3);
		x = rotl32((x ^ rk[i]) - y, 8);
	}
	store32(dst, y);
	store32(dst + 4, x);
}

int	speck_init(block_cipher_t *c) {
	if (c->params.block_size != SPECK_BLOCK_SIZE
		|| c->params.key_size != SPECK_KEY_SIZE
		|| c->params.rounds > SPECK_MAX_ROUNDS)
		return -1;
	c->setup = speck_setup;
	c->encrypt_block = speck_encrypt_block;
	c->decrypt_block = speck_decrypt_block;
	return 0;
}
