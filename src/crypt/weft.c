#include <stdint.h>

#include "spn.h"

/*
*	WEFT: 128-bit block, 128-bit key Feistel network on two 64-bit halves
*
*	encrypt
*		(L, R) = block[0..7], block[8..15]
*		for i in 0 .. R - 1
*			(L, R) = (R, L ^ F(R ^ k[i]))
*		(L, R) ^= (k[R], k[R + 1])
*
*	F(t) = G(S(t)), G(t) = t ^ rotl(t, 5) ^ rotl(t, 17)
*		S is the shared nibble S-box of spn.h (bitsliced), G a 3-term
*		rotation layer: nibble branch number 4 (the max for 3 terms), full
*		nibble diffusion in 3 applications (tools/design_search weft).
*		G is invertible (odd term count), so F is a permutation and a
*		nonzero difference into F always comes out nonzero.
*
*	key schedule and ctx: the on-the-fly schedule of spn.h, k[R], k[R + 1]
*	are the stored end state, which is exactly the decryption whitening.
*
*	decrypt
*		(L, R) ^= (k[R], k[R + 1])
*		for i in R - 1 .. 0
*			(L, R) = (R ^ F(L ^ k[i]), L)
*/

SPN_INLINE uint64_t	weft_f(uint64_t t) {
	return weft_g(spn_sub(t, SPN_ANF));
}

static void	weft_encrypt_block(const block_cipher_t *c, uint8_t *dst,
	const uint8_t *src) {
	uint64_t	l = spn_load(src);
	uint64_t	r = spn_load(src + 8);
	uint64_t	a = c->ctx.spn.start[0];
	uint64_t	b = c->ctx.spn.start[1];

	for (int i = 0; i < c->params.rounds; ++i) {
		uint64_t	next = a ^ spn_ks_f(b) ^ spn_rc(i);
		uint64_t	t = l ^ weft_f(r ^ a);

		l = r;
		r = t;
		a = b;
		b = next;
	}
	spn_store(dst, l ^ a);
	spn_store(dst + 8, r ^ b);
}

static void	weft_decrypt_block(const block_cipher_t *c, uint8_t *dst,
	const uint8_t *src) {
	uint64_t	a = c->ctx.spn.end[0];
	uint64_t	b = c->ctx.spn.end[1];
	uint64_t	l = spn_load(src) ^ a;
	uint64_t	r = spn_load(src + 8) ^ b;

	for (int i = c->params.rounds - 1; i >= 0; --i) {
		uint64_t	prev = b ^ spn_ks_f(a) ^ spn_rc(i);
		uint64_t	t = r ^ weft_f(l ^ prev);

		b = a;
		a = prev;
		r = l;
		l = t;
	}
	spn_store(dst, l);
	spn_store(dst + 8, r);
}

int	weft_init(block_cipher_t *c) {
	if (c->params.block_size != WEFT_BLOCK_SIZE
		|| c->params.key_size != WEFT_KEY_SIZE
		|| c->params.rounds > WEFT_MAX_ROUNDS)
		return -1;
	c->setup = spn_setup;
	c->encrypt_block = weft_encrypt_block;
	c->decrypt_block = weft_decrypt_block;
	return 0;
}
