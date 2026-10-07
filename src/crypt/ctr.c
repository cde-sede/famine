/*
*	CTR
*
*	bs = cipher block size
*	N = random, written as a bs-byte header
*	keystream block i = EncryptBlock(N + i), N a little endian bs-byte integer
*	C = N | P ^ keystream; no padding, output is exactly bs bytes longer
*
*	decryption is the same keystream XOR. No integrity: a flipped ciphertext
*	bit flips the same plaintext bit (see SEAL for the authenticated mode).
*	N is random per message: two messages share keystream only if their
*	counter ranges overlap, birthday bound ~2^(bs * 4) messages.
* */

#include <stdint.h>

#include "cipher.h"

/* dst = src ^ keystream(nonce), dst may equal src */
void	ctr_stream(const block_cipher_t *c, const uint8_t *nonce,
	const uint8_t *src, uint8_t *dst, size_t size) {
	size_t	bs = c->params.block_size;
	uint8_t	ctr[CIPHER_MAX_BLOCK];
	uint8_t	ks[CIPHER_MAX_BLOCK];

	for (size_t i = 0; i < bs; ++i)
		ctr[i] = nonce[i];
	for (size_t off = 0; off < size; off += bs) {
		c->encrypt_block(c, ks, ctr);
		for (size_t i = 0; i < bs && off + i < size; ++i)
			dst[off + i] = src[off + i] ^ ks[i];
		for (size_t i = 0; i < bs && ++ctr[i] == 0; ++i)
			;
	}
}

void	ctr_encrypt(const crypt_params_t *params) {
	const block_cipher_t	*c = params->params.block_params.cipher;
	size_t					bs = c->params.block_size;

	if (params->size > SIZE_MAX - bs || bs + params->size > params->dst_cap
		|| random_bytes(params->dst, bs) != 0) {
		crypt_result(params, 0, -1);
		return;
	}
	ctr_stream(c, params->dst, params->src, params->dst + bs, params->size);
	crypt_result(params, bs + params->size, 0);
}

void	ctr_decrypt(const crypt_params_t *params) {
	const block_cipher_t	*c = params->params.block_params.cipher;
	size_t					bs = c->params.block_size;

	if (params->size < bs || params->size - bs > params->dst_cap) {
		crypt_result(params, 0, -1);
		return;
	}
	ctr_stream(c, params->src, params->src + bs, params->dst, params->size - bs);
	crypt_result(params, params->size - bs, 0);
}
