/*
*	bs = cipher block size
*	IV0, IV1 = random, written as a 2 * bs header
*	S[0] = IV0
*	S[1] = IV1
*	for each block i
*		if i is even
*			X = plaintext[i] ^ S[0]
*			C[i] = EncryptBlock(X)
*			S[0] = C[i]
*		if i is odd
*			X = plaintext[i] ^ S[1]
*			C[i] = EncryptBlock(X)
*			S[1] = C[i]
*	last block always carries 1..bs bytes of padding, each equal to the pad length
*
*	output is IV0 | IV1 | C[0] | C[1] | ..., so the chain state of block i
*	(IV or C[i - 2]) always sits exactly 2 * bs bytes before C[i]: no copy kept
* */

#include <stdint.h>

#include "cipher.h"

void	ripple_encrypt(const crypt_params_t *params) {
	const block_cipher_t	*c = params->params.block_params.cipher;
	size_t					bs = c->params.block_size;
	size_t					iv = 2 * bs;
	size_t					padded;
	uint8_t					pad;

	if (params->size > SIZE_MAX - iv - bs) {
		crypt_result(params, 0, -1);
		return;
	}
	padded = (params->size / bs + 1) * bs;
	pad = (uint8_t)(bs - params->size % bs);
	if (iv + padded > params->dst_cap || random_bytes(params->dst, iv) != 0) {
		crypt_result(params, 0, -1);
		return;
	}

	for (size_t off = 0; off < padded; off += bs) {
		uint8_t	buf[CIPHER_MAX_BLOCK];

		for (size_t i = 0; i < bs; ++i)
			buf[i] = (off + i < params->size ? params->src[off + i] : pad)
				^ params->dst[off + i];
		c->encrypt_block(c, params->dst + iv + off, buf);
	}
	crypt_result(params, iv + padded, 0);
}

/*
*	IV0, IV1 = 2 * bs header
*	S[0] = IV0
*	S[1] = IV1
*	for each block i
*		chain = i & 1
*		P[i] = DecryptBlock(C[i]) ^ S[chain]
*		S[chain] = C[i]
*	strip padding from last block
*
*	fails on truncated input or bad padding; dst content is then undefined
* */
void	ripple_decrypt(const crypt_params_t *params) {
	const block_cipher_t	*c = params->params.block_params.cipher;
	size_t					bs = c->params.block_size;
	size_t					iv = 2 * bs;
	size_t					size;
	uint8_t					pad;

	if (params->size < iv + bs
		|| (params->size - iv) % bs != 0
		|| params->size - iv > params->dst_cap) {
		crypt_result(params, 0, -1);
		return;
	}
	size = params->size - iv;

	for (size_t off = 0; off < size; off += bs) {
		c->decrypt_block(c, params->dst + off, params->src + iv + off);
		for (size_t i = 0; i < bs; ++i)
			params->dst[off + i] ^= params->src[off + i];
	}

	pad = params->dst[size - 1];
	if (pad == 0 || pad > bs) {
		crypt_result(params, 0, -1);
		return;
	}
	for (size_t i = size - pad; i < size; i++) {
		if (params->dst[i] != pad) {
			crypt_result(params, 0, -1);
			return;
		}
	}
	crypt_result(params, size - pad, 0);
}
