#include <stdint.h>

#include "cipher.h"

/* zero padding: decrypt cannot strip it, output keeps the trailing zeros */
void	ecb_encrypt(const crypt_params_t *params) {
	const block_cipher_t	*c = params->params.block_params.cipher;
	size_t					bs = c->params.block_size;
	size_t					out;

	if (params->size > SIZE_MAX - bs) {
		crypt_result(params, 0, -1);
		return;
	}
	out = (params->size + bs - 1) / bs * bs;
	if (out > params->dst_cap) {
		crypt_result(params, 0, -1);
		return;
	}
	for (size_t off = 0; off < params->size; off += bs) {
		uint8_t	buf[CIPHER_MAX_BLOCK];

		for (size_t i = 0; i < bs; ++i)
			buf[i] = off + i < params->size ? params->src[off + i] : 0;
		c->encrypt_block(c, params->dst + off, buf);
	}
	crypt_result(params, out, 0);
}

void	ecb_decrypt(const crypt_params_t *params) {
	const block_cipher_t	*c = params->params.block_params.cipher;
	size_t					bs = c->params.block_size;

	if (params->size % bs != 0 || params->size > params->dst_cap) {
		crypt_result(params, 0, -1);
		return;
	}
	for (size_t off = 0; off < params->size; off += bs)
		c->decrypt_block(c, params->dst + off, params->src + off);
	crypt_result(params, params->size, 0);
}
