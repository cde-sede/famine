#include <stdint.h>

#include "cipher.h"

/* repeating-key XOR, its own inverse: also used as the decrypt func */
void	xor_encrypt(const crypt_params_t *params) {
	const xor_params_t *xor_params = &params->params.xor_params;

	if (params->size > params->dst_cap) {
		crypt_result(params, 0, -1);
		return;
	}
	for (size_t i = 0; i < params->size; i++) {
		params->dst[i] = params->src[i] ^ xor_params->key[i % XOR_KEY_SIZE];
	}
	crypt_result(params, params->size, 0);
}
