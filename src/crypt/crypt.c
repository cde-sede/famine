#include <stdint.h>

#include "cipher.h"

/* worst case is RIPPLE: 2 IV blocks + 1 full padding block (SEAL: 2 blocks) */
size_t	crypt_max_size(size_t size) {
	return size + 3 * CIPHER_MAX_BLOCK;
}

const char	*algo_name(algo_t algo) {
	switch (algo) {
		case XOR:
			return "xor";
		case ECB:
			return "ecb";
		case RIPPLE:
			return "ripple";
		case CTR:
			return "ctr";
		case SEAL:
			return "seal";
		default:
			return "?";
	}
}

t_encrypt_func	get_encrypt_func(algo_t algo) {
	switch (algo) {
		case XOR:
			return xor_encrypt;
		case ECB:
			return ecb_encrypt;
		case RIPPLE:
			return ripple_encrypt;
		case CTR:
			return ctr_encrypt;
		case SEAL:
			return seal_encrypt;
		default:
			return NULL;
	}
}

t_encrypt_func	get_decrypt_func(algo_t algo) {
	switch (algo) {
		case XOR:
			return xor_encrypt;
		case ECB:
			return ecb_decrypt;
		case RIPPLE:
			return ripple_decrypt;
		case CTR:
			return ctr_decrypt;
		case SEAL:
			return seal_decrypt;
		default:
			return NULL;
	}
}
