#include <stdint.h>

#include "spn.h"

/* TWILL: nibble SPN with a rotation-XOR linear layer, see spn.h */

static void	twill_encrypt_block(const block_cipher_t *c, uint8_t *dst,
	const uint8_t *src) {
	spn_store(dst, spn_encrypt(c, spn_load(src), twill_linear));
}

static void	twill_decrypt_block(const block_cipher_t *c, uint8_t *dst,
	const uint8_t *src) {
	spn_store(dst, spn_decrypt(c, spn_load(src), twill_linear_inv));
}

int	twill_init(block_cipher_t *c) {
	if (spn_check_params(c) != 0)
		return -1;
	c->setup = spn_setup;
	c->encrypt_block = twill_encrypt_block;
	c->decrypt_block = twill_decrypt_block;
	return 0;
}
