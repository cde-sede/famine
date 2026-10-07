#include <stdint.h>

#include "spn.h"

/* TESSERA: nibble SPN with a Latin-square permutation + MDS layer, see spn.h */

static void	tessera_encrypt_block(const block_cipher_t *c, uint8_t *dst,
	const uint8_t *src) {
	spn_store(dst, spn_encrypt(c, spn_load(src), tessera_linear));
}

static void	tessera_decrypt_block(const block_cipher_t *c, uint8_t *dst,
	const uint8_t *src) {
	spn_store(dst, spn_decrypt(c, spn_load(src), tessera_linear_inv));
}

int	tessera_init(block_cipher_t *c) {
	if (spn_check_params(c) != 0)
		return -1;
	c->setup = spn_setup;
	c->encrypt_block = tessera_encrypt_block;
	c->decrypt_block = tessera_decrypt_block;
	return 0;
}
