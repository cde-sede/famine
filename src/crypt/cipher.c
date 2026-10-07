#include <stdint.h>

#include "cipher.h"

/*
*	Dispatch is done with switches, not a static table of function
*	pointers, so no data relocation is needed when running position
*	independent.
*/

const char	*cipher_name(cipher_type_t type) {
	switch (type) {
		case CIPHER_SPECK:
			return "speck";
		case CIPHER_TWILL:
			return "twill";
		case CIPHER_TESSERA:
			return "tessera";
		case CIPHER_WEFT:
			return "weft";
		default:
			return "?";
	}
}

cipher_params_t	cipher_default_params(cipher_type_t type) {
	cipher_params_t	p;

	p.block_size = 0;
	p.key_size = 0;
	p.rounds = 0;
	switch (type) {
		case CIPHER_SPECK:
			p.block_size = SPECK_BLOCK_SIZE;
			p.key_size = SPECK_KEY_SIZE;
			p.rounds = SPECK_ROUNDS;
			break;
		case CIPHER_TWILL:
			p.block_size = SPN_BLOCK_SIZE;
			p.key_size = SPN_KEY_SIZE;
			p.rounds = TWILL_ROUNDS;
			break;
		case CIPHER_TESSERA:
			p.block_size = SPN_BLOCK_SIZE;
			p.key_size = SPN_KEY_SIZE;
			p.rounds = TESSERA_ROUNDS;
			break;
		case CIPHER_WEFT:
			p.block_size = WEFT_BLOCK_SIZE;
			p.key_size = WEFT_KEY_SIZE;
			p.rounds = WEFT_ROUNDS;
			break;
		default:
			break;
	}
	return p;
}

int	cipher_init(block_cipher_t *c, cipher_type_t type,
	const cipher_params_t *params) {
	cipher_params_t	p;

	if ((unsigned)type >= CIPHER_COUNT)
		return -1;
	p = cipher_default_params(type);
	if (params) {
		if (params->block_size)
			p.block_size = params->block_size;
		if (params->key_size)
			p.key_size = params->key_size;
		if (params->rounds)
			p.rounds = params->rounds;
	}
	if (p.block_size == 0 || p.block_size > CIPHER_MAX_BLOCK
		|| p.key_size == 0 || p.rounds <= 0)
		return -1;
	c->type = type;
	c->params = p;
	c->setup = NULL;
	c->encrypt_block = NULL;
	c->decrypt_block = NULL;
	switch (type) {
		case CIPHER_SPECK:
			return speck_init(c);
		case CIPHER_TWILL:
			return twill_init(c);
		case CIPHER_TESSERA:
			return tessera_init(c);
		case CIPHER_WEFT:
			return weft_init(c);
		default:
			return -1;
	}
}
