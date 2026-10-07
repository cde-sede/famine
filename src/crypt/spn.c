#include <stdint.h>

#include "spn.h"

/* stores k[0..1], then runs the schedule forward to keep k[R..R+1] */
int	spn_setup(block_cipher_t *c, const uint8_t *key) {
	spn_ctx_t	*ctx = &c->ctx.spn;
	uint64_t	a = spn_load(key);
	uint64_t	b = spn_load(key + 8);

	ctx->start[0] = a;
	ctx->start[1] = b;
	for (int i = 0; i < c->params.rounds; ++i) {
		uint64_t	next = a ^ spn_ks_f(b) ^ spn_rc(i);

		a = b;
		b = next;
	}
	ctx->end[0] = a;
	ctx->end[1] = b;
	return 0;
}

int	spn_check_params(const block_cipher_t *c) {
	if (c->params.block_size != SPN_BLOCK_SIZE
		|| c->params.key_size != SPN_KEY_SIZE
		|| c->params.rounds > SPN_MAX_ROUNDS)
		return -1;
	return 0;
}
