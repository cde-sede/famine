#include <stdint.h>

#include "cipher.h"

#if !defined(__x86_64__)
# error "random.c: raw getrandom syscall only implemented for x86_64"
#endif

#define SYS_GETRANDOM	318
#define ERR_EINTR		4

static long	sys_getrandom(void *buf, size_t size, unsigned flags) {
	long	ret;

	__asm__ volatile ("syscall"
		: "=a"(ret)
		: "a"((long)SYS_GETRANDOM), "D"(buf), "S"(size), "d"((long)flags)
		: "rcx", "r11", "memory");
	return ret;
}

int	random_bytes(uint8_t *dst, size_t size) {
	while (size > 0) {
		long	r = sys_getrandom(dst, size, 0);

		if (r == -ERR_EINTR)
			continue;
		if (r <= 0)
			return -1;
		dst += r;
		size -= (size_t)r;
	}
	return 0;
}
