#ifndef ELFSTATE_H
#define ELFSTATE_H

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

#define ES_MAX_LOAD_SEGMENTS 16
#define ES_MAX_REGIONS	   64

#define ES_REGION_RUNTIME	 0x01u
#define ES_REGION_FILE		0x02u
#define ES_REGION_FILE_BACKED 0x04u
#define ES_REGION_STAGED	  0x08u

struct es_load_segment {
	uintptr_t runtime_start;
	uintptr_t runtime_end;
	Elf64_Addr vaddr;
	Elf64_Off file_offset;
	Elf64_Xword filesz;
	Elf64_Xword memsz;
	Elf64_Word flags;
};

struct es_region {
	uintptr_t runtime_address;
	Elf64_Off file_offset;
	size_t size;
	unsigned flags;
	const void *staged;
};

struct es_image {
	uintptr_t load_bias;
	const Elf64_Phdr *phdr;
	size_t phnum;

	struct es_load_segment load[ES_MAX_LOAD_SEGMENTS];
	size_t load_count;

	struct es_region regions[ES_MAX_REGIONS];
	size_t region_count;
};

int es_init(struct es_image *image);

/*
 * Zero an image without any self-discovery. Use this (instead of es_init)
 * when the image is only a set of file regions to write into some base
 * via es_build_to, e.g. a host tool assembling an output file from a
 * target that is not itself. After reset, register regions and build.
 */
void es_image_reset(struct es_image *image);

int es_runtime_to_file(
	const struct es_image *image,
	uintptr_t address,
	size_t size,
	Elf64_Off *file_offset
);

int es_register_runtime(
	struct es_image *image,
	void *address,
	size_t size,
	struct es_region **out
);

int es_register_file(
	struct es_image *image,
	Elf64_Off offset,
	size_t size,
	struct es_region **out
);

int es_region_read_runtime(
	const struct es_region *region,
	void *dst,
	size_t size
);

/*
 * Give a file region the bytes to write on commit. src must hold
 * region->size bytes and stay valid until es_commit. Runtime regions
 * need no staging: commit writes their live memory.
 */
int es_region_stage(
	struct es_region *region,
	const void *src
);

/*
 * Write a region-patched copy of our own executable to dst_path,
 * atomically (copy /proc/self/exe to a sibling temp, patch the regions,
 * fsync, rename over dst_path). Region offsets are validated against our
 * own file, so the output is same-sized. dst_path may be ourselves
 * (es_commit) or any other path.
 */
int es_commit_to(const struct es_image *image, const char *dst_path);

/*
 * es_commit_to with our own path: overwrite ourselves in place.
 * Takes effect on the next run.
 */
int es_commit(const struct es_image *image);

/*
 * Assemble a new file: copy base_path (NULL = ourselves) to dst_path and
 * write every region at its file_offset. Unlike es_commit_to, regions may
 * extend past the base's size, growing the file, so staged file regions
 * placed at offsets >= base size are appended. This is the primitive for
 * "clone a base image, then tack data onto the end" (e.g. a self-packer:
 * base = ourselves, appended regions = ciphertext + trailer).
 */
int es_build_to(
	const struct es_image *image,
	const char *base_path,
	const char *dst_path
);

/* ---- high-level API ---------------------------------------------------
 *
 * Thin wrappers over the calls above. Typical use:
 *
 *	struct es_image img;
 *	es_open(&img);
 *	es_persist(&img, &g_counter, sizeof g_counter);
 *	g_counter++;
 *	es_sync(&img);
 *
 * es_persist marks a variable's live memory to be saved on sync.
 * es_set stores explicit bytes at that variable's file slot instead.
 */

/* es_init. Returns 0 on success. */
static inline int
es_open(struct es_image *image)
{
	return es_init(image);
}

/*
 * Persist addr's live memory on the next sync. addr must sit in a
 * file-backed load segment (i.e. .data, not .bss). Returns 0/-1.
 */
static inline int
es_persist(struct es_image *image, void *addr, size_t size)
{
	return es_register_runtime(image, addr, size, (struct es_region **)0);
}

/*
 * Persist explicit bytes at addr's file slot (src need not equal addr's
 * live memory, and is read at sync time, so it must stay valid until
 * then). Returns 0/-1.
 */
static inline int
es_set(
	struct es_image *image,
	void *addr,
	const void *src,
	size_t size
)
{
	Elf64_Off offset;
	struct es_region *region;

	if (es_runtime_to_file(image, (uintptr_t)addr, size, &offset) < 0)
		return -1;

	if (es_register_file(image, offset, size, &region) < 0)
		return -1;

	return es_region_stage(region, src);
}

/* es_commit. Writes all persisted state to our file. Returns 0/-1. */
static inline int
es_sync(const struct es_image *image)
{
	return es_commit(image);
}

/* es_commit_to. Writes a patched copy of ourselves to path. Returns 0/-1. */
static inline int
es_sync_to(const struct es_image *image, const char *path)
{
	return es_commit_to(image, path);
}

#endif
