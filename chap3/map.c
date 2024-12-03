#include <sys/syscall.h>

#include <linux/bpf.h>
#include <linux/types.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

// union bpf_attr attr = {
//     .map_type = BPF_MAP_TYPE_HASH,
//     .key_size = sizeof(int),
//     .value_size = sizeof(int),
//     .max_entries = 100,
//     .map_flags = BPF_F_NO_PREALLOC,
// };

// 
// struct {
//   __uint(type, BPF_MAP_TYPE_HASH);
//   __type(key, int);
//   __type(value, int);
//   __uint(max_entries, 100);
//   __uint(map_flags, BPF_F_NO_PREALLOC);
// }icmpcnt SEC(".maps");

static struct bpf_map_create_opts map_opts = { .sz = sizeof(map_opts), .map_flags = BPF_F_NO_PREALLOC };

// static int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
//   return syscall(SYS_bpf, cmd, attr, size);
// }


int main() {
  long long key, next_key, first_key, value;
  int fd = bpf_map_create(BPF_MAP_TYPE_HASH,NULL, sizeof(key), sizeof(value), 2, &map_opts);
  if (fd < 0) {
    printf("Failed to create BPF map: %s\n", strerror(errno));
    return 1;
  }

  key = 1;
  value = 42;
  assert(bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0);

  value = 0;
  assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) < 0 && 
         errno == EEXIST);
  
  assert(bpf_map_update_elem(fd, &key, &value, -1) < 0 &&
         errno == EINVAL);

  assert(bpf_map_lookup_elem(fd, &key, &value) == 0 && value == 42);

  key = 2;
  value = 43;
  assert(bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0);

  	/* Check that key=2 matches the value and delete it */
	assert(bpf_map_lookup_and_delete_elem(fd, &key, &value) == 0 && value == 43);

	/* Check that key=2 is not found. */
	assert(bpf_map_lookup_elem(fd, &key, &value) < 0 && errno == ENOENT);

	/* BPF_EXIST means update existing element. */
	assert(bpf_map_update_elem(fd, &key, &value, BPF_EXIST) < 0 &&
	       /* key=2 is not there. */
	       errno == ENOENT);

	/* Insert key=2 element. */
	assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) == 0);

	/* key=1 and key=2 were inserted, check that key=0 cannot be
	 * inserted due to max_entries limit.
	 */
	key = 0;
	assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) < 0 &&
	       errno == E2BIG);

	/* Update existing element, though the map is full. */
	key = 1;
	assert(bpf_map_update_elem(fd, &key, &value, BPF_EXIST) == 0);
	key = 2;
	assert(bpf_map_update_elem(fd, &key, &value, BPF_ANY) == 0);
	key = 3;
	assert(bpf_map_update_elem(fd, &key, &value, BPF_NOEXIST) < 0 &&
	       errno == E2BIG);

	/* Check that key = 0 doesn't exist. */
	key = 0;
	assert(bpf_map_delete_elem(fd, &key) < 0 && errno == ENOENT);

	/* Iterate over two elements. */
	assert(bpf_map_get_next_key(fd, NULL, &first_key) == 0 &&
	       (first_key == 1 || first_key == 2));
	assert(bpf_map_get_next_key(fd, &key, &next_key) == 0 &&
	       (next_key == first_key));
	assert(bpf_map_get_next_key(fd, &next_key, &next_key) == 0 &&
	       (next_key == 1 || next_key == 2) &&
	       (next_key != first_key));
	assert(bpf_map_get_next_key(fd, &next_key, &next_key) < 0 &&
	       errno == ENOENT);

	/* Delete both elements. */
	key = 1;
	assert(bpf_map_delete_elem(fd, &key) == 0);
	key = 2;
	assert(bpf_map_delete_elem(fd, &key) == 0);
	assert(bpf_map_delete_elem(fd, &key) < 0 && errno == ENOENT);

	key = 0;
	/* Check that map is empty. */
	assert(bpf_map_get_next_key(fd, NULL, &next_key) < 0 &&
	       errno == ENOENT);
	assert(bpf_map_get_next_key(fd, &key, &next_key) < 0 &&
	       errno == ENOENT);

	close(fd);
  return 0;
}
