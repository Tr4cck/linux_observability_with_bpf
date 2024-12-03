#include <linux/bpf.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SEC ("section") __attribute__((section("section")))

union bpf_attr attr = {
    .map_type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(int),
    .value_size = sizeof(int),
    .max_entries = 100,
    .map_flags = BPF_F_NO_PREALLOC,
};

union bpf_map_def SEC

    static int
    bpf(int cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(SYS_bpf, cmd, attr, size);
}

int main() {
  int fd = bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
  if (fd < 0) {
    return 1;
  }

  return 0;
}
