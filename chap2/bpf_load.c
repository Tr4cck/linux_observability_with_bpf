#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

// 定义 bpf() 系统调用宏
#ifndef BPF_PROG_LOAD
#define BPF_PROG_LOAD 5
#endif

// 日志缓冲区大小
#define LOG_BUF_SIZE 65536
char bpf_log_buf[LOG_BUF_SIZE];

// 简单的 BPF 程序：一个空的 BPF 指令集
struct bpf_insn prog[] = {
    {.code = BPF_ALU64 | BPF_MOV | BPF_K,
     .dst_reg = BPF_REG_0,
     .src_reg = 0,
     .off = 0,
     .imm = 0}, // R0 = 0
    {.code = BPF_EXIT,
     .dst_reg = 0,
     .src_reg = 0,
     .off = 0,
     .imm = 0}, // return 0
};

// 调用 bpf() 系统调用
static int bpf(int cmd, union bpf_attr *attr, unsigned int size) {
  return syscall(SYS_bpf, cmd, attr, size);
}

int main() {
  // 设置 bpf_attr
  union bpf_attr attr;
  memset(&attr, 0, sizeof(attr));
  attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;          // 指定程序类型
  attr.insns = (uint64_t)prog;                            // 指向指令集
  attr.insn_cnt = sizeof(prog) / sizeof(struct bpf_insn); // 指令数量
  attr.license = (uint64_t) "GPL";                        // BPF 程序许可证
  attr.log_buf = (uint64_t)bpf_log_buf; // 设置日志缓冲区
  attr.log_size = LOG_BUF_SIZE;         // 缓冲区大小
  attr.log_level = 3;                   // 日志级别（输出详细信息）

  for (int i = 0; i < sizeof(prog) / sizeof(struct bpf_insn); i++) {
    printf("Insn %d: code=0x%x, dst_reg=%d, src_reg=%d, off=%d, imm=%d\n", i,
           prog[i].code, prog[i].dst_reg, prog[i].src_reg, prog[i].off,
           prog[i].imm);
  }

  // 调用 BPF_PROG_LOAD 加载程序
  int prog_fd = bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
  printf("Verifier log:\n%s\n", bpf_log_buf); // 打印验证器输出

  if (prog_fd < 0) {
    perror("bpf(BPF_PROG_LOAD)");
    return 1;
  }

  printf("BPF program loaded successfully, fd: %d\n", prog_fd);
  return 0;
}