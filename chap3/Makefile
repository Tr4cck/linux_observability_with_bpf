CC = gcc
CFLAGS = -g -O2 -Wall -I/usr/include
LDFLAGS = -lbpf -lz

SRC = $(wildcard *.c)
TARGET = $(SRC:%.c=%)

# 构建规则
all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# 清理规则
clean:
	rm -f $(TARGET)
