SRCs = $(wildcard *.c)
OBJs = $(SRCs:%.c=%.o)
BPFCODEs = $(OBJs:%.o=%)

CFLAGs = -target bpf
CFLAGs += -Wall -g -c
CFLAGs += -O2

$(OBJs): %.o: %.c
	$(CLANG) $(CFLAGs) -o $@ $<

test: $(OBJs)
	@for code in $(BPFCODEs); do \
		echo "Loading $$code.o..."; \
		sudo bpftool prog load "$$code.o" "/sys/fs/bpf/$$code"; \
		echo "Currently pinned programs:"; \
		sudo bpftool prog show pinned /sys/fs/bpf/$$code; \
		echo "Running $$code..."; \
		sudo bpftool prog run pinned "/sys/fs/bpf/$$code" repeat 0; \
	done
	@echo "Kernel trace output:"
	@sudo cat /sys/kernel/debug/tracing/trace

.PHONY: test