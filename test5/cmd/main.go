package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/iovisor/gobpf/bcc"
)

const source string = `
#include "vmlinux.h"
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") my_map = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(int),
    .value_size = sizeof(unsigned long),
    .max_entries = 128,
};

SEC("prog")
int count_packets(struct __sk_buff *skb) {
    int key = bpf_get_smp_processor_id();
    unsigned long *value;

    value = bpf_map_lookup_elem(&my_map, &key);
    if (!value) {
        unsigned long init_val = 1;
        bpf_map_update_elem(&my_map, &key, &init_val, BPF_ANY);
    } else {
        __sync_fetch_and_add(value, 1);
    }

    return 0;
}

char _license[] SEC("license") = "GPL";
`

func main() {
	m := bcc.NewModule(source, []string{})
	defer m.Close()

	table := bcc.NewTable(m.TableId("my_map"), m)

	ch := make(chan []byte)

	perfMap, err := bcc.InitPerfMap(table, ch, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init PerfMap: %s\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		perfMap.Stop()
	}()

	perfMap.Start()
	for {
		data := <-ch
		var value uint64
		bcc.GetHostByteOrder().PutUint64(data, value)
		fmt.Printf("Received value from BPF program: %d\n", value)
	}
}
