package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/iovisor/gobpf/elf"
)

func main() {
	module := elf.NewModule("test10.o")
	err := module.Load(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load xdp prog: %v\n", err)
		os.Exit(1)
	}

	err = module.AttachXDP("veth0", "xdp/prog1")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to attach xdp prog: %v\n", err)
		os.Exit(1)
	}

	channel := make(chan []byte)
	lost := make(chan uint64)

	perfMap, err := elf.InitPerfMap(module, "tls_hello", channel, lost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to init perf map: %s\n", err)
		os.Exit(1)
	}
	go func() {
		for {
			l := <-lost
			fmt.Println(l)
		}
	}()
	perfMap.PollStart()
	defer perfMap.PollStop()

	for {
		data := <-channel
		fmt.Printf("size: %d\n", len(data))
		fmt.Println(hex.Dump(data))
	}
}
