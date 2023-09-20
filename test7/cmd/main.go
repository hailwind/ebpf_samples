package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/iovisor/gobpf/elf"
)

func main() {
	mod := elf.NewModule("test1.o")
	defer mod.Close()

	err := mod.Load(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading '%s' ebpf object: %v\n", os.Args[1], err)
		os.Exit(1)
	}

	err = mod.EnableKprobes(0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading kprobes: %v\n", err)
		os.Exit(1)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
