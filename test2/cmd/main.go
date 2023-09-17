package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/iovisor/gobpf/elf"
)

func main() {
	mod := elf.NewModule("test2.o")
	defer mod.Close()

	err := mod.Load(nil)
	if err != nil {
		panic(err)
	}
	err = mod.EnableKprobes(0)
	if err != nil {
		panic(err)
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
