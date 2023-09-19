package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

func main() {
	mod := elf.NewModule("test4.o")
	defer mod.Close()

	err := mod.Load(nil)
	if err != nil {
		panic(err)
	}
	err = mod.EnableKprobes(0)
	if err != nil {
		panic(err)
	}

	mapx := mod.Map("my_map")
	key := 0
	value := int64(60000000000)
	if err := mod.UpdateElement(mapx, unsafe.Pointer(&key), unsafe.Pointer(&value), 0); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update element: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Successfully updated map")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
}
