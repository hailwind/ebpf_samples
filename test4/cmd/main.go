package main

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/iovisor/gobpf/elf"
)

func main() {
	mod := elf.NewModule("test3.o")
	if err := mod.Load(nil); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load module: %s\n", err)
		os.Exit(1)
	}
	defer mod.Close()

	// 获取 map
	m := mod.Map("my_map")
	if m == nil {
		fmt.Fprintf(os.Stderr, "Failed to find map: my_map\n")
		os.Exit(1)
	}

	// 创建要插入的键和值
	key := uint32(1)
	value := uint32(100)

	// 将键值对插入到 map 中
	if err := mod.UpdateElement(m, unsafe.Pointer(&key), unsafe.Pointer(&value), 0); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to update element: %s\n", err)
		os.Exit(1)
	}

	fmt.Println("Element inserted successfully.")
}
