// filememmap project filememmap.go
package filememmap

import (
	"errors"
	"syscall"
	"unsafe"
)

//
const (
	MEM_MAP_READ    = 0
	MEM_MAP_WRITE   = 1
	MEM_MAP_EXECUTE = 2
)

//acl
type acl struct {
	AclRevision byte
	Sbz1        byte
	AclSize     uint16
	AceCount    uint16
	Sbz2        uint16
}

//SECURITY_DESCRIPTOR
type securityDescriptor struct {
	Revision byte
	Sbz1     byte
	Control  uint16
	Owner    uintptr
	Group    uintptr
	Sacl     *acl
	Dacl     *acl
}

//
type memInfo struct {
	hfile syscall.Handle
	hmap  syscall.Handle
	addr  uintptr
}

//
var g_mem map[uintptr]memInfo = make(map[uintptr]memInfo)

//fileSize
func fileSize(fd syscall.Handle) (size int64, err error) {
	size, err = syscall.Seek(fd, 0, syscall.FILE_END)
	//
	return size, err
}

//MemMap
func MemMap(fd syscall.Handle) (addr uintptr, err error) {
	var size int64
	var info memInfo

	//get file size
	size, err = fileSize(fd)
	if nil != err {
		return 0, err
	}
	syscall.Seek(fd, 0, syscall.FILE_BEGIN)
	info.hfile = fd

	//
	var sa syscall.SecurityAttributes
	var sd securityDescriptor
	//
	sd.Control = 4
	sd.Revision = 1
	//
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 0
	sa.SecurityDescriptor = (uintptr)(unsafe.Pointer(&sd))
	info.hmap, err = syscall.CreateFileMapping(info.hfile, &sa, syscall.PAGE_READWRITE, 0, 0, nil)
	if nil != err {
		return 0, err
	}

	//
	info.addr, err = syscall.MapViewOfFile(info.hmap, syscall.FILE_MAP_READ|syscall.FILE_MAP_WRITE, 0, 0, uintptr(size))
	if nil != err {
		return 0, err
	}

	//save
	g_mem[info.addr] = info
	//
	return info.addr, nil
}

//UnMemMap
func UnMemMap(addr uintptr) (err error) {
	var info memInfo
	var ok bool
	//
	info, ok = g_mem[addr]
	if false == ok {
		return errors.New("not found!!!")
	}
	//
	syscall.UnmapViewOfFile(info.addr)
	syscall.CloseHandle(info.hmap)

	//
	return nil
}
