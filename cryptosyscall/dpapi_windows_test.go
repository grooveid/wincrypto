package cryptosyscall

import (
	"fmt"
	"syscall"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestNcrypt(t *testing.T) {

	descriptorString, _ := syscall.UTF16PtrFromString("LOCAL=user")
	var descriptor NCRYPT_DESCRIPTOR_HANDLE
	status := NCryptCreateProtectionDescriptor(descriptorString, 0, &descriptor)
	assert.True(t, status.Success())

	sekrit := []byte("hunter2")
	var pbProtectBlob uintptr
	var chProtectedBlob uintptr
	status = NCryptProtectSecret(descriptor, NCRYPT_SILENT_FLAG, sekrit, nil, 0, &pbProtectBlob, &chProtectedBlob)
	assert.True(t, status.Success())
	cipherText := copyBuffer(unsafe.Pointer(pbProtectBlob), chProtectedBlob)
	LocalFree(pbProtectBlob)

	NCryptCloseProtectionDescriptor(descriptor)

	// try to decrypt
	{
		descriptorString, _ := syscall.UTF16PtrFromString("LOCAL=user")
		var descriptor NCRYPT_DESCRIPTOR_HANDLE
		status := NCryptCreateProtectionDescriptor(descriptorString, 0, &descriptor)
		assert.True(t, status.Success())

		var data uintptr
		var chData uintptr
		status = NCryptUnprotectSecret(descriptor, NCRYPT_SILENT_FLAG, cipherText, nil, 0, &data, &chData)
		assert.True(t, status.Success())

		plaintext := copyBuffer(unsafe.Pointer(data), chData)
		LocalFree(data)

		assert.Equal(t, sekrit, plaintext)
		fmt.Println(string(plaintext))

		NCryptCloseProtectionDescriptor(descriptor)
	}
}

func copyBuffer(ptr unsafe.Pointer, size uintptr) []byte {
	out := make([]byte, size)
	for i := range out {
		out[i] = *((*byte)(unsafe.Pointer(uintptr(ptr) + uintptr(i))))
	}
	return out
}
