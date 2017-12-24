package cryptosyscall

import (
	"fmt"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBCryptOpenAlgorithmProvider(t *testing.T) {
	var handle BCRYPT_ALG_HANDLE

	alg, _ := syscall.UTF16PtrFromString(BCRYPT_RNG_ALGORITHM)
	prov, _ := syscall.UTF16PtrFromString(MS_PRIMITIVE_PROVIDER)
	status := BCryptOpenAlgorithmProvider(&handle, alg, prov, 0)
	assert.Equal(t, NTSTATUS(0), status)
	fmt.Printf("%+v\n", handle)

	buf := make([]byte, 64)
	status = BCryptGenRandom(handle, buf, 0)
	assert.True(t, status.Success())
	fmt.Printf("%x\n", buf)

	status = BCryptCloseAlgorithmProvider(handle, 0)
	assert.True(t, status.Success())
}
