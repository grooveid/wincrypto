package wincrypto

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProtectSecret(t *testing.T) {
	ciphertext, err := ProtectSecret([]byte("hunter2"))
	assert.NoError(t, err)
	plaintext, err := UnprotectSecret(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), plaintext)
}

func TestLegacyProtectSecret(t *testing.T) {
	ciphertext, err := legacyProtectSecret([]byte("hunter2"))
	assert.NoError(t, err)
	plaintext, err := legacyUnprotectSecret(ciphertext)
	assert.NoError(t, err)
	assert.Equal(t, []byte("hunter2"), plaintext)
}

func TestUnprotectBadSecret(t *testing.T) {
	plaintext, err := UnprotectSecret([]byte("bad-ciphertext"))
	assert.Error(t, err, "The parameter is incorrect.")
	assert.Nil(t, plaintext)
	plaintext, err = legacyUnprotectSecret([]byte("bad-ciphertext"))
	assert.Error(t, err, "The parameter is incorrect.")
	assert.Nil(t, plaintext)

	ciphertext, err := ProtectSecret([]byte("hunter2"))
	assert.NoError(t, err)
	ciphertext[0] = ^ciphertext[0]
	plaintext, err = UnprotectSecret([]byte("bad-ciphertext"))
	assert.Error(t, err, "The parameter is incorrect.")
	assert.Nil(t, plaintext)
}
