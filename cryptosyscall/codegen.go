package cryptosyscall

//go:generate go run mksyscall_windows.go -output zsyscall_windows.go bcrypt_windows.go dpapi_windows.go crypto_windows.go
