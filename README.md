# wincrypto

[![Build status](https://ci.appveyor.com/api/projects/status/github/grooveid/wincrypto?svg=true)](https://ci.appveyor.com/project/crewjam/wincrypto)\
[![GoDoc](https://godoc.org/github.com/grooveid/wincrypto?status.svg)](https://godoc.org/github.com/grooveid/wincrypto)

Go bindings for Windows Cryptographic APIs

The package `cryptosyscall` contains (non-idiomatic) bindings for many (but not all) for the
API calls in the NCrypt* and BCrypt* suite.

This is one wrapper for the data protection API, which more to come. Contributions welcome.

```
import "github.com/grooveid/wincrypto"

func main() {
    ciphertext, err := wincrypto.ProtectSecret([]byte("hunter2"))
    if err != nil {
        panic(err)
    }
    fmt.Printf("secret: %x\n", ciphertext)
    
    plaintext, err := wincrypto.UnprotectSecret(ciphertext)
    if err != nil {
        panic(err)
    }
    fmt.Printf("plaintext: %s\n", string(plaintext))
}
```

## Security Issues

Please do not report security issues in the issue tracker. Rather, please contact me directly at ross@grooveid.com ([PGP Key `8EA205C01C425FF195A5E9A43FA0768F26FD2554`](https://keybase.io/crewjam))
