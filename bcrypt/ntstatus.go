package bcrypt

import "fmt"

type NTSTATUS uint32

func (s NTSTATUS) Success() bool {
	return s&0x3 == 0
}

func (s NTSTATUS) Error() string {
	return fmt.Sprintf("NTSTATUS(0x%08x)", s)
}
