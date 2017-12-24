package cryptosyscall

type DATA_BLOB struct {
	Count uint32
	Data  *byte
}

type CRYPTPROTECT_PROMPTSTRUCT struct {
	cbSize        uint32
	dwPromptFlags uint32
	hwndApp       HWND
	szPrompt      *uint16
}

const (
	CRYPTPROTECT_LOCAL_MACHINE = 0x4
	CRYPTPROTECT_UI_FORBIDDEN  = 0x1
)

//sys	CryptProtectData(input *DATA_BLOB, dataDescr *uint16, optionalEntropy *DATA_BLOB, reserved uintptr, promptStruct *CRYPTPROTECT_PROMPTSTRUCT, flags uint32, output *DATA_BLOB) (err error) = crypt32.CryptProtectData
//sys	CryptUnprotectData(input *DATA_BLOB, dataDescr *uint16, optionalEntropy *DATA_BLOB, reserved uintptr, promptStruct *CRYPTPROTECT_PROMPTSTRUCT, flags uint32, output *DATA_BLOB) (err error) = crypt32.CryptUnprotectData
