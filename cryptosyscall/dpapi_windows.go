package cryptosyscall

type NCRYPT_DESCRIPTOR_HANDLE uintptr
type NCRYPT_STREAM_HANDLE uintptr
type HLOCAL uintptr
type HWND uintptr

type NCRYPT_ALLOC_PARA struct {
	// ...
}

type NCRYPT_PROTECT_STREAM_INFO struct {
}

const (
	//NCRYPT_NO_PADDING_FLAG                = BCRYPT_PAD_NONE
	//NCRYPT_PAD_PKCS1_FLAG                 = BCRYPT_PAD_PKCS1
	//NCRYPT_PAD_OAEP_FLAG                  = BCRYPT_PAD_OAEP
	//NCRYPT_PAD_PSS_FLAG                   = BCRYPT_PAD_PSS
	//NCRYPT_NO_KEY_VALIDATION              = BCRYPT_NO_KEY_VALIDATION
	//NCRYPT_MACHINE_KEY_FLAG               = 0x00000020
	NCRYPT_SILENT_FLAG = 0x00000040
	//NCRYPT_OVERWRITE_KEY_FLAG             = 0x00000080
	//NCRYPT_WRITE_KEY_TO_LEGACY_STORE_FLAG = 0x00000200
	//NCRYPT_DO_NOT_FINALIZE_FLAG           = 0x00000400
	//NCRYPT_PERSIST_ONLY_FLAG              = 0x40000000
	//NCRYPT_PERSIST_FLAG                   = 0x80000000
	//NCRYPT_REGISTER_NOTIFY_FLAG           = 0x00000001
	//NCRYPT_UNREGISTER_NOTIFY_FLAG         = 0x00000002

	NCRYPT_ALGORITHM_GROUP_PROPERTY        = "Algorithm Group"
	NCRYPT_ALGORITHM_PROPERTY              = "Algorithm Name"
	NCRYPT_ASSOCIATED_ECDH_KEY             = "SmartCardAssociatedECDHKey"
	NCRYPT_BLOCK_LENGTH_PROPERTY           = "Block Length"
	NCRYPT_CERTIFICATE_PROPERTY            = "SmartCardKeyCertificate"
	NCRYPT_DH_PARAMETERS_PROPERTY          = "DHParameters"
	NCRYPT_EXPORT_POLICY_PROPERTY          = "Export Policy"
	NCRYPT_IMPL_TYPE_PROPERTY              = "Impl Type"
	NCRYPT_KEY_TYPE_PROPERTY               = "Key Type"
	NCRYPT_KEY_USAGE_PROPERTY              = "Key Usage"
	NCRYPT_LAST_MODIFIED_PROPERTY          = "Modified"
	NCRYPT_LENGTH_PROPERTY                 = "Length"
	NCRYPT_LENGTHS_PROPERTY                = "Lengths"
	NCRYPT_MAX_NAME_LENGTH_PROPERTY        = "Max Name Length"
	NCRYPT_NAME_PROPERTY                   = "Name"
	NCRYPT_PIN_PROMPT_PROPERTY             = "SmartCardPinPrompt"
	NCRYPT_PIN_PROPERTY                    = "SmartCardPin"
	NCRYPT_PROVIDER_HANDLE_PROPERTY        = "Provider Handle"
	NCRYPT_READER_PROPERTY                 = "SmartCardReader"
	NCRYPT_ROOT_CERTSTORE_PROPERTY         = "SmartcardRootCertStore"
	NCRYPT_SCARD_PIN_ID                    = "SmartCardPinId"
	NCRYPT_SCARD_PIN_INFO                  = "SmartCardPinInfo"
	NCRYPT_SECURE_PIN_PROPERTY             = "SmartCardSecurePin"
	NCRYPT_SECURITY_DESCR_PROPERTY         = "Security Descr"
	NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY = "Security Descr Support"
	NCRYPT_SMARTCARD_GUID_PROPERTY         = "SmartCardGuid"
	NCRYPT_UI_POLICY_PROPERTY              = "UI Policy"
	NCRYPT_UNIQUE_NAME_PROPERTY            = "Unique Name"
	NCRYPT_USE_CONTEXT_PROPERTY            = "Use Context"
	NCRYPT_USE_COUNT_ENABLED_PROPERTY      = "Enabled Use Count"
	NCRYPT_USE_COUNT_PROPERTY              = "Use Count"
	NCRYPT_USER_CERTSTORE_PROPERTY         = "SmartCardUserCertStore"
	NCRYPT_VERSION_PROPERTY                = "Version"
	NCRYPT_WINDOW_HANDLE_PROPERTY          = "HWND Handle"

	NCRYPT_RSA_ALGORITHM_GROUP   = "RSA"
	NCRYPT_DH_ALGORITHM_GROUP    = "DH"
	NCRYPT_DSA_ALGORITHM_GROUP   = "DSA"
	NCRYPT_ECDSA_ALGORITHM_GROUP = "ECDSA"
	NCRYPT_ECDH_ALGORITHM_GROUP  = "ECDH"

	NCRYPT_ALLOW_EXPORT_FLAG              = 0x00000001
	NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG    = 0x00000002
	NCRYPT_ALLOW_ARCHIVING_FLAG           = 0x00000004
	NCRYPT_ALLOW_PLAINTEXT_ARCHIVING_FLAG = 0x00000008

	NCRYPT_IMPL_HARDWARE_FLAG     = 0x00000001
	NCRYPT_IMPL_SOFTWARE_FLAG     = 0x00000002
	NCRYPT_IMPL_REMOVABLE_FLAG    = 0x00000008
	NCRYPT_IMPL_HARDWARE_RNG_FLAG = 0x00000010

	NCRYPT_MACHINE_KEY_FLAG = 0x00000001

	NCRYPT_ALLOW_DECRYPT_FLAG       = 0x00000001
	NCRYPT_ALLOW_SIGNING_FLAG       = 0x00000002
	NCRYPT_ALLOW_KEY_AGREEMENT_FLAG = 0x00000004
	NCRYPT_ALLOW_ALL_USAGES         = 0x00ffffff
)

// HaveNCrypt returns true if the system has NCryptProtectSecret, etc.
// which was added in Windows 8.
func HaveNCrypt() bool {
	return procNCryptProtectSecret.Find() == nil
}

//sys	LocalFree(hMem uintptr) (r uintptr) = kernel32.LocalFree
//sys	NCryptCreateProtectionDescriptor(descriptorString *uint16, flags uint32, descriptor *NCRYPT_DESCRIPTOR_HANDLE) (s NTSTATUS) = ncrypt.NCryptCreateProtectionDescriptor
//sys	NCryptCloseProtectionDescriptor(descriptor NCRYPT_DESCRIPTOR_HANDLE) (s NTSTATUS) = ncrypt.NCryptCloseProtectionDescriptor
//sys	NCryptGetProtectionDescriptorInfo(descriptor NCRYPT_DESCRIPTOR_HANDLE, memPara *NCRYPT_ALLOC_PARA, infoType uint32, ppvInfo *uintptr) (s NTSTATUS) = ncrypt.NCryptGetProtectionDescriptorInfo
//sys	NCryptProtectSecret(descriptor NCRYPT_DESCRIPTOR_HANDLE, flags uint32, data []byte, memPara *NCRYPT_ALLOC_PARA, hWnd HWND, ppbProtectedBlob *uintptr, pcbProtectedBlob *uintptr) (s NTSTATUS) = ncrypt.NCryptProtectSecret
//sys	NCryptQueryProtectionDescriptorName(descriptor NCRYPT_DESCRIPTOR_HANDLE, name *uint16, descriptorString *uint16, flags uint32) (s NTSTATUS) = ncrypt.NCryptQueryProtectionDescriptorName
//sys	NCryptRegisterProtectionDescriptorName(descriptor NCRYPT_DESCRIPTOR_HANDLE, name *uint16, descriptorString *uint16, flags uint32) (s NTSTATUS) = ncrypt.NCryptRegisterProtectionDescriptorName
//sys	NCryptStreamClose(stream NCRYPT_STREAM_HANDLE) (s NTSTATUS) = ncrypt.NCryptStreamClose
//sys	NCryptStreamOpenToProtect(descriptor NCRYPT_DESCRIPTOR_HANDLE, flags uint32, hWnd HWND, streamInfo *NCRYPT_PROTECT_STREAM_INFO, stream *NCRYPT_STREAM_HANDLE) (s NTSTATUS) = ncrypt.NCryptStreamOpenToProtect
//sys	NCryptStreamOpenToUnprotectEx(descriptor NCRYPT_DESCRIPTOR_HANDLE, flags uint32, hWnd HWND, stream *NCRYPT_STREAM_HANDLE) (s NTSTATUS) = ncrypt.NCryptStreamOpenToUnprotectEx
//sys	NCryptStreamOpenToUnprotect(descriptor NCRYPT_DESCRIPTOR_HANDLE, flags uint32, hWnd HWND, stream *NCRYPT_STREAM_HANDLE) (s NTSTATUS) = ncrypt.NCryptStreamOpenToUnprotect
//sys	NCryptStreamUpdate(stream NCRYPT_STREAM_HANDLE, data []byte, final bool) (s NTSTATUS) = ncrypt.NCryptStreamUpdate
//sys	NCryptUnprotectSecret(descriptor NCRYPT_DESCRIPTOR_HANDLE, flags uint32, protectedBlob []byte, memPara *NCRYPT_ALLOC_PARA, hWnd HWND, ppbData *uintptr, pcbData *uintptr) (s NTSTATUS) = ncrypt.NCryptUnprotectSecret
