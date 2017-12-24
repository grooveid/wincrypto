package bcrypt

type BCRYPT_HANDLE uintptr
type BCRYPT_ALG_HANDLE BCRYPT_HANDLE
type BCRYPT_HASH_HANDLE BCRYPT_HANDLE
type BCRYPT_SECRET_HANDLE BCRYPT_HANDLE
type BCRYPT_KEY_HANDLE BCRYPT_HANDLE

type BCryptBufferDesc struct {
	//...
}

const (
	BCRYPT_3DES_ALGORITHM              = "3DES"
	BCRYPT_3DES_112_ALGORITHM          = "3DES_112"
	BCRYPT_AES_ALGORITHM               = "AES"
	BCRYPT_AES_CMAC_ALGORITHM          = "AES-CMAC"
	BCRYPT_AES_GMAC_ALGORITHM          = "AES-GMAC"
	BCRYPT_CAPI_KDF_ALGORITHM          = "CAPI_KDF"
	BCRYPT_DES_ALGORITHM               = "DES"
	BCRYPT_DESX_ALGORITHM              = "DESX"
	BCRYPT_DH_ALGORITHM                = "DH"
	BCRYPT_DSA_ALGORITHM               = "DSA"
	BCRYPT_ECDH_P256_ALGORITHM         = "ECDH_P256"
	BCRYPT_ECDH_P384_ALGORITHM         = "ECDH_P384"
	BCRYPT_ECDH_P521_ALGORITHM         = "ECDH_P521"
	BCRYPT_ECDSA_P256_ALGORITHM        = "ECDSA_P256"
	BCRYPT_ECDSA_P384_ALGORITHM        = "ECDSA_P384"
	BCRYPT_ECDSA_P521_ALGORITHM        = "ECDSA_P521"
	BCRYPT_MD2_ALGORITHM               = "MD2"
	BCRYPT_MD4_ALGORITHM               = "MD4"
	BCRYPT_MD5_ALGORITHM               = "MD5"
	BCRYPT_RC2_ALGORITHM               = "RC2"
	BCRYPT_RC4_ALGORITHM               = "RC4"
	BCRYPT_RNG_ALGORITHM               = "RNG"
	BCRYPT_RNG_DUAL_EC_ALGORITHM       = "DUALECRNG"
	BCRYPT_RNG_FIPS186_DSA_ALGORITHM   = "FIPS186DSARNG"
	BCRYPT_RSA_ALGORITHM               = "RSA"
	BCRYPT_RSA_SIGN_ALGORITHM          = "RSA_SIGN"
	BCRYPT_SHA1_ALGORITHM              = "SHA1"
	BCRYPT_SHA256_ALGORITHM            = "SHA256"
	BCRYPT_SHA384_ALGORITHM            = "SHA384"
	BCRYPT_SHA512_ALGORITHM            = "SHA512"
	BCRYPT_SP800108_CTR_HMAC_ALGORITHM = "SP800_108_CTR_HMAC"
	BCRYPT_SP80056A_CONCAT_ALGORITHM   = "SP800_56A_CONCAT"
	BCRYPT_PBKDF2_ALGORITHM            = "PBKDF2"
	BCRYPT_ECDSA_ALGORITHM             = "ECDSA"
	BCRYPT_ECDH_ALGORITHM              = "ECDH"
	BCRYPT_XTS_AES_ALGORITHM           = "XTS-AES"
	MS_PRIMITIVE_PROVIDER              = "Microsoft Primitive Provider"
)

const (
	BCRYPT_ALG_HANDLE_HMAC_FLAG uint32 = 0x00000008
	BCRYPT_PROV_DISPATCH        uint32 = 0x00000001
	BCRYPT_HASH_REUSABLE_FLAG   uint32 = 0x00000020
)

//sys	BCryptOpenAlgorithmProvider(algorithm *BCRYPT_ALG_HANDLE, pszAlgId *uint16, pszImplementation *uint16, flags int32) (s NTSTATUS) = bcrypt.BCryptOpenAlgorithmProvider
//sys	BCryptCloseAlgorithmProvider(algorithm BCRYPT_ALG_HANDLE, flags uintptr) (s NTSTATUS) = bcrypt.BCryptCloseAlgorithmProvider
//sys	BCryptCreateHash(algorithm BCRYPT_ALG_HANDLE,hash *BCRYPT_HASH_HANDLE, hashObject []byte, secret []byte, flags uintptr) (s NTSTATUS) = bcrypt.BCryptCreateHash
//sys	BCryptDecrypt(key BCRYPT_KEY_HANDLE, input []byte, paddingInfo uintptr, iv []byte, output []byte, cbResult *uintptr, flags uintptr) (s NTSTATUS) = bcrypt.BCryptDecrypt
//sys	BCryptDeriveKey(sharedSecret BCRYPT_SECRET_HANDLE,  pwszKDF *uint16, parameterList *BCryptBufferDesc, derivedKey []byte, cbResult *uintptr, flags uintptr) (s NTSTATUS) = bcrypt.BCryptDeriveKey
//sys	BCryptDestroyHash(hash BCRYPT_HASH_HANDLE) (s NTSTATUS) = bcrypt.BCryptDestroyHash
//sys	BCryptDestroyKey(key BCRYPT_KEY_HANDLE) (s NTSTATUS) = bcrypt.BCryptDestroyKey
//sys	BCryptDestroySecret(secret BCRYPT_SECRET_HANDLE) (s NTSTATUS) = bcrypt.BCryptDestroySecret
//sys	BCryptDuplicateHash(hash BCRYPT_HASH_HANDLE, newHash *BCRYPT_HASH_HANDLE, hashObject []byte, flags uintptr) (s NTSTATUS) = bcrypt.BCryptDuplicateHash
//sys	BCryptDuplicateKey(key BCRYPT_KEY_HANDLE, newKey *BCRYPT_KEY_HANDLE, keyObject []byte, flags uintptr) (s NTSTATUS) = bcrypt.BCryptDuplicateKey
//sys	BCryptEncrypt(key BCRYPT_KEY_HANDLE, input []byte, pPaddingInfo uintptr, iv []byte, output []byte, cbResult *uintptr, flags uintptr) (s NTSTATUS) = bcrypt.BCryptEncrypt
//sys	BCryptExportKey(key BCRYPT_KEY_HANDLE, exportKey BCRYPT_KEY_HANDLE, pszBlobType *uint16, output []byte, cbResult *uintptr, flags uintptr) (s NTSTATUS) = bcrypt.BCryptExportKey
//sys	BCryptFinalizeKeyPair(key BCRYPT_KEY_HANDLE, flags uintptr) (s NTSTATUS) = bcrypt.BCryptFinalizeKeyPair
//sys	BCryptFinishHash(hash BCRYPT_HASH_HANDLE, output []byte, flags uintptr) (s NTSTATUS) = bcrypt.BCryptFinishHash
//sys	BCryptFreeBuffer(pvBuffer uintptr) (s NTSTATUS) = bcrypt.BCryptFreeBuffer
//sys	BCryptGenerateKeyPair(algorithm BCRYPT_ALG_HANDLE, hash *BCRYPT_KEY_HANDLE, length uintptr, flags uintptr) (s NTSTATUS) = bcrypt.BCryptGenerateKeyPair
//sys	BCryptGenerateSymmetricKey(algorithm BCRYPT_ALG_HANDLE, hash *BCRYPT_KEY_HANDLE, keyObject []byte, secret []byte, flags uintptr) (s NTSTATUS) = bcrypt.BCryptGenerateSymmetricKey
//sys	BCryptGenRandom(algorithm BCRYPT_ALG_HANDLE, pbBuffer []byte, flags uintptr) (s NTSTATUS) = bcrypt.BCryptGenRandom
//sys	BCryptGetProperty(object BCRYPT_HANDLE, pszProperty *uint16, output []byte, cbResult *uintptr, flags uintptr) (s NTSTATUS) = bcrypt.BCryptGetProperty
//sys	BCryptHash(algorithm BCRYPT_ALG_HANDLE, secret []byte, input []byte, output []byte) (s NTSTATUS) = bcrypt.BCryptHash
//sys	BCryptHashData(hash BCRYPT_HASH_HANDLE, input []byte, flags uintptr) (s NTSTATUS) = bcrypt.BCryptHashData
//sys	BCryptImportKey(algorithm BCRYPT_ALG_HANDLE, importKey *BCRYPT_KEY_HANDLE, pszBlobType *uint16, key *BCRYPT_KEY_HANDLE, keyObject []byte, input []byte, flags uintptr) (s NTSTATUS) = bcrypt.BCryptImportKey
//sys	BCryptImportKeyPair(algorithm BCRYPT_ALG_HANDLE, importKey *BCRYPT_KEY_HANDLE, pszBlobType *uint16, key *BCRYPT_KEY_HANDLE, input []byte, flags uintptr) (s NTSTATUS) = bcrypt.BCryptImportKeyPair
//sys	BCryptKeyDerivation(key BCRYPT_KEY_HANDLE, parameterList *BCryptBufferDesc, dervicedKey []byte, cbResult *uintptr, flags uintptr) (s NTSTATUS) = bcrypt.BCryptKeyDerivation
//sys	BCryptSecretAgreement(privKey BCRYPT_KEY_HANDLE, pubKey BCRYPT_KEY_HANDLE, secret *BCRYPT_SECRET_HANDLE, flags uintptr) (s NTSTATUS) = bcrypt.BCryptSecretAgreement
//sys	BCryptSetProperty(object BCRYPT_HANDLE, pszProperty *uint16, input []byte, flags uintptr) (s NTSTATUS) = bcrypt.BCryptSetProperty
//sys	BCryptSignHash(key BCRYPT_KEY_HANDLE, paddingInfo uintptr, input []byte, output []byte, cbResult *uintptr, flags uintptr) (s NTSTATUS) = bcrypt.BCryptSignHash
//sys	BCryptVerifySignature(key BCRYPT_KEY_HANDLE, pPaddingInfo uintptr, hash []byte, signature []byte, flags uintptr) (s NTSTATUS) = bcrypt.BCryptVerifySignature
