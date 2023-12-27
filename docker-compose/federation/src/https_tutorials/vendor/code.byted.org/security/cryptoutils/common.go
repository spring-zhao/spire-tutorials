package cryptoutils

// PEM TYPE
const (
	PEMTypePrivateKeyPKCS8 = "PRIVATE KEY"
	PEMTypePublicKeyPKIX   = "PUBLIC KEY"

	PEMTypePublicKeyECC  = "EC PUBLIC KEY"
	PEMTypePrivateKeyECC = "EC PRIVATE KEY"

	PEMTypePrivateKeyPKCS1 = "RSA PRIVATE KEY"
	PEMTypePublicKeyPKCS1  = "RSA PUBLIC KEY"

	PEMTypeCertSignRequest = "CERTIFICATE REQUEST"
	PEMTypeCert            = "CERTIFICATE"

	PEMTypeVolcZTIEncryptedPrivateKey = "VOLC ENC RPIV KEY"
)

// ECC group name
const (
	NISTP256 = "NIST-P256"
	NISTP384 = "NIST-P384"
	NISTP521 = "NIST-P521"
)

// Ciphersuite
const (
	CS_AES_GCM       = "AES-GCM"
	CS_AES_CBC_PKCS7 = "AES-CBC-PKCS7"
	CS_ECIES_AES_GCM = "ECIES-AES-GCM"
)

const (
	ECIESKDFTag = "volczti-kdf"
	ECIESMACTag = "volczti-mac"
)

type KeyPack struct {
	PublicKeyPEM  string `json:"public_key_pem"`
	PrivateKeyPEM string `json:"private_key_pem"`
}

type CMS struct {
	Version     string `json:"version,omitempty"`
	KeyID       string `json:"key_id,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	IVLen       int    `json:"iv_len,omitempty"`
	IV          []byte `json:"iv,omitempty"`
	CipherData  []byte `json:"cipher_data,omitempty"`
	AAD         []byte `json:"additional_authentication_data,omitempty"`
	Att         []byte `json:"attached_data,omitempty"`
}

type CMSBin struct {
	Version     string `json:"version,omitempty"`
	KeyID       string `json:"key_id,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	IVLen       int    `json:"iv_len,omitempty"`
	IV          []byte `json:"iv,omitempty"`
	CipherData  []byte `json:"cipher_data,omitempty"`
	AAD         []byte `json:"additional_authentication_data,omitempty"`
	Att         []byte `json:"attached_data,omitempty"`
}
