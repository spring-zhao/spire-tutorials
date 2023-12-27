package cryptoutils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"io"
	"math"
	"strings"

	"github.com/beego/beego/v2/core/logs"
	"github.com/pkg/errors"
	"go.mozilla.org/pkcs7"
)

// HMAC256 hash-based message authentication code
func HMAC256(key []byte, message ...[]byte) ([]byte, error) {
	if len(key) <= 0 {
		err := errors.New("input key invalid")
		return nil, err
	}
	md := hmac.New(sha256.New, key)

	for _, v := range message {
		md.Write(v)
	}

	return md.Sum(nil), nil
}

// GetX509FromPEM GetX509FromPEM
func GetX509FromPEM(in []byte) (cert *x509.Certificate, err error) {
	block, _ := pem.Decode(in)
	if block == nil {
		return nil, errors.New("pem.Decode ceritificate be")
	}

	cert, err = x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

// P7Decrypt Pkcs7Decrypt
func P7Decrypt(PEMCert []byte,
	pemEPrivateKey []byte,
	cipher []byte) (plain []byte, err error) {

	block, _ := pem.Decode(pemEPrivateKey)
	if block == nil {
		return nil, errors.New("input pem be")
	}
	//解析PKCS1格式的私钥
	priv, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	if err != nil {
		err = errors.Wrap(err, "private key")
		return nil, err
	}

	cert, err := GetX509FromPEM(PEMCert)
	if err != nil {
		err = errors.Wrap(err, "certificate")
		return nil, err
	}

	p7, err := pkcs7.Parse(cipher)
	if err != nil {
		err = errors.Wrap(err, "")
		return nil, err
	}

	plain, err = p7.Decrypt(cert, priv)
	if err != nil {
		err = errors.Wrap(err, "")
		return nil, err
	}

	return plain, nil
}

// P7Encrypt Pkcs7Decrypt
func P7Encrypt(PEMCert []byte, in []byte) (out []byte, err error) {

	cert, err := GetX509FromPEM(PEMCert)
	if err != nil {
		err = errors.Wrap(err, "certificate")
		return nil, err
	}

	out, err = pkcs7.Encrypt(in, []*x509.Certificate{cert})
	if err != nil {
		err = errors.Wrap(err, "")
		return nil, err
	}

	return out, nil
}

// GenerateRand generates random number
func GenerateRand(bitLength int) (rn []byte, err error) {
	if bitLength%8 != 0 {
		err = errors.Errorf("bitLength should multiple of 8 bits")
		return nil, err
	}

	rn = make([]byte, bitLength/8)
	_, err = rand.Read(rn)
	if nil != err {
		return nil, err
	}

	return rn, err
}

// AESGCMEncrypt AESGCMEncrypt
func AESGCMEncrypt(key []byte,
	plain []byte,
	nonce []byte,
	aad []byte) (encrypted []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	encrypted = gcm.Seal(nil, nonce, plain, aad)

	return encrypted, nil
}

// AESGCMDecrypt AESGCMDecrypt
func AESGCMDecrypt(key []byte,
	encrypted []byte,
	nonce []byte,
	aad []byte) (plain []byte, err error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plain, err = gcm.Open(nil, nonce, encrypted, aad)
	if err != nil {
		return nil, err
	}

	return plain, nil
}

// PackAES a struct for packing gcm result
type PackAES struct {
	IvLen  int    `json:"IvLen"`  // nonce length in bytes
	Iv     string `json:"Iv"`     // base64 encoded nonce
	Cipher string `json:"Cipher"` // base64 encoded ciphertext
}

// AESCBCPackEncrypt AESCBCPackEncrypt
func AESCBCPackEncrypt(key []byte, plain []byte) (pack []byte, err error) {
	p := PackAES{}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plain = PKCS7Padding(plain, aes.BlockSize)

	encrypted := make([]byte, len(plain))
	nonce := make([]byte, aes.BlockSize)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	//fmt.Printf("Nonce: %X\n", nonce)
	//fmt.Printf("plain: %X\n", plain)
	p.IvLen = aes.BlockSize
	p.Iv = base64.StdEncoding.EncodeToString(nonce)

	cbc := cipher.NewCBCEncrypter(block, nonce)
	cbc.CryptBlocks(encrypted, plain)
	p.Cipher = base64.StdEncoding.EncodeToString(encrypted)

	pack, err = json.Marshal(p)
	if err != nil {
		return nil, err
	}
	return pack, nil
}

// AESCBCPackDecrypt decrypt pack outputted by AESCBCPackEncrypt
func AESCBCPackDecrypt(key []byte, pack []byte) (plain []byte, err error) {
	p := PackAES{}

	err = json.Unmarshal(pack, &p)
	if err != nil {
		return nil, err
	}
	cipherblob, err := base64.StdEncoding.DecodeString(p.Cipher)
	if err != nil {
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(p.Iv)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//fmt.Printf("Nonce: %X\n", nonce)
	//fmt.Printf("Cipher: %X\n", cipherblob)

	plain = make([]byte, len(cipherblob))
	cbc := cipher.NewCBCDecrypter(block, nonce)
	cbc.CryptBlocks(plain, cipherblob)
	plain = PKCS7UnPadding(plain)

	return plain, nil
}

// AESGCMPackEncrypt encrypt with gcm mode
func AESGCMPackEncrypt(key []byte, plain []byte) (pack []byte, err error) {
	p := PackAES{}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	p.IvLen = gcm.NonceSize()
	nonce := make([]byte, p.IvLen)
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	p.Iv = base64.StdEncoding.EncodeToString(nonce)

	ciphertext := gcm.Seal(nil, nonce, plain, nil)
	////fmt.Printf("cipher: %X\n", ciphertext)
	p.Cipher = base64.StdEncoding.EncodeToString(ciphertext)

	pack, err = json.Marshal(p)
	if err != nil {
		return nil, err
	}

	return pack, nil
}

// AESGCMPackDecrypt decrypt pack outputted by AESGCMPackEncrypt gcm mode
func AESGCMPackDecrypt(key []byte, pack []byte) (plain []byte, err error) {
	p := PackAES{}

	err = json.Unmarshal(pack, &p)
	if err != nil {
		return nil, err
	}
	cipherblob, err := base64.StdEncoding.DecodeString(p.Cipher)
	if err != nil {
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(p.Iv)
	if err != nil {
		return nil, err
	}

	plain, err = AESGCMDecrypt(key, cipherblob, nonce, nil)
	if err != nil {
		return nil, err
	}

	return plain, nil
}

// DER2PEMEPrivate translate DER coded PKCS8 format pravate key into PEM coding
func DER2PEMEPrivate(derPrivate []byte) (pemEPrivate []byte) {
	blockPub := &pem.Block{
		Type:  PEMTypePrivateKeyPKCS8,
		Bytes: derPrivate,
	}

	return pem.EncodeToMemory(blockPub)
}

// DER2PEMPublic translate DER coded PKCS8 format public key into PEM coding
func DER2PEMPublic(derPub []byte) (pemPub []byte) {
	blockPub := &pem.Block{
		Type:  PEMTypePublicKeyPKIX,
		Bytes: derPub,
	}

	return pem.EncodeToMemory(blockPub)
}

// ASN12PEM 将ASN.1转PEM格式
func ASN12PEM(asn1Data []byte, pemType string) []byte {
	blockPub := &pem.Block{
		Type:  pemType,
		Bytes: asn1Data,
	}

	return pem.EncodeToMemory(blockPub)
}

// PEM2ASN1 将PEM转ASN.1格式
func PEM2ASN1(pemData []byte, pemType string) ([]byte, error) {
	var err error

	block, _ := pem.Decode(pemData)
	if block == nil {
		err = errors.Errorf("Decode pem private key failed.")
		return nil, err
	}

	if strings.Compare(block.Type, pemType) != 0 {
		err = errors.Errorf("PEM Data type failed, input %s, need %s", block.Type, pemType)
		return nil, err
	}

	return block.Bytes, nil
}

// PEM2x509CSR PEM to Internal object, x509 certificate signing request
func PEM2x509CSR(pem []byte) (*x509.CertificateRequest, error) {

	// 1. parse and check input CSR
	asn1, err := PEM2ASN1(pem, PEMTypeCertSignRequest)
	if err != nil {
		logs.Error("%v", err)
		err = errors.New("trans PEM CSR to asn1 failed")
		logs.Error("%v", err)
		return nil, err
	}

	csr, err := x509.ParseCertificateRequest(asn1)
	if err != nil {
		logs.Error("%v", err)
		err = errors.New("x509.ParseCertificateRequest failed")
		return nil, err
	}

	return csr, nil
}

// PEM2x509Cert PEM to Internal object, x509 certificate
func PEM2x509Cert(pem []byte) (*x509.Certificate, error) {

	// 1. parse and check input CSR
	asn1, err := PEM2ASN1(pem, PEMTypeCert)
	if err != nil {
		logs.Error("%v", err)
		err = errors.New("trans PEM CERT to asn1 failed")
		logs.Error("%v", err)
		return nil, err
	}

	cert, err := x509.ParseCertificate(asn1)
	if err != nil {
		logs.Error("%v", err)
		err = errors.New("x509.ParseCertificate failed")
		return nil, err
	}

	return cert, nil
}

// PEM2DERPrivate translate PEM coded PKCS#8 format private key into DER coding
func PEM2DERPrivate(pemEPrivate []byte) (derPrivate []byte, err error) {
	block, _ := pem.Decode(pemEPrivate)
	if block == nil {
		err = errors.Errorf("Decode pem private key failed.")
		return nil, err
	}

	if strings.Compare(block.Type, PEMTypePrivateKeyPKCS8) != 0 {
		err = errors.Errorf("not support block type:%v", block.Type)
		return nil, err
	}

	return block.Bytes, nil
}

// PEM2DERPublic translate PEM coded PKCS#8 format public key into DER coding
func PEM2DERPublic(pemPublic []byte) (derPrivate []byte, err error) {
	block, _ := pem.Decode(pemPublic)
	if block == nil {
		err = errors.Errorf("Decode pem public key failed.")
		return nil, err
	}

	if strings.Compare(block.Type, PEMTypePublicKeyPKIX) != 0 {
		err = errors.Errorf("not support block type:%v", block.Type)
		return nil, err
	}

	return block.Bytes, nil
}

// ParsePEMPrivateKey parse pivate key
func ParsePEMPrivateKey(pemPriv []byte) (key interface{}, err error) {

	block, _ := pem.Decode(pemPriv)
	if block == nil {
		err = errors.Errorf("decode pem private key failed.")
		return nil, err
	}

	if block.Type == "RSA PRIVATE KEY" {
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			err = errors.Wrap(err, "x509.ParsePKCS1PrivateKey(block.Bytes)")
			return nil, err
		}

		return key, nil

	} else if block.Type == "PRIVATE KEY" {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return key, nil
	}

	err = errors.Errorf("not support block type:%v", block.Type)
	return nil, err
}

// PKCS7Padding add PKCS7 Padding
func PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding remove pkcs 7 padding
func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// KDFinNISTCTRMode NIST SP 800-108 ctr mode kdf use SHA-256 as HMAC.
// The input is:
// Key:
//    256-bit HMAC secret.
// Label:
//    Null-terminated ASCII string, encoded as bytes, including the null-terminator.
// Context:
//    Optional binary string containing information related to the derived keying material.
// bitsLen:
//    An unsigned integer specifying the length (in bits) of the output keying material.
//    Encoded as a big-endian, 32-bit unsigned integer. This encoding limits the maximum
//    output bit-count to MAX_UINT32.
// i:
//    The counter, encoded as a big-endian, 32-bit unsigned integer.
//
// Process:
// 1. If (L > MAX_UINT32), then indicate an be and stop
// 2. n <- ceil(L/256) // 256 is the digest length for SHA256
// 3. result(0) <- {}
// 4. For i from 1 to n:
//   a. K(i) <- HMAC_SH256(Key, i || Label || Context || L)
//   b. result(i) <- result(i-1) || K(i)
// 5. Return the leftmost L bits of result(n)
func KDFinNISTCTRMode(key []byte, label string, context []byte, bitsLen uint32) (result []byte, err error) {
	// 1. check input parameters
	if bitsLen%8 != 0 {
		return nil, errors.New("input bits length MUST multiples of 8")
	}

	// 2. 以Null结尾的字符串
	labelNull := []byte(label)
	labelNull = append(labelNull, 0)

	// 3. 输出比特长度，大端表示
	var lenBytes = make([]byte, 4)
	binary.BigEndian.PutUint32(lenBytes, uint32(bitsLen))

	// 4. 迭代次数，大端表示
	var roundBytes = make([]byte, 4)

	// 5. 总循环迭代次数
	n := int(math.Ceil(float64(bitsLen) / float64(256)))
	for i := 1; i <= n; i++ {
		binary.BigEndian.PutUint32(roundBytes, uint32(i))
		md, err := HMAC256(key, roundBytes, labelNull, context, lenBytes)
		if err != nil {
			return nil, err
		}

		appendCount := int(bitsLen)/8 - len(result)
		if appendCount > 32 {
			appendCount = 32
		}
		result = append(result, md[:appendCount]...)
	}

	return result, nil
}
