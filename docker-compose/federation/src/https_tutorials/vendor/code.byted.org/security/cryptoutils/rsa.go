package cryptoutils

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"hash"

	"github.com/pkg/errors"
)

// RSAGenerate RSAGenerate
func RSAGenerate(bits int) (pemPublic []byte, pemEPrivate []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}

	block := &pem.Block{
		Type:  PEMTypePrivateKeyPKCS8,
		Bytes: der,
	}
	pemEPrivate = pem.EncodeToMemory(block)

	derPub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	blockPub := &pem.Block{
		Type:  PEMTypePublicKeyPKIX,
		Bytes: derPub,
	}

	pemPublic = pem.EncodeToMemory(blockPub)

	return pemPublic, pemEPrivate, nil
}

// ParsePEMRSAPrivateKey parse rsa key
func ParsePEMRSAPrivateKey(pemPriv []byte) (key *rsa.PrivateKey, err error) {

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
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		key, ok := priv.(*rsa.PrivateKey)
		if !ok {
			err = errors.Errorf("Wrong type, not \"*rsa.PrivateKey\"")
			return nil, err
		}

		return key, nil
	}

	err = errors.Errorf("not support block type:%v", block.Type)
	return nil, err
}

// ParsePEMRSAPublicKey parse a PKCS8 or PKCS1 encode PEM public key into *rsa.PublicKey
func ParsePEMRSAPublicKey(pemPub []byte) (pub *rsa.PublicKey, err error) {

	block, _ := pem.Decode(pemPub)
	if block == nil {
		err = errors.Errorf("decode pem public key failed.")
		return nil, err
	}

	if block.Type == "PUBLIC KEY" {

		re, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			err = errors.Wrap(err, "ParsePKIXPublicKey block.Bytes")
			return nil, err
		}

		repub, ok := re.(*rsa.PublicKey)
		if !ok {
			err = errors.Errorf("Wrong type, not \"*rsa.PublicKey\"")
			return nil, err
		}

		return repub, nil

	} else if block.Type == "RSA PUBLIC KEY" {

		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			err = errors.Wrap(err, "ParsePKCS1PublicKey block.Bytes")
			return nil, err
		}

		return pub, nil
	}

	err = errors.Errorf("not support block type:%v", block.Type)
	return nil, err
}

// RSASignPKCS1v15 RSA Sign PKCS1v15
func RSASignPKCS1v15(priv []byte,
	data []byte,
	isHash bool,
	hashMethod string) (signature []byte, err error) {
	privKey, err := ParsePEMRSAPrivateKey(priv)
	if err != nil {
		err = errors.Wrap(err, "ParsePEMRSAPrivateKey")
		return nil, err
	}

	var hs hash.Hash
	var paramHs crypto.Hash
	var md []byte

	if isHash {
		switch hashMethod {
		case "SHA384":
			hs = sha512.New384()
			paramHs = crypto.SHA384
		case "SHA512":
			hs = sha512.New()
			paramHs = crypto.SHA512
		default:
			hs = sha256.New()
			paramHs = crypto.SHA256
		}
		hs.Write(data)
		md = hs.Sum(nil)
	} else {
		paramHs = 0
		md = data
	}

	signature, err = rsa.SignPKCS1v15(rand.Reader, privKey, paramHs, md[:])
	return signature, err
}

// RSAVerifyPKCS1v15 RSA Verify PKCS1v15
func RSAVerifyPKCS1v15(pub []byte,
	data []byte,
	signature []byte,
	isHash bool,
	hashMethod string) (ok bool, err error) {
	pubKey, err := ParsePEMRSAPublicKey(pub)
	if err != nil {
		err = errors.Wrap(err, "RSAParsePEMPub")
		return false, err
	}

	var hs hash.Hash
	var paramHs crypto.Hash
	var md []byte

	if isHash {
		switch hashMethod {
		case "SHA384":
			hs = sha512.New384()
			paramHs = crypto.SHA384
		case "SHA512":
			hs = sha512.New()
			paramHs = crypto.SHA512
		default:
			hs = sha256.New()
			paramHs = crypto.SHA256
		}
		hs.Write(data)
		md = hs.Sum(nil)
	} else {
		paramHs = 0
		md = data
	}

	err = rsa.VerifyPKCS1v15(pubKey, paramHs, md[:], signature)
	if err != nil {
		return false, err
	}

	return true, nil
}

// RSASignPSS RSA Sign PSS
func RSASignPSS(priv []byte,
	data []byte,
	hashMethod string,
	sLen int) (signature []byte, err error) {
	privKey, err := ParsePEMRSAPrivateKey(priv)
	if err != nil {
		err = errors.Wrap(err, "ParsePEMRSAPrivateKey")
		return nil, err
	}

	var hs hash.Hash
	var paramHs crypto.Hash
	var md []byte

	switch hashMethod {
	case "SHA384":
		hs = sha512.New384()
		paramHs = crypto.SHA384
	case "SHA512":
		hs = sha512.New()
		paramHs = crypto.SHA512
	default:
		hs = sha256.New()
		paramHs = crypto.SHA256
	}

	hs.Write(data)
	md = hs.Sum(nil)

	var opts *rsa.PSSOptions
	if sLen != 0 {
		temp := rsa.PSSOptions{SaltLength: sLen}
		opts = &temp
	}

	signature, err = rsa.SignPSS(rand.Reader, privKey, paramHs, md[:], opts)
	return signature, err
}

// RSAVerifyPSS RSA Verify PSS
func RSAVerifyPSS(pub []byte,
	data []byte,
	signature []byte,
	hashMethod string,
	sLen int) (ok bool, err error) {
	pubKey, err := ParsePEMRSAPublicKey(pub)
	if err != nil {
		err = errors.Wrap(err, "RSAParsePEMPub")
		return false, err
	}

	var hs hash.Hash
	var paramHs crypto.Hash
	var md []byte

	switch hashMethod {
	case "SHA384":
		hs = sha512.New384()
		paramHs = crypto.SHA384
	case "SHA512":
		hs = sha512.New()
		paramHs = crypto.SHA512
	default:
		hs = sha256.New()
		paramHs = crypto.SHA256
	}

	hs.Write(data)
	md = hs.Sum(nil)

	var opts *rsa.PSSOptions
	if sLen != 0 {
		temp := rsa.PSSOptions{SaltLength: sLen}
		opts = &temp
	}

	err = rsa.VerifyPSS(pubKey, paramHs, md[:], signature, opts)
	if err != nil {
		return false, err
	}

	return true, nil
}

// RSAVerifyPKCS1v15withSha256 use RSASSA-PKCS1-v1_5 to verify.
//    use HSA256 to cacl md of data
func RSAVerifyPKCS1v15withSha256(PEMPub []byte, data []byte, signature []byte) error {

	pub, err := ParsePEMRSAPublicKey(PEMPub)
	if err != nil {
		return err
	}

	md := sha256.Sum256(data)

	err = rsa.VerifyPKCS1v15(pub, crypto.SHA256, md[:], signature)
	if err != nil {
		return err
	}

	return nil
}

// RSASignPKCS1v15withSha256 RSA Sign PKCS1v15 By Sha256
func RSASignPKCS1v15withSha256(PEMPriv []byte, data []byte) (signature []byte, err error) {
	priv, err := ParsePEMRSAPrivateKey(PEMPriv)
	if err != nil {
		err = errors.Wrap(err, "ParsePEMRSAPrivateKey")
		return nil, err
	}

	md := sha256.Sum256(data)

	signature, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, md[:])
	return signature, err
}

//RSAVerifyPSSwithSha256 use PKCS 1 PSS to verify.
func RSAVerifyPSSwithSha256(PEMPub []byte, data []byte, signature []byte) error {

	pub, err := ParsePEMRSAPublicKey(PEMPub)
	if err != nil {
		return err
	}

	md := sha256.Sum256(data)

	opts := rsa.PSSOptions{SaltLength: 32}

	err = rsa.VerifyPSS(pub, crypto.SHA256, md[:], signature, &opts)
	if err != nil {
		return err
	}

	return nil
}

// RSASignPSSwithSha256 RSA Sign PKCS1 PSS By Sha256
func RSASignPSSwithSha256(PEMPriv []byte, data []byte) (signature []byte, err error) {
	priv, err := ParsePEMRSAPrivateKey(PEMPriv)
	if err != nil {
		err = errors.Wrap(err, "ParsePEMRSAPrivateKey")
		return nil, err
	}

	md := sha256.Sum256(data)
	opts := rsa.PSSOptions{SaltLength: 32}

	signature, err = rsa.SignPSS(rand.Reader, priv, crypto.SHA256, md[:], &opts)
	return signature, err
}

// RSAEncryptPKCS1OAEP RSA Encrypt PKCS1 OAEP
func RSAEncryptPKCS1OAEP(PEMPub []byte, data []byte) (encrypted []byte, err error) {
	pub, err := ParsePEMRSAPublicKey(PEMPub)
	if err != nil {
		return nil, err
	}

	//if len(data) >= (pub.Size() - 2*sha256.Size - 2) {
	if len(data) >= (pub.Size() - 2*sha1.Size - 2) {
		err = errors.Errorf("data too large, len:%v", len(data))
		return nil, err
	}

	//return rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, data, nil)
	return rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, data, nil)
}

// RSAEncryptPKCS1v15 RSA Encrypt PKCS1 v15
func RSAEncryptPKCS1v15(PEMPub []byte, data []byte) (encrypted []byte, err error) {
	pub, err := ParsePEMRSAPublicKey(PEMPub)
	if err != nil {
		return nil, err
	}

	if len(data) >= (pub.Size() - 2*sha256.Size - 2) {
		err = errors.Errorf("data too large, len:%v", len(data))
		return nil, err
	}

	return rsa.EncryptPKCS1v15(rand.Reader, pub, data)
}

// RSADecryptPKCS1OAEP decrypt oaep
func RSADecryptPKCS1OAEP(PEMPriv []byte, ciphertext []byte) (plaintext []byte, err error) {
	priv, err := ParsePEMRSAPrivateKey(PEMPriv)
	if err != nil {
		err = errors.Wrap(err, "ParsePEMRSAPrivateKey")
		return nil, err
	}

	//return rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, ciphertext, nil)
	return rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, ciphertext, nil)
}

// RSADecryptPKCS1v15 decrypt pkcs1 v1.5
func RSADecryptPKCS1v15(PEMPriv []byte, ciphertext []byte) (plaintext []byte, err error) {
	priv, err := ParsePEMRSAPrivateKey(PEMPriv)
	if err != nil {
		err = errors.Wrap(err, "ParsePEMRSAPrivateKey")
		return nil, err
	}

	return rsa.DecryptPKCS1v15(rand.Reader, priv, ciphertext)
}

// PackRSAEnvelope a package for storing the rsa envelop data
type PackRSAEnvelope struct {
	AlgMode     string `json:"AlgMode"`     // AES-256-GCM, AES-256-CBC
	PaddingMode int    `json:"PaddingMode"` // PKCS7
	EDEK        []byte `json:"EDEK"`        // RSAES-OAEP encrypted dek
	Blob        []byte `json:"Blob"`        // aes gcm encrypted data blob
}
