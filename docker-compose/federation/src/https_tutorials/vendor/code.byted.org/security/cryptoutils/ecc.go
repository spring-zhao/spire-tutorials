package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"hash"
	"math/big"
	"reflect"
	"strings"

	"github.com/pkg/errors"
)

func ECCPrivateKey2PEM(priv *ecdsa.PrivateKey) (pemPrivate []byte, err error) {

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}

	block := &pem.Block{
		Type:  PEMTypePrivateKeyPKCS8,
		Bytes: der,
	}

	pemPrivate = pem.EncodeToMemory(block)
	return
}

func ECCPubliceKey2PEM(pub *ecdsa.PublicKey) (pemPublic []byte, err error) {

	derPub, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	blockPub := &pem.Block{
		Type:  PEMTypePublicKeyPKIX,
		Bytes: derPub,
	}

	pemPublic = pem.EncodeToMemory(blockPub)
	return
}

// GenerateECCPEM Generate ecc key pair and return pem
func GenerateECCPEM(groupName string) (pemPublic []byte, pemPrivate []byte, err error) {
	var c elliptic.Curve

	if strings.EqualFold(NISTP256, groupName) {
		c = elliptic.P256()
	} else if strings.EqualFold(NISTP384, groupName) {
		c = elliptic.P384()
	} else if strings.EqualFold(NISTP521, groupName) {
		c = elliptic.P521()
	} else {
		err = errors.Errorf("Wrong ecc group name(%v), only support(%v, %v, %v).",
			groupName, NISTP256, NISTP384, NISTP521)
		return nil, nil, err
	}

	priv, err := ecdsa.GenerateKey(c, rand.Reader)
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
	pemPrivate = pem.EncodeToMemory(block)

	derPub, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	blockPub := &pem.Block{
		Type:  PEMTypePublicKeyPKIX,
		Bytes: derPub,
	}

	pemPublic = pem.EncodeToMemory(blockPub)

	return pemPublic, pemPrivate, nil
}

// ECCSign ECC Sign
func ECCSign(priv []byte,
	data []byte,
	isHash bool,
	hashMethod string) (R []byte, S []byte, err error) {
	privKey, err := ParsePEMEccPrivateKey(priv)
	if err != nil {
		err = errors.Wrap(err, "ParsePEMEccPrivateKey")
		return nil, nil, err
	}

	var hs hash.Hash
	var md []byte

	if isHash {
		switch hashMethod {
		case "SHA384":
			hs = sha512.New384()
		case "SHA512":
			hs = sha512.New()
		default:
			hs = sha256.New()
		}
		hs.Write(data)
		md = hs.Sum(nil)
	} else {
		md = data
	}

	r, s, err := ecdsa.Sign(rand.Reader, privKey, md[:])
	if err != nil {
		return nil, nil, err
	}

	rtext, err := r.MarshalText()
	if err != nil {
		err = errors.Wrap(err, "R MarshalText")
		return nil, nil, err
	}

	stext, err := s.MarshalText()
	if err != nil {
		err = errors.Wrap(err, "S MarshalText")
		return nil, nil, err
	}

	return rtext, stext, nil
}

// ECCVerify ECC verify
func ECCVerify(pub []byte,
	data []byte,
	isHash bool,
	hashMethod string,
	R []byte,
	S []byte) (verify bool, err error) {
	pubKey, err := ParsePEMEccPublicKey(pub)
	if err != nil {
		err = errors.Wrap(err, "ParsePEMEccPublicKey")
		return false, err
	}

	var hs hash.Hash
	var md []byte

	if isHash {
		switch hashMethod {
		case "SHA384":
			hs = sha512.New384()
		case "SHA512":
			hs = sha512.New()
		default:
			hs = sha256.New()
		}
		hs.Write(data)
		md = hs.Sum(nil)
	} else {
		md = data
	}

	var r, s big.Int
	err = r.UnmarshalText(R)
	if err != nil {
		err = errors.Wrap(err, "UnmarshalText R")
		return false, err
	}
	err = s.UnmarshalText(S)
	if err != nil {
		err = errors.Wrap(err, "UnmarshalText S")
		return false, err
	}

	verify = ecdsa.Verify(pubKey, md[:], &r, &s)
	return verify, nil
}

// ParsePEMEccPrivateKey parse a PKCS8 encode PEM private key into *ecdsa.Private
func ParsePEMEccPrivateKey(pemPriv []byte) (key *ecdsa.PrivateKey, err error) {
	block, _ := pem.Decode(pemPriv)
	if block == nil {
		err = errors.Errorf("decode pem private key failed.")
		return nil, err
	}

	if block.Type == "PRIVATE KEY" {
		priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		key, ok := priv.(*ecdsa.PrivateKey)
		if !ok {
			err = errors.Errorf("Wrong type, this is a %v", reflect.TypeOf(priv).Kind())
			return nil, err
		}
		return key, nil
	}

	err = errors.Errorf("not support block type:%v", block.Type)
	return nil, err
}

// ParsePEMEccPublicKey parse a PKCS8 encode PEM public key into *ecdsa.PublicKey
func ParsePEMEccPublicKey(pemPub []byte) (pub *ecdsa.PublicKey, err error) {

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

		repub, ok := re.(*ecdsa.PublicKey)
		if !ok {
			err = errors.Errorf("not supported kind:%v", reflect.ValueOf(re).Kind())
			return nil, err
		}

		return repub, nil
	}

	err = errors.Errorf("not support block type:%v", block.Type)
	return nil, err
}
