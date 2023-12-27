package cryptoutils

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

// ParsePrivateKey parse rsa key
func ParsePrivateKey(in []byte) (key crypto.PrivateKey, err error) {

	block, _ := pem.Decode(in)
	if block == nil {
		// 不是PEM格式

		keyP1, err := x509.ParsePKCS1PrivateKey(in)
		if err == nil {
			return keyP1, nil
		}

		keyEC, err := x509.ParseECPrivateKey(in)
		if err == nil {
			return keyEC, nil
		}

		keyP8, err := x509.ParsePKCS8PrivateKey(in)
		if err == nil {
			return keyP8, nil
		}

		return nil, errors.Errorf("not supported wrap format")
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
	} else if block.Type == "EC PRIVATE KEY" {

		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}

		return key, nil
	}

	err = errors.Errorf("not support block type:%v", block.Type)
	return nil, err
}
