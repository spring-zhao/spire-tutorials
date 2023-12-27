package tools

import (
	"code.byted.org/security/certinfo"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/go-jose/go-jose/v3/jwt"
	"os"
	"reflect"
)

const (
	textStart     = "\n-----BEGIN "
	textEnd       = "\n-----END "
	textEndOfLine = "-----"
)

func FileExist(path string) bool {
	_, err := os.Lstat(path)
	return !os.IsNotExist(err)
}

func TextFromX509(certs []*x509.Certificate) string {
	var chain string
	for i, cert := range certs {
		mid := fmt.Sprintf("X509 Certificate %d/%d", i+1, len(certs))

		result, err := certinfo.CertificateText(cert)
		if err != nil {
			return ""
		}

		chain += fmt.Sprintf("%s%s%s\n%s%s%s%s", textStart, mid, textEndOfLine, result, textEnd, mid, textEndOfLine)
	}

	return chain
}

func TextFromJWTString(raw string) string {

	var err error
	var mid = "Joint Web Token"

	tok, err := jwt.ParseSigned(raw)
	if err != nil {
		return ""
	}

	dest := make(map[string]interface{})
	err = tok.UnsafeClaimsWithoutVerification(&dest)
	if err != nil {
		return ""
	}

	out, err := json.MarshalIndent(dest, "", "  ")
	if err != nil {
		return ""
	}

	chain := fmt.Sprintf("%s%s%s\n%s%s%s%s", textStart, mid, textEndOfLine, string(out), textEnd, mid, textEndOfLine)

	return string(chain)
}

func TextFromStruct(i interface{}) string {
	var inLine string

	v := reflect.ValueOf(i)
	if v.Kind() == reflect.Ptr {
		ii := v.Elem().Interface()

		inLine += TextFromStruct(ii)
		return inLine
	}

	if v.Kind() != reflect.Struct {
		return ""
	}

	vValue := reflect.ValueOf(i)
	vType := reflect.TypeOf(i)

	inLine += fmt.Sprintln("--:")
	for i := 0; i < vValue.NumField(); i++ {

		inLine += vType.Field(i).Name + ":" + fmt.Sprint(vValue.Field(i))
		inLine += fmt.Sprintln()
	}

	return inLine
}
