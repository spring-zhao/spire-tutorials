package cryptoutils

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"code.byted.org/security/certinfo"
	"github.com/pkg/errors"
)

//	 KeyUsageDigitalSignature KeyUsage = 1 << iota
//		KeyUsageContentCommitment
//		KeyUsageKeyEncipherment
//		KeyUsageDataEncipherment
//		KeyUsageKeyAgreement
//		KeyUsageCertSign
//		KeyUsageCRLSign
//		KeyUsageEncipherOnly
//		KeyUsageDecipherOnly
var keyUsageNames = []struct {
	usage x509.KeyUsage
	name  string
}{
	{x509.KeyUsageDigitalSignature, "DigitalSignature"},
	{x509.KeyUsageContentCommitment, "ContentCommitment"},
	{x509.KeyUsageKeyEncipherment, "KeyEncipherment"},
	{x509.KeyUsageDataEncipherment, "DataEncipherment"},
	{x509.KeyUsageKeyAgreement, "KeyAgreement"},
	{x509.KeyUsageCertSign, "CertSign"},
	{x509.KeyUsageCRLSign, "CRLSign"},
	{x509.KeyUsageEncipherOnly, "EncipherOnly"},
	{x509.KeyUsageDecipherOnly, "DecipherOnly"},
}

// KeyUsage2String KeyUsage2String
func KeyUsage2String(keyUsage x509.KeyUsage) string {
	var str string = ""
	for _, v := range keyUsageNames {
		if v.usage&keyUsage != 0 {
			str += " " + v.name
		}
	}

	return str
}

// TryParsePEMCertificate TryParsePEMCertificate
func TryParsePEMCertificate(pemCertificate []byte) bool {

	if len(pemCertificate) == 0 {
		return false
	}

	parentASN1Cert, err := PEM2ASN1(pemCertificate, "CERTIFICATE")
	if err != nil {
		return false
	}

	// 2.2. Parse parent certificate
	_, err = x509.ParseCertificate(parentASN1Cert)
	if err != nil {
		return false
	}

	return true
}

func VerifyTLSCert(cert *tls.Certificate, certPool *x509.CertPool) error {
	if len(cert.Certificate) < 1 {
		return errors.Errorf("no certificate")
	}

	certs, err := ParseCertificates(cert.Certificate)
	if err != nil {
		return err
	}

	return VerifyX509Cert(certs, certPool)
}

func VerifyX509Cert(certs []*x509.Certificate, roots *x509.CertPool) error {
	if len(certs) == 0 {
		return errors.Errorf("no certificate")
	}

	leaf := certs[0]
	intermediates := x509.NewCertPool()

	if len(certs) > 1 {
		for _, intermediate := range certs[1:] {
			intermediates.AddCert(intermediate)
		}
	}

	verifyOpts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	}

	_, err := leaf.Verify(verifyOpts)

	return err
}

func VerifyX509Chain(roots []*x509.Certificate, candidates []*x509.Certificate) error {
	if len(candidates) == 0 {
		return errors.Errorf("No certificate")
	}
	if len(roots) == 0 {
		return errors.Errorf("No root certificate")
	}

	leaf := candidates[0]

	interPool := x509.NewCertPool()
	if len(candidates) > 1 {
		for _, intermediate := range candidates[1:] {
			interPool.AddCert(intermediate)
		}
	}

	rootPool := x509.NewCertPool()
	for _, root := range roots {
		rootPool.AddCert(root)
	}

	verifyOpts := x509.VerifyOptions{
		Intermediates: interPool,
		Roots:         rootPool,
	}

	_, err := leaf.Verify(verifyOpts)

	return err
}

// VerifyX509CertificateAgainstSystemRoots Verify inputted "certs" against the Local OS CertPool
func VerifyX509CertificateAgainstSystemRoots(certs []*x509.Certificate) error {
	if len(certs) == 0 {
		return errors.Errorf("no certificate")
	}

	systemPool, err := x509.SystemCertPool()
	if err != nil {
		return err
	}

	verifyOpts := x509.VerifyOptions{
		Roots: systemPool,
	}

	if len(certs) > 1 {
		intermediates := x509.NewCertPool()
		for _, intermediate := range certs[1:] {
			intermediates.AddCert(intermediate)
		}

		verifyOpts.Intermediates = intermediates
	}

	leaf := certs[0]
	_, err = leaf.Verify(verifyOpts)

	return err
}

// NewCertPool returns a new CertPool with the given X.509 certificates
func NewCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}

func ParseCertificates(rawCerts [][]byte) ([]*x509.Certificate, error) {
	certList := make([]*x509.Certificate, 0, len(rawCerts))

	for _, rawCert := range rawCerts {
		certListFromPEM, err := ParseCertificatesPEM(rawCert)
		if err == nil {
			certList = append(certList, certListFromPEM...)
			continue
		}

		certFromDER, err := x509.ParseCertificate(rawCert)
		if err != nil {
			return nil, errors.Errorf("Fail to parse certificate: %v", err)
		}

		certList = append(certList, certFromDER)
	}

	return certList, nil
}

// ParseCertificatesPEM attempts to parse a series of PEM encoded certificates.
// It appends any certificates found to s and reports whether any certificates
// were successfully parsed.
//
// On many Linux systems, /etc/ssl/cert.pem will contain the system wide set
// of root CAs in a format suitable for this function.
func ParseCertificatesPEM(pemCerts []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate

	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			return nil, errors.Errorf("Not PEM file format")
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			continue
		}

		certBytes := block.Bytes
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			continue
		}

		certs = append(certs, cert)
	}

	return certs, nil
}

func ParseCertificateChainPEM(pemCerts []byte) ([]*x509.Certificate, error) {
	return ParseCertificatesPEM(pemCerts)
}

func CertificateChainTextFromPEM(certChainPEM []byte) (str string, err error) {

	bundle, err := ParseCertificatesPEM(certChainPEM)
	if err != nil {
		return
	}

	for idx, cert := range bundle {
		result, err := certinfo.CertificateText(cert)
		if err != nil {
			return "", fmt.Errorf("parse %d cert err:%v", idx, err)
		}

		str += fmt.Sprintf("%s\n", result)
	}

	return
}

func CertificateChainText(certs []*x509.Certificate) (str string, err error) {

	for idx, cert := range certs {
		result, err := certinfo.CertificateText(cert)
		if err != nil {
			return "", fmt.Errorf("parse %d cert err:%v", idx, err)
		}

		str += fmt.Sprintf("%s\n", result)
	}

	return
}
