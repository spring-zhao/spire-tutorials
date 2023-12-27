package cryptoutils

import (
	"code.byted.org/security/certinfo"
	"crypto/x509"
)

func CertificateRequestPEMText(pemData []byte) (string, error) {
	csr, err := PEM2x509CSR(pemData)
	if err != nil {
		return "", err
	}

	return certinfo.CertificateRequestText(csr)
}

func CertificateRequestASN1Text(asn1Data []byte) (string, error) {

	csr, err := x509.ParseCertificateRequest(asn1Data)
	if err != nil {
		return "", err
	}

	return certinfo.CertificateRequestText(csr)
}

func CertificatePEMText(pemData []byte) (string, error) {
	cert, err := PEM2x509Cert(pemData)
	if err != nil {
		return "", err
	}

	return certinfo.CertificateText(cert)
}

func CertificateASN1Text(asn1Data []byte) (string, error) {

	cert, err := x509.ParseCertificate(asn1Data)
	if err != nil {
		return "", err
	}

	return certinfo.CertificateText(cert)
}
