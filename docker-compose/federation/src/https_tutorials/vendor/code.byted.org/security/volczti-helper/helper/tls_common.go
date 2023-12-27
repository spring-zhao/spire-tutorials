package helper

import (
	"code.byted.org/security/cryptoutils"
	"code.byted.org/security/go-spiffe-v2/spiffeid"
	"code.byted.org/security/go-spiffe-v2/svid/x509svid"
	"code.byted.org/security/volczti-helper/config"
	"code.byted.org/security/volczti-helper/log"
	"code.byted.org/security/volczti-helper/matcher"
	"code.byted.org/security/volczti-helper/tools"
	"code.byted.org/security/volczti-helper/vid"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"github.com/pkg/errors"
)

const (
	TLSMinVersion = tls.VersionTLS12
	TLSMaxVersion = tls.VersionTLS13
)

// tlsConfigCallbackVerifyPeerCertificate return a func serves callbacks from TLS listener/dialer. It performs
// SPIFFE-specific validation steps on behalf of the golang TLS library
func (h *Helper) newTLSConfigCallbackVerifyPeerCertificate(trusted *config.PeerTrustConfig) func(rawCerts [][]byte, _ [][]*x509.Certificate) error {

	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {

		if trusted == nil {
			return errors.Errorf("There is no any trusted peer configured")
		}

		if len(rawCerts) == 0 {
			return errors.Errorf("Input invalid, no peer certificate inputted")
		}

		// Parse from raw certs
		certs, err := cryptoutils.ParseCertificates(rawCerts)
		if err != nil {
			return errors.Errorf("Parse Certificates cert failed, err:%v", err)
		}
		if len(certs) == 0 {
			return errors.Errorf("No tls certificate from peer")
		}

		if trusted.Matcher != nil {
			return trusted.Matcher.Verify(certs)
		}

		var info string
		// verify Private PKI or System PKI
		if trusted != nil && (trusted.EnablePublicPKI || trusted.EnablePrivatePKI) {
			err = h.externalVerify(trusted, certs)
			if err == nil {
				return nil
			}

			info = fmt.Sprintf("External verify failed, error: \"%s\"", err.Error())
		}

		err = h.volcAndByteZTIVerify(trusted, certs)
		if err != nil {
			info += fmt.Sprintf("ZTI verify failed, error:\"%s\"", err.Error())
			return errors.Errorf(info)
		}

		return nil
	}
}

func (h *Helper) externalVerify(trusted *config.PeerTrustConfig, certs []*x509.Certificate) (err error) {
	if trusted == nil || certs == nil {
		return errors.Errorf("Input invalid, trusted == nil || certs == nil")
	}
	if len(certs) == 0 {
		return errors.Errorf("Input invalid, no certificate inputted")
	}

	leaf := certs[0]

	if trusted.SAN == nil {
		goto ExternalVerifyCertificateChain
	}

	err = matcher.MatchSANGroupWithItemByPattern(trusted.SAN, leaf)
	if err == nil {
		goto ExternalVerifyCertificateChain
	}

	return errors.Errorf("Nothing matched")

ExternalVerifyCertificateChain:
	info := ""
	// check cached leaf and tail certs are valid or not
	err = h.CheckCachedCertificate(certs)
	if err == nil {
		return nil
	}
	info += "Failed to skip verification with cached certificate"

	if trusted != nil && trusted.EnablePublicPKI {
		err = cryptoutils.VerifyX509CertificateAgainstSystemRoots(certs)
		if err == nil {
			// cache the verified leaf cert
			err := h.CachedCertificate(certs)
			if err != nil {
				return err
			}
			return nil
		}

		info += fmt.Sprintf("EnablePublicPKI:true, System Roots Verified failed, err:%s", err.Error())
	}

	if trusted != nil && trusted.EnablePrivatePKI && len(trusted.PrivatePKIRoots) > 0 {
		// roots := []*x509.Certificate{}
		roots, err := cryptoutils.ParseCertificates(trusted.PrivatePKIRoots)
		if err == nil {
			err = cryptoutils.VerifyX509Chain(roots, certs)
			if err == nil {
				// cache the verified leaf cert
				err := h.CachedCertificate(certs)
				if err != nil {
					return err
				}
				return nil
			}

			info += fmt.Sprintf("Private Roots Verified failed, err:%s", err.Error())
		}

		info += "ParseCertificates Roots failed"
	}

	return errors.Errorf("System or Private roots verified fail. Error Info: %s", info)
}

func (h *Helper) volcAndByteZTIVerify(trusted *config.PeerTrustConfig, certs []*x509.Certificate) error {
	if trusted == nil || certs == nil {
		return errors.Errorf("Input invalid, trusted == nil || certs == nil")
	}
	if len(certs) == 0 {
		return errors.Errorf("Input invalid, no certificate inputted")
	}

	leaf := certs[0]
	if len(leaf.URIs) == 0 {
		return errors.Errorf("There is no URI in the leaf certificate")
	}

	sID, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		return errors.Errorf("spiffeid from cert failed, err:%v", err)
	}
	// peerID := sID.String()

	if len(trusted.ID) == 0 && trusted.SAN == nil {
		goto ZTICertChainVerification
	}

	if trusted.SAN != nil {
		err = matcher.MatchSANGroupWithItemByPattern(trusted.SAN, leaf)
		if err == nil {
			goto ZTICertChainVerification
		}
		if len(trusted.ID) == 0 {
			return err
		}
	}

	if trusted.EnableByteZTI {
		if err = parseAndMatchByteZTIID(sID, trusted.ID); err == nil {
			goto ZTICertChainVerification
		}
	}

	err = parseAndMatchVolcZTIID(sID, trusted.ID)
	if err != nil {
		return errors.Errorf("Failed matching with Error err:%v", err)
	}

ZTICertChainVerification:
	return h.verifyZTICertificateChain(trusted, certs)
}

func parseAndMatchByteZTIID(sID spiffeid.ID, ID []string) error {
	id, err := vid.ByteIDFromSpiffeID(&sID)
	if err != nil {
		return errors.Errorf("Failed parsing SpiffeID to ByteID with Error: %v", err)
	}

	err = matcher.MatchIDListWithItemByPattern(ID, id.ID)
	if err != nil {
		return errors.Errorf("Failed matching ByteID with Error: %v", err)
	}
	return nil
}

func parseAndMatchVolcZTIID(sID spiffeid.ID, ID []string) error {
	peerID := sID.String()
	id, err := vid.FromSpiffeID(&sID)
	if err != nil {
		return errors.Errorf("Failed parsing SpiffeID to VolcID with Error:%v", err)
	}

	err = matcher.MatchIDListWithItemByPattern(ID, id.ID)
	if err != nil {
		return errors.Errorf("Peer id(%s), match error:%s", peerID, err)
	}
	return nil
}

func (h *Helper) verifyZTICertificateChain(trusted *config.PeerTrustConfig, certs []*x509.Certificate) error {
	var roots []*x509.Certificate
	// check cached leaf or tail cert is valid or not
	err := h.CheckCachedCertificate(certs)
	if err == nil {
		return nil
	}

	roots, err = h.FetchX509Bundle(trusted)
	if err != nil {
		return errors.Errorf("FetchX509Bundle failed, err:%s", err.Error())
	}

	err = cryptoutils.VerifyX509Chain(roots, certs)
	if err != nil {
		log.Error("Verify X509chain with roots fail", "error", err, "Roots", tools.TextFromX509(roots), "CertificateChain", tools.TextFromX509(certs))
		return err
	}

	// cache the verified leaf cert
	err = h.CachedCertificate(certs)
	if err != nil {
		return err
	}

	return nil
}

func (h *Helper) tlsConfigCallbackGetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {

	return h.fetchTLSCertificate()
}

func (h *Helper) tlsConfigCallbackGetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error) {

	return h.fetchTLSCertificate()
}

func (h *Helper) fetchTLSCertificate() (*tls.Certificate, error) {
	var err error

	certs, sk, err := h.FetchCertificates()
	if err != nil {
		log.Error("FetchX509Certificates", "err", err)
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: make([][]byte, 0, len(certs)),
		PrivateKey:  sk,
	}

	for _, x509Cert := range certs {
		tlsCert.Certificate = append(tlsCert.Certificate, x509Cert.Raw)
	}

	return tlsCert, nil
}

func (h *Helper) CachedCertificate(certs []*x509.Certificate) error {
	if len(certs) < config.CertsLeastLength {
		return errors.Errorf("no certs to cache")
	}
	leaf := certs[0]

	leafHash := sha256.Sum256(leaf.RawTBSCertificate)

	h.cachedx509Certificates[0].Add(leafHash, leaf)

	return nil
}

func (h *Helper) CheckCachedCertificate(certs []*x509.Certificate) error {
	if len(certs) < config.CertsLeastLength {
		return errors.Errorf("no certs to check cache")
	}
	leaf := certs[0]

	leafHash := sha256.Sum256(leaf.RawTBSCertificate)
	_, ok := h.cachedx509Certificates[0].Get(leafHash)
	if ok {
		return nil
	}

	return errors.Errorf("No leaf cert cached")
}
