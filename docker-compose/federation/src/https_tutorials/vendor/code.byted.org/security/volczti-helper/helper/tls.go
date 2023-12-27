package helper

import (
	"crypto/tls"

	"code.byted.org/security/volczti-helper/config"
)

func (h *Helper) NewTLSClient(trusted *config.PeerTrustConfig) (*tls.Config, error) {
	config := &tls.Config{

		MinVersion: TLSMinVersion,
		MaxVersion: TLSMaxVersion,

		InsecureSkipVerify: true, // Disable validation/verification because we perform this step with custom logic in `verifyPeerCertificate`

		// 自定义的验证对方证书的回调函数，利用该函数验证来自服务端的证书链和身份
		VerifyPeerCertificate: h.newTLSConfigCallbackVerifyPeerCertificate(trusted),
	}

	return config, nil
}

// NewTLSServer server use this funn to get a tls.Config, Server will not test verify client side's certificates
func (h *Helper) NewTLSServer() (*tls.Config, error) {
	config := &tls.Config{

		MinVersion: TLSMinVersion,
		MaxVersion: TLSMaxVersion,

		ClientAuth:         tls.NoClientCert,
		InsecureSkipVerify: true, // Disable validation/verification because we perform this step with custom logic in `verifyPeerCertificate`

		// 获取自身证书，即 Server 端证书
		GetCertificate: h.tlsConfigCallbackGetCertificate,
	}

	return config, nil
}

// NewMTLS both client and server use this func to get a tls.Config
// template: The valid id templates
func (h *Helper) NewMTLS(trusted *config.PeerTrustConfig) (*tls.Config, error) {
	config := &tls.Config{
		MinVersion: TLSMinVersion, // shouldn't below the most popular version
		MaxVersion: TLSMaxVersion,

		ClientAuth:         tls.RequireAnyClientCert, // client must send at least one tlsCertificate
		InsecureSkipVerify: true,                     // Disable validation/verification because we perform, this step with custom logic in `verifyPeerCertificate`

		// self defined verifier
		VerifyPeerCertificate: h.newTLSConfigCallbackVerifyPeerCertificate(trusted),
		GetCertificate:        h.tlsConfigCallbackGetCertificate,
		GetClientCertificate:  h.tlsConfigCallbackGetClientCertificate,
	}

	return config, nil
}

// NewMTLSWithAll generates a tls.Config which trust all peer trust domains (VolcZTI、ByteZTI、System/Public PKI)
func (h *Helper) NewMTLSWithAll() (*tls.Config, error) {
	trusted := &config.PeerTrustConfig{
		EnableByteZTI:    true,
		EnablePublicPKI:  true,
		EnablePrivatePKI: true,
	}
	return h.NewMTLS(trusted)
}
