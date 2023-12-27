package config

type ErrorType string

const (
	VOLC_ZTI_AUDIENCE            = "volc_zti"
	DefaultAgentTimeout          = 20  // seconds
	DefaultUpdateIntervalSeconds = 120 // duration for updating cert/bundle/private key from local disk
	CertsLeastLength             = 1   // certs should include at least a leaf cert
)

// 所处的机房环境，运行环境；均指代Tob的环境
const (
	EnvTobSdv  = "EnvTobSdv"
	EnvTobBoe  = "EnvTobBoe"
	EnvTobProd = "EnvTobProd"

	defaultSecIdentifyPath    = "/spire-agent-socket"
	defaultCertFileName       = "svid.pem"
	defaultPrivateKeyFileName = "key.pem"
	defaultBundleFileName     = "bundle.pem"

	VOLCZTI_ENV         = "VOLCZTI_ENV"
	VOLCZTI_APP         = "VOLCZTI_APP"
	VOLCZTI_CERT_PATH   = "VOLCZTI_CERT_PATH"
	VOLCZTI_KEY_PATH    = "VOLCZTI_KEY_PATH"
	VOLCZTI_BUNDLE_PATH = "VOLCZTI_BUNDLE_PATH"
	VOLCZTI_TOKEN_PATH  = "VOLCZTI_TOKEN_PATH"
)
