package config

import (
	"code.byted.org/security/volczti-helper/tools"
	"crypto/x509"
	"io"
	"os"
	"time"

	"github.com/pkg/errors"
)

// LocalSourceConfig is designed to config where could fetch local endpoint identity.
// It is an instance level configuration.
type LocalSourceConfig struct {
	Env string // 可选only cloud be: EnvTobSdv, EnvTobBoe, EnvTobProd

	// application name, used for metrics, logs
	AppName string

	// logging
	LogWriter io.Writer // 可选。if nil, log will be output to stderr.
	LogLevel  string    // 可选。cloud be: "trace, debug, info, warn, error, off". If no level inputted, sdk output all level logs.

	// 本地证书配置可以来自四个位置，优先级从高到低如下：
	// P1: 系统环境变量：VOLCZTI_CERT_PATH、VOLCZTI_KEY_PATH、VOLCZTI_BUNDLE_PATH
	// P2: io.Reader：Reader 指定的 io.Reader，用户可以将 []byte 转换成 io.Reader 提供出来
	// P3: 指定文件路径：FilePath 指定的文件系统路径
	// P4: 从 ZTI Agent 获取：通过 ZTIAgentSocketPath 指定 ZTI Agent 监听的 UNIX Domain Socket
	Reader             *Reader       // 从 io.Reader 中读取证书、私钥、根证书，优先级【高于FilePath】
	FilePath           *FilePath     // 从本地环境磁盘加载证书、RootCerts、Token等，优先级【高于ZTIAgent】
	ZTIAgentSocketPath string        // 从ZTI Agent加载证书、RootCerts、Token等，优先级【最低】
	ZTIAgentTimeout    time.Duration // 可选。duration for creating new connect to agent by specified unix domain socket
}

// PeerTrustConfig is designed to config who could be trusted. It's a session level configuration.
// Detail config rules 请参考用户指南 https://bytedance.feishu.cn/docx/PtSjd7valoWqCAxCAgLc4R0GndZ
type PeerTrustConfig struct {
	Matcher IMatcher // Can be empty. 用户自定义的证书匹配方法，最高优先级。如果配置，则仅使用该接口匹配，其他逻辑都 by pass

	ID  []string // VolcZTI 和 ByteZTI 的可信身份列表。使用通配符匹配证书使用该模式匹配
	SAN *SAN

	EnableByteZTI    bool     // 是否信任 ByteZTI 身份
	EnablePublicPKI  bool     // 使用公网证书体系开关
	EnablePrivatePKI bool     // 使用外部私有证书体系开关
	PrivatePKIRoots  [][]byte // 仅当"EnablePrivatePKI"为true时生效
}

type IMatcher interface {
	// Verify To verify/validate the peer end certificate chain.
	//     leaf certificate is at the beginning of chain
	Verify(certs []*x509.Certificate) error
}

type SAN struct {
	DNS []string // Extension SubjectAlternativeName DNS
	IP  []string // Extension SubjectAlternativeName IP
	URI []string // Extension SubjectAlternativeName URI
}

type Reader struct {
	X509Cert       io.Reader // PEM format
	X509Bundle     io.Reader // PEM format
	X509PrivateKey io.Reader // PEM format

	JWT       io.Reader // not supported
	JWTBundle io.Reader // not supported
}

type FilePath struct {
	X509CertPath       string // PEM format tlsCertificate loaded from specific PATH
	X509BundlePath     string // PEM format bundle loaded from specific PATH
	X509PrivateKeyPath string // PEM format private key loaded from specific PATH

	JWTPath       string // not supported
	JWTBundlePath string // not supported
}

func (cfg *LocalSourceConfig) setupConfigFromOSEnv() error {
	if cfg == nil {
		return errors.Errorf("input invalid")
	}

	envEnv := os.Getenv(VOLCZTI_ENV)
	if len(envEnv) > 0 {
		cfg.Env = envEnv
	}

	appName := os.Getenv(VOLCZTI_APP)
	if len(appName) > 0 {
		cfg.AppName = appName
	}

	certPath := os.Getenv(VOLCZTI_CERT_PATH)
	keyPath := os.Getenv(VOLCZTI_KEY_PATH)
	bundlePath := os.Getenv(VOLCZTI_BUNDLE_PATH)

	if len(certPath) != 0 && len(keyPath) != 0 && len(bundlePath) != 0 {
		filePath := &FilePath{
			X509CertPath:       certPath,
			X509BundlePath:     bundlePath,
			X509PrivateKeyPath: keyPath,
		}
		cfg.FilePath = filePath

		// OS Env has the highest priority, clear other config
		cfg.Reader = nil
		cfg.ZTIAgentSocketPath = ""
	} else if len(certPath) == 0 && len(keyPath) == 0 && len(bundlePath) == 0 {
		// Empty
		// NO CODE
	} else {
		return errors.Errorf("must setup VOLCZTI_CERT_PATH VOLCZTI_KEY_PATH VOLCZTI_BUNDLE_PATH at the same time")
	}

	return nil
}

func CheckAndSetDefaultConfig(cfg *LocalSourceConfig) error {
	if nil == cfg {
		return errors.Errorf("config input invalid")
	}

	err := cfg.setupConfigFromOSEnv()
	if nil != err {
		err = errors.Wrapf(err, "fail to setup Config from ENV")
		return err
	}

	//if !envIsValid(cfg.Env) {
	//	return errors.Errorf("config.Env invalid, env: %s not support, only support: EnvTobSdv, EnvTobBoe, EnvTobProd", cfg.Env)
	//}

	if len(cfg.LogLevel) == 0 {
		cfg.LogLevel = "trace"
	}

	if nil == cfg.LogWriter {
		cfg.LogWriter = os.Stderr
	}

	if len(cfg.AppName) == 0 {
		cfg.AppName = "nil"
	}

	if cfg.ZTIAgentTimeout < DefaultAgentTimeout*time.Second {
		// if timeout shorter than 1 seconds, use default timeout duration
		cfg.ZTIAgentTimeout = DefaultAgentTimeout * time.Second
	}

	err = tools.ValidateUnixSocketPath(cfg.ZTIAgentSocketPath)
	if err != nil {
		return nil
	}

	cfg.ZTIAgentSocketPath = tools.NormalizeUnixSocketPath(cfg.ZTIAgentSocketPath)

	return nil
}

func envIsValid(env string) bool {
	switch env {
	case EnvTobSdv, EnvTobBoe, EnvTobProd:
		return true
	default:
		return false
	}
}

//
//func (c *FilePath) IsX509FilePathValid() bool {
//	if c == nil {
//		return false
//	}
//
//	_, err := os.Stat(c.X509BundlePath)
//	if err != nil {
//		log.Info("X509BundlePath(%s) not exist", c.X509BundlePath)
//		return false
//	}
//
//	_, err = os.Stat(c.X509CertPath)
//	if err != nil {
//		log.Info("X509CertPath(%s) not exist", c.X509CertPath)
//		return false
//	}
//
//	_, err = os.Stat(c.X509PrivateKeyPath)
//	if err != nil {
//		log.Info("X509PrivateKeyPath(%s) not exist", c.X509PrivateKeyPath)
//		return false
//	}
//
//	return true
//}
//
//func (c *FilePath) IsJWTFilePathValid() bool {
//
//	if c == nil {
//		return false
//	}
//
//	_, err := os.Stat(c.JWTBundlePath)
//	if err != nil {
//		return false
//	}
//
//	_, err = os.Stat(c.JWTPath)
//	if err != nil {
//		return false
//	}
//
//	return true
//}
