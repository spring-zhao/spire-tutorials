package helper

import (
	"crypto"
	"crypto/x509"

	"code.byted.org/security/cryptoutils"
	"code.byted.org/security/volczti-helper/cache"
	"code.byted.org/security/volczti-helper/config"
	"code.byted.org/security/volczti-helper/log"
	lru "github.com/hashicorp/golang-lru"

	"code.byted.org/security/go-spiffe-v2/svid/x509svid"
	"github.com/pkg/errors"
)

const (
	MaxLeafCacheSize = 5000
)

type Helper struct {
	cfg                    *config.LocalSourceConfig // zti helper config
	cache                  *cache.Cache              // cache
	cachedx509Certificates []*lru.Cache
}

// NewHelper 创建 ZTI Helper
//
// 返回一个Helper指针，可以使用该Helper创建单向或双向TLS协议的TLS LocalSourceConfig。
// 也可以使用Helper直接获取证书和私钥。
// 结束后，应当调用Close()，以避免goroutine泄露。
func NewHelper(cfg *config.LocalSourceConfig) (*Helper, error) {
	var err error

	if nil == cfg {
		err = errors.Errorf("Input config invalid(cfg == nil)")
		return nil, err
	}

	err = config.CheckAndSetDefaultConfig(cfg)
	if nil != err {
		err = errors.Wrapf(err, "Input config content ileagal")
		return nil, err
	}

	log.InitLogger(cfg.LogLevel, cfg.LogWriter) // setup logger

	ca, err := cache.NewCache(cfg)
	if err != nil {
		log.Error("NewCache failed", err, err.Error())
		return nil, err
	}

	cachedLeafCert, _ := lru.New(MaxLeafCacheSize)

	// setup helper
	t := &Helper{
		cfg:                    cfg,
		cache:                  ca,
		cachedx509Certificates: []*lru.Cache{cachedLeafCert},
	}

	return t, nil
}

func (h *Helper) Close() {

	if h == nil || h.cache == nil {
		return
	}

	h.cache.Close()
}

// FetchX509Bundle Fetch local Trust Domain bundle
func (h *Helper) FetchX509Bundle(trusted *config.PeerTrustConfig) ([]*x509.Certificate, error) {
	if h == nil || h.cache == nil {
		return nil, errors.Errorf("Cache not configured!")
	}
	volcZTIX509Bundle, err := h.cache.FetchX509Bundle()

	if !trusted.EnableByteZTI {
		return volcZTIX509Bundle, err
	}

	rawByteZTIBundles, err := config.GetByteZTIBundles()
	if err != nil {
		return nil, err
	}

	byteZTIX509Bundle, err := cryptoutils.ParseCertificatesPEM(rawByteZTIBundles)
	if err != nil {
		err = errors.Errorf("ParseCertificates rawByteZTIBundles failed, err:%s", err.Error())
		log.Error(err.Error())
		return nil, err
	}

	if volcZTIX509Bundle != nil {
		return append(volcZTIX509Bundle, byteZTIX509Bundle...), nil
	}
	return byteZTIX509Bundle, nil
}

// FetchTrustDomain Fetch the Trust Domain string
func (h *Helper) FetchTrustDomain() (string, error) {

	var certs []*x509.Certificate
	var err error

	certs, _, err = h.FetchCertificates()
	if err != nil {
		log.Error("FetchCertificates failed", "err", err)
		return "", err
	}

	if len(certs) != 0 {

		sid, err := x509svid.IDFromCert(certs[0])
		if err != nil {
			log.Error("IDFromCert failed", "err", err)
			return "", err
		}

		return sid.TrustDomain().String(), nil
	}

	return "", errors.Errorf("x509Certificates empty")
}

// FetchCertificates
func (h *Helper) FetchCertificates() ([]*x509.Certificate, crypto.PrivateKey, error) {

	if h == nil || h.cache == nil {
		return nil, nil, errors.Errorf("Cache not configured!")
	}
	return h.cache.FetchX509Certificates()
}
