package cache

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"os"
	"sync"
	"time"

	"code.byted.org/security/cryptoutils"
	"code.byted.org/security/volczti-helper/tools"

	"code.byted.org/security/volczti-helper/config"
	"code.byted.org/security/volczti-helper/jwkset"
	"code.byted.org/security/volczti-helper/log"

	"code.byted.org/security/go-spiffe-v2/svid/jwtsvid"
	"code.byted.org/security/go-spiffe-v2/workloadapi"
	"github.com/pkg/errors"
)

type Cache struct {
	mux       sync.Mutex
	cacheDone chan bool

	MemReader       *config.Reader      // load from io.Reader
	FilePath        *config.FilePath    // load from cfg specified path
	WorkloadClient  *workloadapi.Client // load from workloadapi client, zti agent
	ZTIAgentTimeout time.Duration
	// SVID X509
	x509PrivateKey  crypto.PrivateKey   // private key
	x509Certificate []*x509.Certificate // certificates in x509.Certificate format
	x509Bundle      []*x509.Certificate // bundle cert chain

	// trusted certifcate pool, consist of intermediates CA and root CA
	//certpool *x509.CertPool // trusted bundle cert pool

	// JWT token
	jwtToken     []byte
	jwtBundleSet []byte
}

func NewCache(cfg *config.LocalSourceConfig) (*Cache, error) {
	c := Cache{}

	if cfg == nil {
		err := errors.Errorf("input config invalid, empty")
		log.Error("New cache fail", "error", err)
		return nil, err
	}

	if cfg.Reader != nil {
		c.MemReader = cfg.Reader
	}

	if cfg != nil && cfg.FilePath != nil {
		c.FilePath = cfg.FilePath
	}

	if cfg != nil && len(cfg.ZTIAgentSocketPath) > 0 {

		ctx, cancel := context.WithTimeout(context.Background(), cfg.ZTIAgentTimeout)
		defer cancel()

		workloadClient, err := workloadapi.New(ctx, workloadapi.WithAddr(cfg.ZTIAgentSocketPath))
		if err != nil {
			err = errors.Errorf("Unable to create workloadapi client: %s", err)
			log.Error("workloadapi New failed", "err", err)
			return nil, err
		}

		c.WorkloadClient = workloadClient
		c.ZTIAgentTimeout = cfg.ZTIAgentTimeout
	}

	err := c.refreshCacheOnce()
	if err != nil {
		log.Error("Initializing load failed", "err", err)
		return nil, err
	}

	go c.refreshDeamon(config.DefaultUpdateIntervalSeconds * time.Second)

	return &c, nil
}

func (c *Cache) Close() {

	if c == nil {
		return
	}

	if c.cacheDone != nil {
		c.cacheDone <- true
	}
}

func (c *Cache) refreshDeamon(updateInterval time.Duration) {

	for {

		if updateInterval < time.Second {
			updateInterval = time.Second
		}

		t := time.NewTimer(updateInterval)

		select {
		case <-c.cacheDone:
			err := c.WorkloadClient.Close()
			if err != nil {
				log.Error("failed to close workload client", "err", err)
			}
			c.WorkloadClient = nil
			return

		case <-t.C:
			c.refreshCacheOnce()
		}
	}
}

func (c *Cache) refreshCacheOnce() error {
	if c.MemReader != nil {
		if err := c.refreshCacheFromMemReader(); err != nil {
			log.Trace("load SVID from io.Reader fail", "error", err)
			return err
		} else {
			// Got SVID, should return, not fall down
			return nil
		}
	}

	if c.FilePath != nil {
		if err := c.refreshCacheFromDisk(); err != nil {
			log.Trace("load SVID from DISK fail", "error", err)
			return err
		} else {
			// Got SVID, should return, not fall down
			return nil
		}
	}

	if c.WorkloadClient != nil {
		if err := c.refreshCacheFromAgent(); err != nil {
			log.Trace("load SVID from ZTI Agent fail", "error", err)
			return err
		} else {
			// Got SVID, should return, not fall down
			return nil
		}
	}

	return nil
}

// refresh cache
func (c *Cache) refreshCacheFromAgent() (err error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c == nil {
		err := errors.Errorf("cache is nil")
		log.Error("refreshCacheFromAgent", "err", err)
		return err
	}

	if c.WorkloadClient == nil {
		err := errors.Errorf("WorkloadClient is nil")
		log.Error("refreshCacheFromAgent", "err", err)
		return err
	}

	// 1. refresh jwt
	ctx, cancel := context.WithTimeout(context.Background(), c.ZTIAgentTimeout)
	defer cancel()

	svid, err := c.WorkloadClient.FetchJWTSVID(ctx, jwtsvid.Params{
		Audience: config.VOLC_ZTI_AUDIENCE,
	})
	if err != nil {
		log.Error("FetchJWTSVID", "err", err)
		return err
	}
	c.jwtToken = []byte(svid.Marshal())

	spireJWTBundleSet, err := c.WorkloadClient.FetchJWTBundles(ctx)
	if err != nil {
		err = errors.Errorf("FetchJWTBundles, err:%v", err)
		log.Error("FetchJWTBundles", "err", err)
		return err
	}

	jwkset, err := jwkset.SpireJWTBundleSet2JWKSet(spireJWTBundleSet)
	if err != nil {
		log.Error("SpireJWTBundleSet2JWKSet failed", "err", err)
		return err
	}

	c.jwtBundleSet, err = jwkset.Marshal()
	if err != nil {
		err = errors.Errorf("jwkset.Marshal bundles, err:%v", err)
		log.Error("jwkset.Marshal bundles", "err", err)
		return err
	}

	// 2. Load x509
	svidX509, err := c.WorkloadClient.FetchX509SVID(ctx)
	if err != nil {
		log.Error("FetchX509SVID failed", "err", err)
		return err
	}

	c.x509Certificate = svidX509.Certificates
	c.x509PrivateKey = svidX509.PrivateKey

	if len(c.x509Certificate) == 0 {
		err = errors.Errorf("Fetched x509 certificates from zti-agent are empty")
		log.Error(err.Error())
		return err
	}

	x509BundleSet, err := c.WorkloadClient.FetchX509Bundles(ctx)
	if err != nil {
		log.Error("FetchX509Bundles from agent failed", "err", err)
		return err
	}

	bundles := x509BundleSet.Bundles()
	if len(bundles) <= 0 {
		err := errors.Errorf("the bundles not exist.")
		log.Error(err.Error())
		return err
	}
	for _, v := range bundles {
		certs := v.X509Authorities()
		c.x509Bundle = append(c.x509Bundle, certs...)
	}

	return nil
}

// refresh cache from io.Reader
func (c *Cache) refreshCacheFromMemReader() (err error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c == nil || c.MemReader == nil {
		err := errors.Errorf("input invalid, empty cache or empty cache.Reader")
		log.Warn("input invalid, empty cache or empty cache.Reader")
		return err
	}

	// trying to load JWT and JWT bundle
	if c.MemReader.JWT != nil {
		buf := &bytes.Buffer{}
		_, err := buf.ReadFrom(c.MemReader.JWT)
		if err != nil {
			err = errors.Wrap(err, "Load JWT Token io.Reader failed")
			log.Error(err.Error())
			return err
		}
		c.jwtToken = buf.Bytes()
	}
	if c.MemReader.JWTBundle != nil {
		buf := &bytes.Buffer{}
		_, err := buf.ReadFrom(c.MemReader.JWTBundle)
		if err != nil {
			err = errors.Wrap(err, "Load JWT Bundle from io.Reader failed")
			log.Error(err.Error())
			return err
		}
		c.jwtBundleSet = buf.Bytes()
	}

	// trying to load and parse cert
	if c.MemReader.X509Cert != nil {
		buf := &bytes.Buffer{}
		_, err := buf.ReadFrom(c.MemReader.X509Cert)
		x509 := buf.Bytes()
		if err == nil {
			c.x509Certificate, err = cryptoutils.ParseCertificates([][]byte{x509})
			if err != nil {
				err := errors.Errorf("ParseCertificates x509Certificate failed, err:%s", err.Error())
				log.Error(err.Error())
				return err
			}
		}
	}
	if c.MemReader.X509Bundle != nil {
		buf := &bytes.Buffer{}
		_, err := buf.ReadFrom(c.MemReader.X509Bundle)
		x509Bundle := buf.Bytes()
		if err == nil {
			c.x509Bundle, err = cryptoutils.ParseCertificates([][]byte{x509Bundle})
			if err != nil {
				err := errors.Errorf("ParseCertificates x509Bundle failed, err:%s", err.Error())
				log.Error(err.Error())
				return err
			}
		}
	}
	if c.MemReader.X509PrivateKey != nil {
		buf := &bytes.Buffer{}
		_, err := buf.ReadFrom(c.MemReader.X509PrivateKey)
		x509PrivateKey := buf.Bytes()
		if err == nil {
			c.x509PrivateKey, err = cryptoutils.ParsePrivateKey(x509PrivateKey)
			if err != nil {
				err = errors.Errorf("ParsePrivateKey failed, err:%s", err.Error())
				log.Error(err.Error())
				return err
			}
		}
	}

	return nil
}

// refresh cache from disk
func (c *Cache) refreshCacheFromDisk() (err error) {
	c.mux.Lock()
	defer c.mux.Unlock()

	if c == nil || c.FilePath == nil {
		return nil
	}

	// trying to load JWT and JWT bundle
	if len(c.FilePath.JWTPath) > 0 {
		if tools.FileExist(c.FilePath.JWTPath) {
			jwtBlob, err := os.ReadFile(c.FilePath.JWTPath)
			if err != nil {
				err = errors.Wrap(err, "Load JWT Token failed")
				log.Error(err.Error())
				return err
			}
			c.jwtToken = jwtBlob
		} else {
			err := errors.Errorf("Wrong JWT Token config, path:%s", c.FilePath.JWTPath)
			log.Error(err.Error())
			return err
		}
	}
	if len(c.FilePath.JWTBundlePath) > 0 {
		if tools.FileExist(c.FilePath.JWTBundlePath) {
			jwtBundleSetBlob, err := os.ReadFile(c.FilePath.JWTBundlePath)
			if err != nil {
				err = errors.Wrap(err, "Load JWT Bundle failed")
				log.Error(err.Error())
				return err
			}
			c.jwtBundleSet = jwtBundleSetBlob
		} else {
			err := errors.Errorf("Wrong JWT Bundle config, path:%s", c.FilePath.JWTBundlePath)
			log.Error(err.Error())
			return err
		}
	}

	// trying to load and parse cert
	if len(c.FilePath.X509CertPath) > 0 {
		if tools.FileExist(c.FilePath.X509CertPath) {
			x509, err := os.ReadFile(c.FilePath.X509CertPath)
			if err == nil {
				c.x509Certificate, err = cryptoutils.ParseCertificates([][]byte{x509})
				if err != nil {
					err := errors.Errorf("ParseCertificates x509Certificate failed, err:%s", err.Error())
					log.Error(err.Error())
					return err
				}
			}
		} else {
			err := errors.Errorf("Wrong X509CertPath config, path:%s", c.FilePath.X509CertPath)
			log.Error(err.Error())
			return err
		}
	}
	if len(c.FilePath.X509BundlePath) > 0 {
		if tools.FileExist(c.FilePath.X509BundlePath) {
			x509Bundle, err := os.ReadFile(c.FilePath.X509BundlePath)
			if err == nil {
				c.x509Bundle, err = cryptoutils.ParseCertificates([][]byte{x509Bundle})
				if err != nil {
					err := errors.Errorf("ParseCertificates x509Bundle failed, err:%s", err.Error())
					log.Error(err.Error())
					return err
				}
			}
		} else {
			err := errors.Errorf("Wrong X509BundlePath config, path:%s", c.FilePath.X509BundlePath)
			log.Error(err.Error())
			return err
		}
	}
	if len(c.FilePath.X509PrivateKeyPath) > 0 {
		if tools.FileExist(c.FilePath.X509PrivateKeyPath) {
			x509PrivateKey, err := os.ReadFile(c.FilePath.X509PrivateKeyPath)
			if err == nil {
				c.x509PrivateKey, err = cryptoutils.ParsePrivateKey(x509PrivateKey)
				if err != nil {
					err = errors.Errorf("ParsePrivateKey failed, err:%s", err.Error())
					log.Error(err.Error())
					return err
				}
			}
		} else {
			err := errors.Errorf("Wrong X509PrivateKeyPath config, path:%s", c.FilePath.X509PrivateKeyPath)
			log.Error(err.Error())
			return err
		}
	}

	return nil
}

func (c *Cache) FetchX509Certificates() ([]*x509.Certificate, crypto.PrivateKey, error) {
	var err error

	if nil == c.x509Certificate || nil == c.x509PrivateKey {
		c.refreshCacheOnce()

		if nil == c.x509Certificate || nil == c.x509PrivateKey {

			err = errors.Errorf("x509Certificate or x509PrivateKey empty")
			log.Error(err.Error())

			return nil, nil, err
		}
	}

	return c.x509Certificate, c.x509PrivateKey, nil
}

func (c *Cache) FetchX509Bundle() ([]*x509.Certificate, error) {
	var err error

	if nil == c.x509Bundle {
		c.refreshCacheOnce()

		if nil == c.x509Bundle {

			err = errors.Errorf("x509Bundle empty")
			log.Error(err.Error())

			return nil, err
		}
	}

	return c.x509Bundle, nil
}

func (c *Cache) FetchJwtToken() (tok string, err error) {

	if c == nil {
		err = errors.Errorf("Cache invalid")
		log.Error("Cache invalid")
		return
	}

	if c.jwtToken == nil {
		c.refreshCacheOnce()

		if c.jwtToken == nil {
			err = errors.Errorf("token empty")
			log.Error(err.Error())

			return
		}
	}

	return string(c.jwtToken), nil
}

func (c *Cache) FetchJwtTokenBundle() (string, error) {

	var err error

	if c == nil {
		err = errors.Errorf("Cache invalid")
		log.Error("Cache invalid")
		return "", err
	}

	if c.jwtBundleSet == nil {
		c.refreshCacheOnce()

		if c.jwtBundleSet == nil {
			err = errors.Errorf("jwtBundle empty")
			log.Error(err.Error())

			return "", err
		}
	}
	return string(c.jwtBundleSet), nil
}
