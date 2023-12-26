package main

import (
	"code.byted.org/security/volczti-helper/config"
	"code.byted.org/security/volczti-helper/helper"
	"flag"
	"fmt"
	"https_tutorials/common"
	"io"
	"net/http"
	"path"
	"time"
)

func mtlsClient(Case *TLSClient, port int, specialBundlePath string) (string, error) {
	cfg := &config.LocalSourceConfig{
		Env:     config.EnvTobSdv,
		AppName: "volczti-client-test",
	}

	if len(Case.ClientAgentSocketPath) > 0 {
		cfg.ZTIAgentSocketPath = Case.ClientAgentSocketPath
	} else {
		X509CertPath := path.Join(Case.ClientBaseFolder, "svid.pem")
		X509BundlePath := path.Join(Case.ClientBaseFolder, "bundle.pem")
		X509PrivateKeyPath := path.Join(Case.ClientBaseFolder, "key.pem")

		cfg.FilePath = &config.FilePath{
			X509CertPath:       X509CertPath,
			X509BundlePath:     X509BundlePath,
			X509PrivateKeyPath: X509PrivateKeyPath,
		}
		if len(specialBundlePath) > 0 {
			cfg.FilePath.X509BundlePath = specialBundlePath
		}
	}

	h, err := helper.NewHelper(cfg)
	if err != nil {
		fmt.Printf("New helper failed, err:%s", err.Error())
		return "", err
	}
	defer h.Close()

	tlsConfig, err := h.NewMTLS(Case.ClientTrusted)
	if err != nil {
		fmt.Printf("New zti tls config failed, err:%v", err)
		return "", err
	}

	tr := &http.Transport{
		MaxIdleConns:       10,
		IdleConnTimeout:    30 * time.Second,
		DisableCompression: true,
		TLSClientConfig:    tlsConfig,
	}

	client := &http.Client{Transport: tr}
	url := fmt.Sprintf("https://%s:%d/hello", *ip, port)
	fmt.Printf("client for url: %s\n", url)
	resp, err := client.Get(url)
	if err != nil {
		fmt.Printf("Method GET failed, err:%v", err)
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Printf("ReadAll failed, err:%v", err)
		return "", err
	}

	return string(body), nil
}

type TLSClient struct {
	ClientAgentSocketPath string
	ClientBaseFolder      string
	ClientTrusted         *config.PeerTrustConfig
}

var updateInterval = 5 * time.Second
var ip = flag.String("ip", "", "")

func main() {
	flag.Parse()

	if len(*ip) == 0 {
		fmt.Printf("input ip empty")
		return
	}

	clientCase := &TLSClient{
		ClientAgentSocketPath: "/tmp/agent.sock",
		ClientBaseFolder:      "./cert/client",
		ClientTrusted: &config.PeerTrustConfig{
			EnablePublicPKI:  true,
			EnablePrivatePKI: true,
			EnableByteZTI:    true,
		},
	}

	for {
		t := time.NewTimer(updateInterval)

		select {
		case <-t.C:
			resp, err := mtlsClient(clientCase, common.Port, "")
			if err != nil {
				fmt.Printf("Start client failed, err:%s", err.Error())
			} else {
				fmt.Printf("message: %+v", resp)
			}
		}
	}
}
