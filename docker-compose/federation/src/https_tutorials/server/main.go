package main

import (
	"code.byted.org/security/volczti-helper/config"
	"code.byted.org/security/volczti-helper/helper"
	"fmt"
	"https_tutorials/common"
	"net/http"
	"path"
)

func mtlsServer(Case *TLSServer, port int, matcher *config.IMatcher, specialBundlePath string) (*http.Server, error) {
	cfg := &config.LocalSourceConfig{
		Env:     config.EnvTobSdv,
		AppName: "volczti-server-test",
	}

	if len(Case.ServerAgentSocketPath) > 0 {
		cfg.ZTIAgentSocketPath = Case.ServerAgentSocketPath
	} else {
		X509CertPath := path.Join(Case.ServerBaseFolder, "svid.pem")
		X509BundlePath := path.Join(Case.ServerBaseFolder, "bundle.pem")
		X509PrivateKeyPath := path.Join(Case.ServerBaseFolder, "key.pem")

		cfg.FilePath = &config.FilePath{
			X509CertPath:       X509CertPath,
			X509BundlePath:     X509BundlePath,
			X509PrivateKeyPath: X509PrivateKeyPath,
		}
		if len(specialBundlePath) > 0 {
			cfg.FilePath.X509BundlePath = specialBundlePath
		}
	}

	if matcher != nil {
		Case.ServerTrusted.Matcher = *matcher
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/hello", func(w http.ResponseWriter, req *http.Request) {
		w.Write([]byte("We have established contact.\n"))
	})

	h, err := helper.NewHelper(cfg)
	if err != nil {
		fmt.Printf("New zti helper failed, err:%v", err)
		return nil, err
	}
	defer h.Close()

	tlsConfig, err := h.NewMTLS(Case.ServerTrusted)
	if err != nil {
		fmt.Printf("New zti tls config failed, err:%v", err)
		return nil, err
	}

	srv := &http.Server{
		Addr:      fmt.Sprintf("0.0.0.0:%d", port),
		Handler:   mux,
		TLSConfig: tlsConfig,
	}

	err = srv.ListenAndServeTLS("", "")
	if err != nil && err != http.ErrServerClosed {
		fmt.Printf("ListenAndServeTLS failed, err:%v", err)
	}

	return srv, nil
}

type TLSServer struct {
	ServerAgentSocketPath string
	ServerBaseFolder      string
	ServerTrusted         *config.PeerTrustConfig
}

func main() {
	serverCase := &TLSServer{
		ServerAgentSocketPath: "/tmp/agent.sock",
		ServerBaseFolder:      "./cert/server",
		ServerTrusted: &config.PeerTrustConfig{
			EnablePublicPKI:  true,
			EnablePrivatePKI: true,
			EnableByteZTI:    true,
		},
	}

	var srv, _ = mtlsServer(serverCase, common.Port, nil, "")
	defer func(srv *http.Server) {
		err := srv.Close()
		if err != nil {
			fmt.Printf("failed to close server, err:%s", err)
		}
	}(srv)
}
