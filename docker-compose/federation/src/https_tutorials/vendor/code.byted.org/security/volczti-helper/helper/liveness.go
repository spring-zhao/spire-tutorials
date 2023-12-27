package helper

import (
	"context"
	"fmt"
	"os"
	"time"

	"code.byted.org/security/certinfo"
	"code.byted.org/security/volczti-helper/log"
	"code.byted.org/security/volczti-helper/status"

	"code.byted.org/security/go-spiffe-v2/bundle/x509bundle"
	"code.byted.org/security/go-spiffe-v2/proto/spiffe/workload"
	"code.byted.org/security/go-spiffe-v2/spiffeid"
	"code.byted.org/security/go-spiffe-v2/svid/x509svid"
	"github.com/pkg/errors"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

// 检测Agent是否正常工作
func (h *Helper) ProbeAgentLiveness() (out string, err error) {

	if h == nil || h.cfg == nil || len(h.cfg.ZTIAgentSocketPath) == 0 {
		err = errors.Errorf("input config invalid, check if ZTIAgentSocketPath if empty")
		log.Error(err.Error())
		return
	}

	_, err = os.Stat(h.cfg.ZTIAgentSocketPath)
	if err != nil {
		if os.IsNotExist(err) {
			err = status.Errorf(status.CodeAgentSocketNotFound, err.Error())
			return
		} else {
			err = status.Errorf(status.CodeAgentError, err.Error())
			return
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	conn, err := grpc.DialContext(ctx, h.cfg.ZTIAgentSocketPath, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Error(err.Error())

		err = status.Wrap(status.CodeAgentError, err)
		return
	}

	wlClient := workload.NewSpiffeWorkloadAPIClient(conn)
	if wlClient == nil {
		err = status.Errorf(status.CodeAgentError, "workload NewSpiffeWorkloadAPIClient failed")
		log.Error(err.Error())
		return
	}

	outCerts, err := probeX509Certificates(ctx, wlClient)
	if err != nil {
		err = status.Wrap(status.CodeIdentityFetchFailed, err)
		log.Error(err.Error())
		return
	}

	outBundles, err := probeX509Bundles(ctx, wlClient)
	if err != nil {
		err = status.Wrap(status.CodeIdentityFetchFailed, err)
		log.Error(err.Error())
		return
	}

	out = outCerts + outBundles

	log.Info(out)

	return
}

func probeX509Certificates(ctx context.Context, wlClient workload.SpiffeWorkloadAPIClient) (out string, err error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	stream, err := wlClient.FetchX509SVID(ctx, &workload.X509SVIDRequest{})
	if err != nil {
		log.Error(err.Error())
		return
	}

	resp, err := stream.Recv()
	if err != nil {
		log.Error(err.Error())
		return
	}

	svids, err := parseX509SVIDs(resp, true)
	if err != nil {
		log.Error(err.Error())
		return
	}

	out = "===========================================================\n"
	out += fmt.Sprintf("Got %d svids\n", len(svids))
	for i, svid := range svids {

		out += "===========================================================\n"
		out += fmt.Sprintf("svid %d has %d certificates:\n", i+1, len(svid.Certificates))

		for j, cert := range svid.Certificates {
			str, err := certinfo.CertificateText(cert)
			if err != nil {
				continue
			}
			out += "-----------------------------------------------------------\n"
			out += fmt.Sprintf("svid %d, certificate %d:\n%s\n", i+1, j+1, str)
		}
	}

	return
}

func probeX509Bundles(ctx context.Context, wlClient workload.SpiffeWorkloadAPIClient) (out string, err error) {
	ctx, cancel := context.WithCancel(withHeader(ctx))
	defer cancel()

	stream, err := wlClient.FetchX509Bundles(ctx, &workload.X509BundlesRequest{})
	if err != nil {
		log.Error(err.Error())
		return
	}
	resp, err := stream.Recv()
	if err != nil {
		log.Error(err.Error())
		return
	}

	x509BundleSet, err := parseX509BundlesResponse(resp)
	if err != nil {
		log.Error(err.Error())
		return
	}

	bundles := x509BundleSet.Bundles()

	out = "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
	out += fmt.Sprintf("Got %d bundles\n", len(bundles))

	for _, bundle := range bundles {
		td := bundle.TrustDomain().String()
		certs := bundle.X509Authorities()

		out += "+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n"
		out += fmt.Sprintf("TrustDomain %s has %d certificates:\n", td, len(certs))

		for j, cert := range certs {
			str, err := certinfo.CertificateText(cert)
			if err != nil {
				continue
			}
			out += "-----------------------------------------------------------\n"
			out += fmt.Sprintf("TrustDomain %s, certificate %d:\n%s\n", td, j+1, str)
		}
	}

	return
}

func parseX509BundlesResponse(resp *workload.X509BundlesResponse) (*x509bundle.Set, error) {
	bundles := []*x509bundle.Bundle{}

	for tdID, b := range resp.Bundles {
		td, err := spiffeid.TrustDomainFromString(tdID)
		if err != nil {
			return nil, err
		}

		b, err := x509bundle.ParseRaw(td, b)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, b)
	}

	return x509bundle.NewSet(bundles...), nil
}

func withHeader(ctx context.Context) context.Context {
	header := metadata.Pairs("workload.spiffe.io", "true")
	return metadata.NewOutgoingContext(ctx, header)
}

// parseX509SVIDs parses one or all of the SVIDs in the response. If firstOnly
// is true, then only the first SVID in the response is parsed and returned.
// Otherwise all SVIDs are parsed and returned.
func parseX509SVIDs(resp *workload.X509SVIDResponse, firstOnly bool) ([]*x509svid.SVID, error) {
	n := len(resp.Svids)
	if n == 0 {
		return nil, errors.New("no SVIDs in response")
	}
	if firstOnly {
		n = 1
	}

	svids := make([]*x509svid.SVID, 0, n)
	for i := 0; i < n; i++ {
		svid := resp.Svids[i]
		s, err := x509svid.ParseRaw(svid.X509Svid, svid.X509SvidKey)
		if err != nil {
			return nil, err
		}
		svids = append(svids, s)
	}

	return svids, nil
}
