package vid

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"

	"code.byted.org/security/cryptoutils"
	"code.byted.org/security/go-spiffe-v2/svid/x509svid"

	"code.byted.org/security/go-spiffe-v2/spiffeid"
	"github.com/pkg/errors"
)

const (
	PrefixNS = "ns_" // namespace
	PrefixR  = "r_"  // region
	PrefixAZ = "az_" // available zone
	PrefixC  = "c_"  // cluster name
	//PrefixID = "id_" // not used for now
	//PrefixVDC = "vdc_" // vdc
	BytePrefixID = "id:" // id for byteZTI
)

type VID struct {
	TrustDomain   string `json:"trust_domain" yaml:"trust_domain"`
	NameSpace     string `json:"namespace" yaml:"namespace"`
	Region        string `json:"region" yaml:"region"`
	AvailableZone string `json:"available_zone" yaml:"available_zone"`
	Cluster       string `json:"cluster" yaml:"cluster"`
	ID            string `json:"id" yaml:"id"`
}

// MemberOfTrustDomain returns true if the ID is a member of the given trust domain.
func (id VID) MemberOfTrustDomain(td string) bool {
	return id.TrustDomain == td
}

// MemberOfNamespace returns true if the ID is a member of the given namespace.
func (id VID) MemberOfNamespace(ns string) bool {
	return id.NameSpace == ns
}

func GetIDFieldFromCert(cert *x509.Certificate) (string, error) {
	parsedID, err := x509svid.IDFromCert(cert)
	if err != nil {
		return "", err
	}

	vid, err := FromSpiffeID(&parsedID)
	if err != nil {
		return "", err
	}

	return vid.ID, nil
}

func GetIDFieldFromTLSCert(cert *tls.Certificate) (string, error) {
	certs, err := cryptoutils.ParseCertificates(cert.Certificate)
	if err != nil {
		return "", err
	}

	if len(certs) == 0 {
		return "", errors.Errorf("no certificate")
	}

	parsedID, err := x509svid.IDFromCert(certs[0])
	if err != nil {
		return "", err
	}

	vid, err := FromSpiffeID(&parsedID)
	if err != nil {
		return "", err
	}

	return vid.ID, nil
}

func StrFromCert(cert *x509.Certificate) (string, error) {
	parsedID, err := x509svid.IDFromCert(cert)
	if err != nil {
		return "", err
	}

	return parsedID.String(), nil
}

func StrFromTLSCert(cert *tls.Certificate) (string, error) {
	certs, err := cryptoutils.ParseCertificates(cert.Certificate)
	if err != nil {
		return "", err
	}

	if len(certs) == 0 {
		return "", errors.Errorf("no certificate")
	}

	return StrFromCert(certs[0])
}

func FromCert(cert *x509.Certificate) (*VID, error) {
	parsedID, err := x509svid.IDFromCert(cert)
	if err != nil {
		return nil, err
	}

	vid, err := FromSpiffeID(&parsedID)
	if err != nil {
		return nil, err
	}

	return vid, nil
}

func FromString(s string) (*VID, error) {

	sID, err := spiffeid.FromString(s)
	if err != nil {
		return nil, err
	}

	return FromSpiffeID(&sID)
}

func FromSpiffeID(sID *spiffeid.ID) (*VID, error) {

	remain := sID.Path()
	ns, remain, err := getField(remain, PrefixNS)
	//if len(ns) == 0 || err != nil {
	if err != nil {
		return nil, fmt.Errorf("get field %s failed", PrefixNS)
	}

	region, remain, err := getField(remain, PrefixR)
	//if len(region) == 0 || err != nil {
	if err != nil {
		return nil, fmt.Errorf("get field %s failed", PrefixR)
	}

	az, remain, err := getField(remain, PrefixAZ)
	//if len(az) == 0 || err != nil {
	if err != nil {
		return nil, fmt.Errorf("get field %s failed", PrefixAZ)
	}

	cluster, remain, err := getField(remain, PrefixC)
	//if len(cluster) == 0 || err != nil {
	if err != nil {
		return nil, fmt.Errorf("get field %s failed", PrefixC)
	}

	// cut off the prefix "/"
	if len(remain) > 0 && strings.HasPrefix(remain, "/") {
		remain = remain[1:]
	}

	vID := &VID{
		TrustDomain:   sID.TrustDomain().String(),
		NameSpace:     ns,
		Region:        region,
		AvailableZone: az,
		Cluster:       cluster,
		ID:            remain,
	}

	return vID, err
}

func ByteIDFromSpiffeID(sID *spiffeid.ID) (*VID, error) {
	remain := sID.Path()
	i := strings.Index(remain, BytePrefixID)
	if i < 0 {
		return nil, errors.Errorf("Failed to parse SpiffeID of byteZTI")
	}
	remain = remain[i+3:]

	vID := &VID{
		TrustDomain: sID.TrustDomain().IDString(),
		ID:          remain,
	}

	return vID, nil
}

// func ToSpiffeID(vID *VID) (*spiffeid.ID, error) {
// 	var err error
// 	var path string

// 	if len(vID.NameSpace) != 0 {
// 		// err = errors.Errorf("vID namespace empty")
// 		// return nil, err

// 		path += "/ns_" + vID.NameSpace
// 	}

// 	if len(vID.Region) != 0 {
// 		// err = errors.Errorf("vID region empty")
// 		// return nil, err

// 		path += "/r_" + vID.Region
// 	}

// 	if len(vID.AvailableZone) != 0 {
// 		// err = errors.Errorf("AvailableZone empty")
// 		// return nil, err

// 		path += "/az_" + vID.AvailableZone
// 	}

// 	if len(vID.Cluster) != 0 {
// 		// err = errors.Errorf("Cluster empty")
// 		// return nil, err

// 		path += "/c_" + vID.Cluster
// 	}

// 	if len(vID.ID) != 0 {
// 		// err = errors.Errorf("volc-id empty")
// 		// return nil, err

// 		if !strings.HasPrefix(vID.ID, "/") {
// 			path += "/"
// 		}
// 		path += vID.ID
// 	}

// 	// path = "/ns_" + vID.NameSpace + "/r_" + vID.Region + "/az_" + vID.AvailableZone + "/c_" + vID.Cluster

// 	// if !strings.HasPrefix(vID.ID, "/") {
// 	// 	path += "/"
// 	// }
// 	// path += vID.ID

// 	if len(path) == 0 {
// 		return nil, errors.Errorf("path empty")
// 	}

// 	td, err := spiffeid.TrustDomainFromString(vID.TrustDomain)
// 	if err != nil {
// 		return nil, err
// 	}
// 	sID, err := spiffeid.FromPath(td, path)

// 	return &sID, err
// }

// func ToString(vID *VID) (string, error) {
// 	sID, err := ToSpiffeID(vID)
// 	if err != nil {
// 		return "", err
// 	}

// 	return sID.String(), nil
// }

func getField(s, key string) (value string, remains string, err error) {
	if !strings.HasPrefix(s, "/") {
		//err = errors.Errorf("input format error")
		remains = s
		return
	}

	if strings.Count(s, "/"+key) != 1 {
		//err = errors.Errorf("no any key")
		remains = s
		return
	}

	b := strings.Index(s, key)
	e := strings.Index(s[b+1:], "/") + (b + 1)

	value = s[b+len(key) : e]
	remains = s[:b-1] + s[e:]

	return value, remains, nil
}
