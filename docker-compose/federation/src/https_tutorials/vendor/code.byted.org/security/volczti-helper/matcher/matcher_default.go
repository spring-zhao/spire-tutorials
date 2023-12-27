package matcher

import (
	"crypto/x509"
	"encoding/json"
	"reflect"
	"regexp"

	"code.byted.org/security/volczti-helper/config"
	"code.byted.org/security/volczti-helper/vid"

	"github.com/pkg/errors"
)

// func NewDefaultMatcher(template []*vid.VID) Matcher {

// 	return func(actual *vid.VID) error {
// 		if nil == actual {
// 			err := errors.Errorf("input invalid, actual id is nil")
// 			return err
// 		}

// 		return MatchVolcZTIIDListByRegExp(template, actual)
// 	}
// }

func MatchIDListWithItemByPattern(templateIDList []string, actualID string) (err error) {
	if nil == templateIDList || len(templateIDList) == 0 {
		return nil
	}

	if len(actualID) == 0 {
		err = errors.Errorf("input invalid, actual:%v", actualID)
		return err
	}

	type OneShot struct {
		IDX    int
		ErrMsg string
	}

	var errList []OneShot

	for idx, templateID := range templateIDList {
		if MatchByPattern(templateID, actualID) {
			return nil
		}

		shot := OneShot{
			IDX: idx,
			// ErrMsg: err.Error(),
		}

		errList = append(errList, shot)
	}

	errShots, _ := json.MarshalIndent(errList, "ErrorList", "  ")
	err = errors.Errorf("not match, err:\n%s", errShots)
	return err
}

// DefaultMatcherByStringID default matcher using id string
// func DefaultMatcherByStringID(templateIDStringList []string, actual *vid.VID) error {
// 	if nil == actual || nil == templateIDStringList || len(templateIDStringList) == 0 {
// 		err := errors.Errorf("input invalid")
// 		return err
// 	}

// 	var template []*vid.VID

// 	for _, str := range templateIDStringList {

// 		vid, err := vid.FromString(str)
// 		if err != nil {
// 			return nil
// 		}

// 		template = append(template, vid)
// 	}

// 	return MatchVolcZTIIDListByRegExp(template, actual)
// }

// MatchVolcZTIIDByRegExp use regular expression to match each element of volcid
//
//	domain -> ns -> region -> vdc/az -> volc-id
//	IMPORTANT, if element is empty, step over that
func MatchVolcZTIIDByRegExp(tpl *vid.VID, item *vid.VID) error {
	if nil == tpl || nil == item {
		return errors.Errorf("input invalid")
	}

	o1 := *tpl
	o2 := *item

	t := reflect.TypeOf(o1)
	v1 := reflect.ValueOf(o1)
	v2 := reflect.ValueOf(o2)

	for i := 0; i < v1.NumField(); i++ {
		iName := t.Field(i).Name

		vv1 := v1.FieldByName(iName)
		vv2 := v2.FieldByName(iName)

		if !vv1.CanInterface() || !vv2.CanInterface() {
			continue
		}

		str1, ok := vv1.Interface().(string)
		if !ok {
			return errors.Errorf("template wrong type")
		}

		str2, ok := vv2.Interface().(string)
		if !ok {
			return errors.Errorf("iterm wrong type")
		}

		err := RegExpMatchOneItem(iName, str1, str2)
		if err != nil {
			return errors.Errorf("regexp matching %s error:%v", iName, err)
		}
	}

	return nil
}

func RegExpMatchOneItem(name, template, item string) error {

	if len(template) != 0 {
		match, err := regexp.MatchString(template, item)
		if err != nil {
			return errors.Errorf("regexp matching %s error:%v", name, err)
		}
		if !match {
			return errors.Errorf("%s not match(%s:%s)", name, template, item)
		}
	}

	return nil
}

// MatchByPattern defines matching rules for all, including ID, DNS, URI, IP
func MatchByPattern(template, actual string) bool {
	if template == "" || template == "*" {
		return true
	}
	return deepMatchRune([]rune(template), []rune(actual))
}

func deepMatchRune(pattern, str []rune) bool {
	for len(pattern) > 0 {
		switch pattern[0] {
		case '*':
			return deepMatchRune(pattern[1:], str) || (len(str) > 0 && deepMatchRune(pattern, str[1:]))
		default:
			if len(str) == 0 || str[0] != pattern[0] {
				return false
			}
		}
		str = str[1:]
		pattern = pattern[1:]
	}

	return len(str) == 0 && len(pattern) == 0
}

func MatchSANGroupWithItemByPattern(SAN *config.SAN, cert *x509.Certificate) error {
	info := ""
	if len(SAN.DNS) > 0 {
		for _, dnsName := range cert.DNSNames {
			err := MatchIDListWithItemByPattern(SAN.DNS, dnsName)
			if err == nil {
				return nil // hit
			}
		}

		info = "Verify DNS failed, DNS:"
		for _, d := range cert.DNSNames {
			info += d + " "
		}
	}

	if len(SAN.URI) > 0 {
		// fmt.Printf("URI of leaf is: %v, URI of Identity is: %v\n", cert.URIs, SAN.URI)
		if MatchURI(cert.URIs, SAN.URI) {
			return nil // hit
		}

		info = "Verify URI failed, URI:"
		for _, d := range cert.DNSNames {
			info += d + " "
		}
	}

	if len(SAN.IP) > 0 {
		for _, ipAddress := range cert.IPAddresses {
			err := MatchIDListWithItemByPattern(SAN.IP, ipAddress.String())
			if err == nil {
				return nil // hit
			}
		}

		info = "Verify IP failed, IP:"
		for _, d := range cert.IPAddresses {
			info += d.String() + " "
		}
	}

	return errors.Errorf("Failed to match SAN with Error Info: %s", info)
}
