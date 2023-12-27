package matcher

import (
	"net/url"
)

func MatchURI(actual []*url.URL, templates []string) bool {

	for _, a := range actual {
		for _, t := range templates {
			candidate, err := url.Parse(t)
			if err != nil {
				continue
			}

			if MatchByPattern(candidate.Host, a.Host) && MatchByPattern(candidate.Path, a.Path) {
				return true
			}
		}
	}

	return false
}

//
//func MatchString(actual []string, templates []string) bool {
//
//	for _, a := range actual {
//		for _, t := range templates {
//			r := strings.EqualFold(a, t)
//			if r {
//				return true
//			}
//		}
//	}
//
//	return false
//}
//
//func MatchNetIP(actual []net.IP, templates []string) bool {
//
//	for _, a := range actual {
//		for _, t := range templates {
//			tIP := net.ParseIP(t)
//
//			r := a.Equal(tIP)
//			if r {
//				return true
//			}
//		}
//	}
//
//	return false
//}
