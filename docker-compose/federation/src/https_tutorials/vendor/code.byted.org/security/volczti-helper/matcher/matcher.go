package matcher

import "code.byted.org/security/volczti-helper/vid"

// Matcher for authentication call back
// users can define customized mather, the match pass if and only a nil error returned
type Matcher func(actual *vid.VID) error
