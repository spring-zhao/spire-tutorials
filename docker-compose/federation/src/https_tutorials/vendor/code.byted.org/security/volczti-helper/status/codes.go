package status

import "strconv"

type Code uint32

const (
	// OK is returned on success.
	OK Code = 0

	// Unknown error. 错误可能来自于非ZTI可控的调用栈
	Unknown Code = 1

	// 定义 ZTI Helepr SDK 错误代码
	CodeInputInvalid        Code = 3
	CodePermissionDenied    Code = 4
	CodeIdentityExpired     Code = 5
	CodePublicKeyNotFound   Code = 6
	CodeIdentityNotIssued   Code = 7
	CodeIdentityFetchFailed Code = 8
	CodeAgentSocketNotFound Code = 9
	CodeAgentError          Code = 10
)

var strToCode = map[string]Code{
	`"OK"`:                      OK,
	`"UNKNOWN"`:                 Unknown,
	`"CodeInputInvalid"`:        CodeInputInvalid,
	`"CodePermissionDenied"`:    CodePermissionDenied,
	`"CodeIdentityExpired"`:     CodeIdentityExpired,
	`"CodePublicKeyNotFound"`:   CodePublicKeyNotFound,
	`"CodeIdentityNotIssued"`:   CodeIdentityNotIssued,
	`"CodeIdentityFetchFailed"`: CodeIdentityFetchFailed,
	`"CodeAgentSocketNotFound"`: CodeAgentSocketNotFound,
	`"CodeAgentError"`:          CodeAgentError,
}

func (c Code) String() string {
	switch c {
	case OK:
		return "OK"
	case Unknown:
		return "Unknown"
	case CodeInputInvalid:
		return "CodeInputInvalid"
	case CodePermissionDenied:
		return "CodePermissionDenied"
	case CodeIdentityExpired:
		return "CodeIdentityExpired"
	case CodePublicKeyNotFound:
		return "CodePublicKeyNotFound"
	case CodeIdentityNotIssued:
		return "CodeIdentityNotIssued"
	case CodeIdentityFetchFailed:
		return "CodeIdentityFetchFailed"
	case CodeAgentSocketNotFound:
		return "CodeAgentSocketNotFound"
	case CodeAgentError:
		return "CodeAgentError"
	default:
		return "Code(" + strconv.FormatInt(int64(c), 10) + ")"
	}
}
