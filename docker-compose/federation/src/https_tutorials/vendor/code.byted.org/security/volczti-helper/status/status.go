package status

import (
	"fmt"
)

type Error struct {
	Code    Code
	Message string
}

func (e *Error) Error() string {
	return fmt.Sprintf("volczti error: code = %d desc = %s", e.Code, e.Message)
}
func (e *Error) VolcZTIErrorCode() Code {
	if e != nil {
		return Unknown
	}
	return e.Code
}

// Errorf returns Error(c, fmt.Sprintf(format, a...)).
func Errorf(c Code, format string, a ...interface{}) error {
	return &Error{Code: c, Message: fmt.Sprintf(format, a...)}
}

// Wrap returns Error(c, fmt.Sprintf(format, a...)).
func Wrap(c Code, err error) error {
	return &Error{Code: c, Message: err.Error()}
}

// Code returns the Code of the error if it is a Status error, codes.OK if err
// is nil, or codes.Unknown otherwise.
func GetCode(err error) Code {
	// Don't use FromError to avoid allocation of OK status.
	if err == nil {
		return OK
	}
	if e, ok := err.(interface {
		VolcZTIErrorCode() Code
	}); ok {
		return e.VolcZTIErrorCode()
	}
	return Unknown
}
