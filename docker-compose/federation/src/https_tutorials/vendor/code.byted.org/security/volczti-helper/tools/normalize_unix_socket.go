package tools

import (
	"fmt"
	"os"
	"strings"
)

const (
	UNIX_SCHEME = "unix://"
)

func NormalizeUnixSocketPath(socketPath string) string {
	if strings.HasPrefix(socketPath, UNIX_SCHEME) {
		return socketPath
	} else {
		return fmt.Sprintf("%s%s", UNIX_SCHEME, socketPath)
	}
}

func ValidateUnixSocketPath(socketPath string) error {
	socketPath = strings.TrimPrefix(socketPath, UNIX_SCHEME)

	_, err := os.Stat(socketPath)
	return err
}
