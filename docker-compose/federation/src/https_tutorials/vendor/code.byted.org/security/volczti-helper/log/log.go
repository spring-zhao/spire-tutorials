package log

import (
	"io"
	"os"

	"github.com/hashicorp/go-hclog"
)

var logger hclog.Logger // hcloger for logging

func init() {
	logger = hclog.New(&hclog.LoggerOptions{
		Name:   "zti-helper-sdk",
		Level:  hclog.LevelFromString("trace"),
		Output: os.Stderr,
	})
}

func InitLogger(logLevel string, logWriter io.Writer) {

	if len(logLevel) == 0 {
		logLevel = "trace"
	}

	if nil == logWriter {
		logWriter = os.Stderr
	}

	logger = hclog.New(&hclog.LoggerOptions{
		Name:            "zti-helper-sdk",
		Level:           hclog.LevelFromString(logLevel),
		Output:          logWriter,
		IncludeLocation: true,
	})

}

// Trace Emit a message and key/value pairs at the TRACE level
func Trace(msg string, args ...interface{}) {
	if logger == nil {
		return
	}

	if len(args) == 0 {
		logger.Trace(msg)
	} else {
		logger.Trace(msg, args...)
	}
}

// Debug Emit a message and key/value pairs at the DEBUG level
func Debug(msg string, args ...interface{}) {
	if logger == nil {
		return
	}

	if len(args) == 0 {
		logger.Debug(msg)
	} else {
		logger.Debug(msg, args...)
	}
}

// Info Emit a message and key/value pairs at the INFO level
func Info(msg string, args ...interface{}) {
	if logger == nil {
		return
	}

	if len(args) == 0 {
		logger.Info(msg)
	} else {
		logger.Info(msg, args...)
	}
}

// Warn Emit a message and key/value pairs at the WARN level
func Warn(msg string, args ...interface{}) {
	if logger == nil {
		return
	}

	if len(args) == 0 {
		logger.Warn(msg)
	} else {
		logger.Warn(msg, args...)
	}
}

// Error Emit a message and key/value pairs at the ERROR level
func Error(msg string, args ...interface{}) {
	if logger == nil {
		return
	}

	if len(args) == 0 {
		logger.Error(msg)
	} else {
		logger.Error(msg, args...)
	}
}
