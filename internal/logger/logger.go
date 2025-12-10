package logger

import (
	"fmt"
	"io"
	"os"
	"time"
)

// LogLevel represents the severity of a log message
type LogLevel int

const (
	LevelDebug LogLevel = iota
	LevelInfo
	LevelError
)

// Logger handles logging to stderr
type Logger struct {
	level  LogLevel
	output io.Writer
}

// New creates a new logger that writes to stderr
func New(level LogLevel) *Logger {
	return &Logger{
		level:  level,
		output: os.Stderr,
	}
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// Debug logs a debug message to stderr
func (l *Logger) Debug(format string, args ...interface{}) {
	if l.level <= LevelDebug {
		l.log("DEBUG", format, args...)
	}
}

// Info logs an info message to stderr
func (l *Logger) Info(format string, args ...interface{}) {
	if l.level <= LevelInfo {
		l.log("INFO", format, args...)
	}
}

// Error logs an error message to stderr
func (l *Logger) Error(format string, args ...interface{}) {
	if l.level <= LevelError {
		l.log("ERROR", format, args...)
	}
}

// log writes a formatted log message to stderr
func (l *Logger) log(level string, format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")
	message := fmt.Sprintf(format, args...)
	fmt.Fprintf(l.output, "[%s] %s: %s\n", timestamp, level, message)
}

// Default logger instance
var defaultLogger = New(LevelInfo)

// Debug logs a debug message using the default logger
func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

// Info logs an info message using the default logger
func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

// Error logs an error message using the default logger
func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

// SetLevel sets the log level for the default logger
func SetLevel(level LogLevel) {
	defaultLogger.SetLevel(level)
}

// ParseLogLevel parses a string log level and returns the corresponding LogLevel
// Valid values: "debug", "info", "error" (case-insensitive)
// Returns LevelInfo as default if the string is invalid
func ParseLogLevel(levelStr string) LogLevel {
	switch levelStr {
	case "debug", "DEBUG", "Debug":
		return LevelDebug
	case "info", "INFO", "Info":
		return LevelInfo
	case "error", "ERROR", "Error":
		return LevelError
	default:
		return LevelInfo // Default to Info
	}
}
