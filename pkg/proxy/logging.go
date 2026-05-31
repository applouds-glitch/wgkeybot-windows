package proxy

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Logging: SetLogFilePath перенаправляет вывод в файл; без пути — stderr.

var (
	logMu       sync.Mutex
	logFile     *os.File
	logTZOffset int
)

func SetLogFilePath(path string) {
	logMu.Lock()
	defer logMu.Unlock()
	if logFile != nil {
		_ = logFile.Close()
		logFile = nil
	}
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	logFile = f
}

func SetTimezoneOffset(offsetSeconds int) {
	logMu.Lock()
	logTZOffset = offsetSeconds
	logMu.Unlock()
}

func logf(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	ts := time.Now().UTC().Add(time.Duration(logTZOffset) * time.Second).Format("15:04:05.000")
	line := fmt.Sprintf("[%s] %s\n", ts, fmt.Sprintf(format, args...))
	if logFile != nil {
		_, _ = logFile.WriteString(line)
	} else {
		_, _ = fmt.Fprint(os.Stderr, line)
	}
}

func turnLog(format string, args ...interface{}) {
	logf(format, args...)
}
