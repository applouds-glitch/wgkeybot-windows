package proxy

import (
	"fmt"
	"os"
	"sync"
	"time"
)

// Logging: SetLogFilePath перенаправляет вывод в файл; без пути — stderr.

var (
	logMu   sync.Mutex
	logFile *os.File
	// logLoc — часовой пояс меток времени. По умолчанию локальный: тем же
	// поясом стандартный log пишет строки winbridge и tray в тот же файл, и
	// раньше строки прокси шли в UTC вперемешку с ними — на машине в MSK три
	// часа разницы внутри одного лога. SetTimezoneOffset — для хоста, у которого
	// time.Local не настоящий (так было заведено для Android).
	logLoc = time.Local
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
	logLoc = time.FixedZone("", offsetSeconds)
	logMu.Unlock()
}

// logClock переводит t в часовой пояс лога — для времени, которое печатается в
// теле сообщения, чтобы оно не расходилось с меткой строки.
func logClock(t time.Time) time.Time {
	logMu.Lock()
	defer logMu.Unlock()
	return t.In(logLoc)
}

func logf(format string, args ...any) {
	logMu.Lock()
	defer logMu.Unlock()
	ts := time.Now().In(logLoc).Format("15:04:05.000")
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
