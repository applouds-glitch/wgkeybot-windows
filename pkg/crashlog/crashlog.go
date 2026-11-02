// Package crashlog направляет паники и fatal error рантайма Go в файл.
//
// Сборка с -H windowsgui консоли не имеет, а журнал пишется только с --debug:
// паника в любой горутине прокси или трея убивала процесс молча — иконка
// пропадала из трея, и от причины не оставалось ничего. debug.SetCrashOutput
// дублирует дескриптор файла и пишет туда тот же текст, что рантайм отдал бы в
// stderr: сообщение паники и стек. Восстановленные recover паники и обычные
// строки журнала сюда не попадают. Порт идеи iOS 06b85b9.
package crashlog

import (
	"os"
	"runtime/debug"
)

// Open направляет вывод паник Go в path. Файл, выросший больше limit, перед
// этим уезжает в path+".old" (прежний .old заменяется); limit <= 0 — файл не
// трогать, им владеет журнал. Вызывать один раз при старте процесса, как можно
// раньше: паника до вызова уходит в никуда.
//
// Ротация — только здесь, при старте: на Windows файл, открытый обычным
// os.OpenFile (без FILE_SHARE_DELETE), не переименовать, пока его держит
// дубликат дескриптора в рантайме.
func Open(path string, limit int64) error {
	if limit > 0 {
		if fi, err := os.Stat(path); err == nil && fi.Size() > limit {
			_ = os.Rename(path, path+".old")
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	// SetCrashOutput держит свой дубликат дескриптора: этот можно закрыть сразу.
	defer f.Close()
	return debug.SetCrashOutput(f, debug.CrashOptions{})
}
