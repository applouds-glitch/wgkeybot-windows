// Package watchdog решает, мёртв ли туннель, по WireGuard handshake. Решение
// вынесено из winbridge в платформо-нейтральный пакет, чтобы его можно было
// проверить тестами на хосте: winbridge тянет Windows API и на Linux не
// собирается.
package watchdog

import "time"

const (
	// PollInterval — шаг опроса статистики WireGuard.
	PollInterval = 30 * time.Second
	// StaleAfter — возраст handshake, после которого растущий TX без ответа
	// считается мёртвым туннелем.
	StaleAfter = 3 * time.Minute
	// NeverAfter — сколько ждать первого handshake после старта наблюдения
	// (подключения, сна, возврата сети).
	NeverAfter = 150 * time.Second
	// DeadChecksMax — столько опросов подряд туннель должен выглядеть мёртвым.
	DeadChecksMax = 2
	// ResumeGap — опрос, пришедший настолько позже шага, значит, что машина
	// спала: тикер во сне не тикает, и после пробуждения первый тик приходит
	// с разрывом во всю длину сна.
	ResumeGap = 2 * PollInterval
)

// Event — что показал очередной опрос.
type Event int

const (
	// Alive — туннель жив или решать пока рано.
	Alive Event = iota
	// Resumed — машина проснулась: счётчики сброшены, туннелю дан grace.
	Resumed
	// Dead — туннель мёртв, пора переподключаться.
	Dead
)

// Handshake — состояние наблюдения за одним подключением. Не потокобезопасно:
// им владеет одна горутина watchdog'а.
type Handshake struct {
	upSince    time.Time
	graceUntil time.Time
	lastPoll   time.Time
	prevTx     uint64
	prevTxSet  bool
	deadChecks int
	// never — сколько ждать первого handshake от upSince: NeverAfter для
	// подключения, RebuiltGrace для перезапущенного транспорта (Course).
	never time.Duration
}

// New начинает наблюдение за туннелем, поднятым к моменту now.
func New(now time.Time) *Handshake {
	return &Handshake{upSince: now, lastPoll: now, never: NeverAfter}
}

// Hold начинает наблюдение заново: туннель заведомо не может сейчас показать
// handshake (висит капча — прокси ждёт пользователя), и устаревший handshake
// ничего не говорит о его здоровье.
func (h *Handshake) Hold(now time.Time) {
	h.upSince = now
	h.lastPoll = now
	h.prevTxSet = false
	h.deadChecks = 0
}

// Offline — физической сети нет. Туннель без сети не мёртв, а ждёт её:
// переподключение без шлюза только ломает маршруты (в VPN-режиме
// RouteManager без шлюза не создаётся) и оставляет приложение отключённым.
// Пока сети нет, наблюдение стоит; когда она вернётся, у туннеля есть
// NeverAfter, чтобы показать свежий handshake, прежде чем его сочтут мёртвым.
func (h *Handshake) Offline(now time.Time) {
	h.Hold(now)
	h.graceUntil = now.Add(NeverAfter)
}

// Poll оценивает очередной опрос: lastHandshake — время последнего handshake
// (нулевое, если его не было), tx — отправлено байт всего.
func (h *Handshake) Poll(now, lastHandshake time.Time, tx uint64) Event {
	// Разрыв меряется и по монотонным часам, и по стенным: Go на Windows берёт
	// монотонное время из InterruptTime, которое во сне идёт, но стенные часы
	// страхуют от платформы, где это не так. Ложное пробуждение (перевели часы)
	// стоит только лишнего grace.
	gap := now.Sub(h.lastPoll)
	wallGap := now.Round(0).Sub(h.lastPoll.Round(0))
	if gap > ResumeGap || wallGap > ResumeGap {
		h.Offline(now)
		return Resumed
	}
	h.lastPoll = now

	isDead := false
	if lastHandshake.IsZero() {
		isDead = now.Sub(h.upSince) > h.never
	} else if now.Sub(lastHandshake) > StaleAfter {
		isDead = h.prevTxSet && tx > h.prevTx
	}
	h.prevTx = tx
	h.prevTxSet = true
	if !isDead || now.Before(h.graceUntil) {
		h.deadChecks = 0
		return Alive
	}
	h.deadChecks++
	if h.deadChecks >= DeadChecksMax {
		return Dead
	}
	return Alive
}
