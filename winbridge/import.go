package winbridge

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/wgkeybot/windows/pkg/connlink"
)

var (
	// errTokenNotFound — 404 на /api/v1/init: бот такого токена не выдавал, или
	// его скопировали не целиком.
	errTokenNotFound = errors.New("Токен не найден. Скопируйте его заново в боте: «Подключить устройство» → Windows.")
	// errTokenRefused — 401 на /api/v1/init. Сервер отвечает так только на
	// неактивную подписку устройства, поэтому повторный импорт не поможет — в
	// отличие от 401 на /api/v1/config (ErrUnauthorized).
	errTokenRefused = errors.New("Сервер отклонил токен: подписка этого устройства не активна. Проверьте её в боте.")
	// errServerBadConfig — сервер выдал конфиг, с которым туннель не поднять.
	errServerBadConfig = errors.New("Сервер вернул некорректный конфиг.")
)

// PrepareImport разбирает то, что вставили в диалог импорта, и возвращает конфиг
// с access_token. Всё проверяется до сохранения: неудачный импорт не должен
// заменить рабочий конфиг.
func PrepareImport(raw string) (config []byte, accessToken string, err error) {
	input, err := connlink.Parse(raw)
	if err != nil {
		return nil, "", err
	}
	if input.Embedded != nil {
		// Как у InitFromToken и FetchConfig: хеш того же конфига с сервера совпадёт,
		// и первое обновление не будет рвать туннель ради него же.
		config = []byte(strings.TrimSpace(input.Embedded.Config))
		if !configUsable(config) {
			return nil, "", &connlink.Error{Reason: connlink.FailInvalidConfig}
		}
		return config, input.Embedded.AccessToken, nil
	}
	config, accessToken, err = InitFromToken(input.Token)
	if err != nil {
		return nil, "", err
	}
	if !configUsable(config) {
		return nil, "", errServerBadConfig
	}
	return config, accessToken, nil
}

// initError переводит отказ /api/v1/init на язык того, что с ним делать.
func initError(err error) error {
	var status *statusError
	var transport *url.Error
	switch {
	case errors.Is(err, ErrUnauthorized):
		return errTokenRefused
	case errors.As(err, &status) && status.code == http.StatusNotFound:
		return errTokenNotFound
	case errors.As(err, &transport):
		// Без адреса запроса: в нём токен.
		return fmt.Errorf("Не удалось связаться с сервером: %w.\n\nЕсли сервер недоступен, в боте на экране устройства "+
			"нажмите «🆘 Страница не открывается» и вставьте сюда ссылку с конфигом: она импортируется без сервера.", transport.Err)
	}
	return err
}

// configUsable отвечает, есть ли в конфиге то, без чего туннель не поднять:
// свой ключ и ключ пира.
func configUsable(data []byte) bool {
	cfg, err := parseConfBytes(data, "")
	return err == nil && isWGKey(cfg.PrivateKey) && isWGKey(cfg.PublicKey)
}

func isWGKey(key string) bool {
	raw, err := hex.DecodeString(keyToHex(key))
	return err == nil && len(raw) == 32
}
