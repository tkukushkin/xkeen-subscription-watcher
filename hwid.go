package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

var rciBaseURL = "http://127.0.0.1:79/rci"

const rciTimeout = 5 * time.Second

// deviceInfo — данные роутера, которые отправляются провайдеру в заголовках запроса подписки.
type deviceInfo struct {
	HWID      string
	OS        string
	OSVersion string
	Model     string
}

func (d *deviceInfo) setHeaders(h http.Header) {
	for name, value := range map[string]string{
		"x-hwid":         d.HWID,
		"x-device-os":    d.OS,
		"x-ver-os":       d.OSVersion,
		"x-device-model": d.Model,
	} {
		if value != "" {
			h.Set(name, value)
		}
	}
}

func rciGet(path string, target any) error {
	client := &http.Client{Timeout: rciTimeout}
	resp, err := client.Get(rciBaseURL + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", path, resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// fetchDeviceInfo получает данные роутера из RCI Keenetic. Серийный номер обязателен,
// остальные поля — нет.
func fetchDeviceInfo() (*deviceInfo, error) {
	var identification struct {
		Serial string `json:"serial"`
	}
	if err := rciGet("/show/identification", &identification); err != nil {
		return nil, err
	}
	if identification.Serial == "" {
		return nil, fmt.Errorf("/show/identification: пустой serial")
	}
	device := &deviceInfo{HWID: hwidFromSerial(identification.Serial)}

	var version struct {
		Vendor      string `json:"vendor"`
		Title       string `json:"title"`
		Description string `json:"description"`
	}
	if err := rciGet("/show/version", &version); err != nil {
		log.Printf("Не удалось получить версию роутера, отправляем только x-hwid: %v", err)
	} else {
		device.OS = version.Vendor
		device.OSVersion = version.Title
		device.Model = version.Description
	}
	return device, nil
}

// hwidFromSerial возвращает UUID версии 8 из SHA-256 серийного номера роутера.
func hwidFromSerial(serial string) string {
	hash := sha256.Sum256([]byte("xkeen-subscription-watcher:" + serial))
	b := hash[:16]
	b[6] = (b[6] & 0x0f) | 0x80
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
