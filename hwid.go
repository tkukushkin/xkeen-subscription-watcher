package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type VersionInfo struct {
	Release     string `json:"release"`
	Title       string `json:"title"`
	Arch        string `json:"arch"`
	Model       string `json:"model"`
	HwID        string `json:"hw_id"`
	Vendor      string `json:"vendor"`
	Description string `json:"description"`
}

type IdentificationInfo struct {
	Serial     string `json:"serial"`
	MAC        string `json:"mac"`
	ServiceTag string `json:"servicetag"`
	CID        string `json:"cid"`
}

type HardwareInfo struct {
	HWID        string `json:"hwid"`
	DeviceOS    string `json:"platform"`
	VersionOS   string `json:"osversion"`
	DeviceModel string `json:"model"`
}

func loadHardwareInfo(path string) (*HardwareInfo, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p HardwareInfo
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	return &p, nil
}

func saveHardwareInfo(path string, p *HardwareInfo) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

func FetchHardwareInfo(cacheDir string, noCacheHWID bool) (*HardwareInfo, error) {
	fullPath := filepath.Join(cacheDir, "hwinfo.json")
	var hwinfo *HardwareInfo
	var loadCacheErr error
	// ignore cached data if the user wants it
	if !noCacheHWID {
		hwinfo, loadCacheErr = loadHardwareInfo(fullPath)
		if loadCacheErr == nil {
			log.Printf("Используется кеш HWID: %s", fullPath)
		}
	}
	if noCacheHWID || loadCacheErr != nil {
		log.Printf("Чтение HWID из RCI...")
		rciInfo, err := fetchHardwareInfo()
		if err != nil {
			log.Printf("Ошибка чтения HWID из RCI %v", err)
			return nil, err
		}
		hwid := rciInfo.hardwareID()
		if hwid == "" {
			log.Printf("Невозможно получить HWID из RCI, нет необходимых данных. Используйте --no-hwid")
			return nil, fmt.Errorf("невозможно получить HWID, нет данных")
		}
		hwinfo = &HardwareInfo{
			HWID:        hwid,
			DeviceOS:    rciInfo.Version.Vendor,
			VersionOS:   rciInfo.Version.Title,
			DeviceModel: rciInfo.Version.Description,
		}
		if !noCacheHWID {
			// save only if no --no-cache-hwid provided
			_ = saveHardwareInfo(fullPath, hwinfo)
		}
	}
	return hwinfo, nil
}

type rciHardwareInfo struct {
	Version VersionInfo
	ID      IdentificationInfo
}

func rciGet(path string, target any) error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:79/rci" + path)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(target)
}

func fetchHardwareInfo() (*rciHardwareInfo, error) {
	var ri rciHardwareInfo

	if err := rciGet("/show/version", &ri.Version); err != nil {
		return nil, fmt.Errorf("show/version: %w", err)
	}
	if err := rciGet("/show/identification", &ri.ID); err != nil {
		return nil, fmt.Errorf("show/identification: %w", err)
	}

	return &ri, nil
}

// uuidFromSeed returns a SHA‑256 derived UUID string.
func uuidFromSeed(s string) string {
	hash := sha256.Sum256([]byte(s))
	// Truncate hash
	b := hash[:16]
	// Version 5 (SHA-based) and RFC 4122
	b[6] = (b[6] & 0x0f) | 0x50 // version 5
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// hardwareID returns a SHA‑based UUID string from router version and ID data, fetched from RCI interface.
// Format is uuid(sha256("xkeen_hwid_"+uuid(sha256(vendor|arch|serial|mac"))))
// Must not be empty 'serial' or 'mac'.
func (ri *rciHardwareInfo) hardwareID() string {
	if ri.ID.Serial == "" && ri.ID.MAC == "" {
		// bail out if can't identify Keenetic device
		return ""
	}
	hwStr := ""
	if ri.Version.Vendor != "" {
		hwStr += ri.Version.Vendor + "|"
	}
	if ri.Version.Arch != "" {
		hwStr += ri.Version.Arch + "|"
	}
	if ri.ID.Serial != "" {
		hwStr += ri.ID.Serial + "|"
	}
	if ri.ID.MAC != "" {
		hwStr += ri.ID.MAC + "|"
	}
	hwStr = "xkeen_hwid_" + uuidFromSeed(hwStr)
	return uuidFromSeed(hwStr)
}
