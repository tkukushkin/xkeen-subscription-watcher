package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var xrayBinary = "xray"

const (
	xrayAPITimeoutSeconds = 5
	xrayAPICommandTimeout = 15 * time.Second
	xrayDumpTimeout       = 30 * time.Second
)

var errAPINotConfigured = errors.New(`в конфиге Xray не включён API: добавьте секцию "api" с "listen" и "HandlerService" в "services", например {"api": {"tag": "api", "listen": "127.0.0.1:10085", "services": ["HandlerService"]}}`)

// runXray запускает xray с таймаутом и возвращает stdout. В ошибку попадают аргументы,
// stdout и stderr.
func runXray(timeout time.Duration, stdin []byte, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, xrayBinary, args...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		output := strings.TrimSpace(strings.TrimSpace(stdout.String()) + "\n" + strings.TrimSpace(stderr.String()))
		return nil, fmt.Errorf("%s %s: %w: %s", xrayBinary, strings.Join(args, " "), err, output)
	}
	return stdout.Bytes(), nil
}

// findAPIAddress возвращает api.listen из объединённого конфига confdir, если в api.services
// есть HandlerService.
func findAPIAddress(confdir string) (string, error) {
	out, err := runXray(xrayDumpTimeout, nil, "run", "-dump", "-confdir", confdir)
	if err != nil {
		return "", fmt.Errorf("не удалось прочитать конфиг Xray: %w", err)
	}

	var cfg struct {
		API *struct {
			Listen   string   `json:"listen"`
			Services []string `json:"services"`
		} `json:"api"`
	}
	if err := json.Unmarshal(out, &cfg); err != nil {
		return "", fmt.Errorf("не удалось разобрать конфиг Xray: %w", err)
	}
	if cfg.API == nil || cfg.API.Listen == "" {
		return "", errAPINotConfigured
	}
	for _, service := range cfg.API.Services {
		if strings.EqualFold(service, "HandlerService") {
			return cfg.API.Listen, nil
		}
	}
	return "", errAPINotConfigured
}

type xrayAPI struct {
	addr string
}

func (a xrayAPI) run(stdin []byte, command string) error {
	_, err := runXray(xrayAPICommandTimeout, stdin,
		"api", command, "-s", a.addr, "-t", strconv.Itoa(xrayAPITimeoutSeconds), "stdin:")
	return err
}

func (a xrayAPI) addOutbound(outbound map[string]any) error {
	stdin, err := json.Marshal(map[string]any{"outbounds": []any{outbound}})
	if err != nil {
		return err
	}
	return a.run(stdin, "ado")
}

func (a xrayAPI) removeOutbound(tag string) error {
	stdin, err := json.Marshal(map[string]any{"outbounds": []any{map[string]any{"tag": tag}}})
	if err != nil {
		return err
	}
	return a.run(stdin, "rmo")
}
