package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"slices"
	"strings"

	"github.com/xtls/xray-core/app/proxyman/command"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/infra/conf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	DEFAULT_ROUTING_CONFIG_PATH string = "/opt/etc/xray/configs/05_routing.json"
)

func restartXKeen() error {
	if !isXKeenRunning() {
		log.Println("XKeen не запущен, перезапуск не требуется")
		return nil
	}

	cmd := exec.Command("xkeen", "-restart")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func hotReloadConfig(tag string, newConfig []byte) error {
	if !isXKeenRunning() {
		log.Println("XKeen не запущен, обновление outbounds конфига не требуется")
		return nil
	}

	connection, err := getXrayApiConnection()
	if err != nil {
		return fmt.Errorf("Не удалось установить соединение с XRay api: %w", err)
	}
	defer connection.Close()
	client := command.NewHandlerServiceClient(connection)

	currentOutbounds, err := getCurrentOutbounds(client, tag)
	if err != nil {
		return fmt.Errorf("Не удалось получить текущий конфиг outbounds: %w", err)
	}

	newOutbounds, err := parseNewOutbounds(newConfig)
	if err != nil {
		return fmt.Errorf("Не удалось распарсить новый конфиг outbounds: %w", err)
	}

	allTags := make(map[string]struct{})

	for key := range currentOutbounds {
		allTags[key] = struct{}{}
	}

	for key := range newOutbounds {
		allTags[key] = struct{}{}
	}

	for key := range allTags {
		err := processOutboundUpdate(newOutbounds[key], currentOutbounds[key], client)
		if err != nil {
			return fmt.Errorf("Ошибка обновления outbound с тегом %q: %w", key, err)
		}

		log.Printf("Успешное обновление outbound с тегом %q", key)
	}

	return nil
}

func isXKeenRunning() bool {
	err := exec.Command("xkeen", "-status").Run()
	return err == nil
}

func getXrayApiConnection() (*grpc.ClientConn, error) {
	xrayApiAddr, err := getXrayApiAddr()
	if err != nil {
		return nil, err
	}

	return grpc.NewClient(
		xrayApiAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

func getXrayApiAddr() (string, error) {
	routingConfigFile, err := os.Open(DEFAULT_ROUTING_CONFIG_PATH)
	if err != nil {
		return "", err
	}
	defer routingConfigFile.Close()

	routingConfigBytes, err := io.ReadAll(routingConfigFile)
	if err != nil {
		return "", err
	}

	var config conf.Config
	err = json.Unmarshal(routingConfigBytes, &config)
	if err != nil {
		return "", err
	}

	if config.API == nil {
		return "", errors.New("Отсутствует секция \"api\" в конфиге xray")
	}

	if !slices.Contains(config.API.Services, "HandlerService") {
		return "", errors.New("Отсутствует сервис \"HandlerService\" в \"api.services\" в конфиге xray")
	}

	if len(config.API.Listen) == 0 {
		return "", errors.New("Не задан \"api.listen\" в конфиге xray")
	}

	return config.API.Listen, nil
}

func parseNewOutbounds(newConfig []byte) (map[string]*core.OutboundHandlerConfig, error) {
	var config conf.Config
	err := json.Unmarshal(newConfig, &config)
	if err != nil {
		return nil, err
	}

	result := make(map[string]*core.OutboundHandlerConfig)
	for _, c := range config.OutboundConfigs {
		outboundConfig, err := c.Build()
		if err != nil {
			return nil, err
		}

		result[outboundConfig.Tag] = outboundConfig
	}

	return result, nil
}

func getCurrentOutbounds(client command.HandlerServiceClient, tag string) (map[string]*core.OutboundHandlerConfig, error) {
	outboundListResp, err := client.ListOutbounds(context.Background(), &command.ListOutboundsRequest{})
	if err != nil {
		return nil, err
	}

	result := make(map[string]*core.OutboundHandlerConfig)
	for _, outboundConfig := range outboundListResp.Outbounds {
		if strings.HasPrefix(outboundConfig.Tag, tag) {
			result[outboundConfig.Tag] = outboundConfig
		}
	}

	return result, nil
}

func processOutboundUpdate(
	newConfig *core.OutboundHandlerConfig,
	currentConfig *core.OutboundHandlerConfig,
	client command.HandlerServiceClient,
) error {
	if currentConfig != nil {
		_, err := client.RemoveOutbound(context.Background(), &command.RemoveOutboundRequest{
			Tag: currentConfig.Tag,
		})
		if err != nil {
			return err
		}
	}

	if newConfig != nil {
		_, err := client.AddOutbound(context.Background(), &command.AddOutboundRequest{
			Outbound: newConfig,
		})
		if err != nil {
			return err
		}
	}

	return nil
}
