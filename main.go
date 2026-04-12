package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"

	"github.com/spf13/cobra"
)

var version = "dev"

func main() {
	log.SetFlags(log.LstdFlags)
	cmd := newRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	cmd := newRootCmd()
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	cmd.SetArgs(args)
	return cmd.Execute()
}

func newRootCmd() *cobra.Command {
	var (
		outputDir          string
		noRestart          bool
		singleProxy        bool
		realityFingerprint string
		dialerProxies      []string
	)

	cmd := &cobra.Command{
		Use:   "xkeen-subscription-watcher [flags] <tag>=<url> ...",
		Short: "Обработка подписок и генерация конфигураций для Xray",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := buildConfig(args, outputDir, !noRestart, singleProxy, realityFingerprint, dialerProxies)
			if err != nil {
				return err
			}
			return execute(cfg)
		},
	}

	cmd.Flags().StringVar(&outputDir, "output-dir", "/opt/etc/xray/configs",
		"Каталог для сохранения сгенерированных конфигураций.")
	cmd.Flags().BoolVar(&noRestart, "no-restart", false,
		"Не перезапускать XKeen после обновления конфигураций.")
	cmd.Flags().BoolVar(&singleProxy, "single-proxy", false,
		"Брать только первый прокси из подписки и не добавлять имя к тегу.")
	cmd.Flags().StringVar(&realityFingerprint, "reality-fingerprint", "",
		"Переопределить fingerprint для Reality подключений.")
	cmd.Flags().StringSliceVar(&dialerProxies, "dialer-proxies", nil,
		"Dialer proxies через запятую.")

	cmd.AddCommand(newVersionCmd())

	return cmd
}

func getVersion() string {
	if version != "dev" {
		return version
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return version
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Показать версию",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			cmd.Println(getVersion())
		},
	}
}

type config struct {
	subscriptions      []subscription
	outputDir          string
	restartXkeen       bool
	dialerProxies      []string
	singleProxy        bool
	realityFingerprint string
}

type subscription struct {
	tag string
	url string
}

func buildConfig(
	positionalArgs []string,
	outputDir string,
	restartXkeen, singleProxy bool,
	realityFingerprint string,
	dialerProxies []string,
) (config, error) {
	if len(positionalArgs) == 0 {
		return config{}, fmt.Errorf("не указаны подписки. Использование: xkeen-subscription-watcher [флаги] <tag>=<url> ...")
	}

	var subs []subscription
	tags := make(map[string]bool)
	for _, arg := range positionalArgs {
		tag, u, found := strings.Cut(arg, "=")
		if !found {
			return config{}, fmt.Errorf("неверный формат подписки: %q, ожидается <tag>=<url>", arg)
		}
		if tags[tag] {
			return config{}, fmt.Errorf("тег %q указан несколько раз, используйте уникальные имена", tag)
		}
		tags[tag] = true
		if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
			return config{}, fmt.Errorf("неизвестный формат URL: %s, URL должен начинаться на http:// или https://", u)
		}
		subs = append(subs, subscription{tag: tag, url: u})
	}

	info, err := os.Stat(outputDir)
	if err != nil || !info.IsDir() {
		return config{}, fmt.Errorf("указанный путь для --output-dir %s не является директорией", outputDir)
	}

	return config{
		subscriptions:      subs,
		outputDir:          outputDir,
		restartXkeen:       restartXkeen,
		dialerProxies:      dialerProxies,
		singleProxy:        singleProxy,
		realityFingerprint: realityFingerprint,
	}, nil
}

func execute(cfg config) error {
	updated := false
	for _, sub := range cfg.subscriptions {
		changed, err := processSubscription(sub, cfg)
		if err != nil {
			log.Printf("Ошибка при обработке подписки %q, пропускаем: %v", sub.tag, err)
			continue
		}
		if changed {
			updated = true
		}
	}

	if !updated {
		log.Println("Изменений в подписках не найдено, завершаем работу.")
		return nil
	}

	if cfg.restartXkeen {
		log.Println("Перезапускаем XKeen.")
		cmd := exec.Command("xkeen", "-restart")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	return nil
}

func processSubscription(sub subscription, cfg config) (bool, error) {
	outputPath := filepath.Join(cfg.outputDir, fmt.Sprintf("04_outbounds.%s.json", sub.tag))

	outbounds, err := getOutbounds(sub, cfg)
	if err != nil {
		return false, err
	}

	xrayConfig := map[string]any{
		"outbounds": outbounds,
	}

	newContent, err := json.MarshalIndent(xrayConfig, "", "  ")
	if err != nil {
		return false, fmt.Errorf("ошибка сериализации JSON: %w", err)
	}
	newContent = append(newContent, '\n')

	existingContent, err := os.ReadFile(outputPath)
	if err == nil && bytes.Equal(existingContent, newContent) {
		log.Printf("Изменения в подписке %q не найдены, пропускаем.", sub.tag)
		return false, nil
	}

	log.Printf("Записываем новую конфигурацию для подписки %q в %s.", sub.tag, outputPath)
	if err := os.WriteFile(outputPath, newContent, 0644); err != nil {
		return false, fmt.Errorf("ошибка записи файла %s: %w", outputPath, err)
	}

	return true, nil
}

func getOutbounds(sub subscription, cfg config) ([]any, error) {
	log.Printf("Запрашиваем URL подписки: %s.", sub.url)

	proxyURLs, err := fetchProxyURLs(sub)
	if err != nil {
		return nil, err
	}
	sort.Strings(proxyURLs)

	tagCounters := make(map[string]int)
	var result []any

	for _, proxyURL := range proxyURLs {
		p, err := parseProxyURL(proxyURL)
		if err != nil {
			log.Printf("Не удалось распарсить URL прокси %q из подписки %q, пропускаем: %v", proxyURL, sub.tag, err)
			continue
		}

		tag := sub.tag
		if !cfg.singleProxy {
			if name := getProxyName(proxyURL); name != "" {
				tag = tag + "--" + name
			}
		}

		tagCounters[tag]++
		if tagCounters[tag] > 1 {
			tag = fmt.Sprintf("%s--%d", tag, tagCounters[tag])
		}

		result = append(result, generateOutbound(p, tag, cfg.realityFingerprint, ""))
		for _, dp := range cfg.dialerProxies {
			result = append(result, generateOutbound(p, tag+"--"+dp, cfg.realityFingerprint, dp))
		}

		if cfg.singleProxy {
			break
		}
	}

	return result, nil
}
