package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"reflect"
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
		noHWID             bool
		include            []string
		exclude            []string
		tagFlag            string
		urlFlag            string
	)

	cmd := &cobra.Command{
		Use:   "xkeen-subscription-watcher [flags] --tag <tag> --url <url> | <tag>=<url> ...",
		Short: "Обработка подписок и генерация конфигураций для Xray",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := subscriptionArgs(args, tagFlag, urlFlag)
			if err != nil {
				return err
			}
			cfg, err := buildConfig(args, outputDir, !noRestart, singleProxy, realityFingerprint, dialerProxies)
			if err != nil {
				return err
			}
			cfg.sendHWID = !noHWID
			if cfg.filter, err = newNameFilter(include, exclude); err != nil {
				return err
			}
			return execute(cfg)
		},
	}

	cmd.Flags().StringVar(&tagFlag, "tag", "",
		"Тег подписки: имя файла 04_outbounds.<tag>.json и префикс тегов узлов. Указывается вместе с --url.")
	cmd.Flags().StringVar(&urlFlag, "url", "",
		"URL подписки. Указывается вместе с --tag.")
	cmd.Flags().StringVar(&outputDir, "output-dir", "/opt/etc/xray/configs",
		"Каталог для сохранения сгенерированных конфигураций.")
	cmd.Flags().BoolVar(&noRestart, "no-restart", false,
		"Только записать конфигурации, не применяя их к Xray.")
	cmd.Flags().BoolVar(&singleProxy, "single-proxy", false,
		"Брать только первый прокси из подписки и не добавлять имя к тегу.")
	cmd.Flags().StringVar(&realityFingerprint, "reality-fingerprint", "",
		"Переопределить fingerprint для Reality подключений.")
	cmd.Flags().StringSliceVar(&dialerProxies, "dialer-proxies", nil,
		"Dialer proxies через запятую.")
	cmd.Flags().BoolVar(&noHWID, "no-hwid", false,
		"Не отправлять HWID роутера при запросе подписок.")
	cmd.Flags().StringArrayVar(&include, "include", nil,
		"Оставить только узлы, имя которых подходит под маску (*, ?, [...]); можно указать несколько раз.")
	cmd.Flags().StringArrayVar(&exclude, "exclude", nil,
		"Отбросить узлы, имя которых подходит под маску (*, ?, [...]); можно указать несколько раз.")

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

// subscriptionArgs возвращает подписки в виде <tag>=<url>: из --tag и --url, если они заданы,
// иначе из позиционных аргументов.
func subscriptionArgs(positionalArgs []string, tag, url string) ([]string, error) {
	if tag == "" && url == "" {
		return positionalArgs, nil
	}
	if tag == "" || url == "" {
		return nil, fmt.Errorf("--tag и --url нужно указывать вместе")
	}
	if len(positionalArgs) > 0 {
		return nil, fmt.Errorf("--tag и --url нельзя совмещать с подписками в виде <tag>=<url>")
	}
	if strings.Contains(tag, "=") {
		return nil, fmt.Errorf("--tag не может содержать «=»: %q", tag)
	}
	return []string{tag + "=" + url}, nil
}

type config struct {
	subscriptions      []subscription
	outputDir          string
	applyToXray        bool
	dialerProxies      []string
	singleProxy        bool
	realityFingerprint string
	sendHWID           bool
	device             *deviceInfo
	filter             nameFilter
}

type subscription struct {
	tag string
	url string
}

func buildConfig(
	positionalArgs []string,
	outputDir string,
	applyToXray, singleProxy bool,
	realityFingerprint string,
	dialerProxies []string,
) (config, error) {
	if len(positionalArgs) == 0 {
		return config{}, fmt.Errorf("не указана подписка. Использование: xkeen-subscription-watcher [флаги] --tag <tag> --url <url>")
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
		applyToXray:        applyToXray,
		dialerProxies:      dialerProxies,
		singleProxy:        singleProxy,
		realityFingerprint: realityFingerprint,
	}, nil
}

type pendingUpdate struct {
	sub        subscription
	path       string
	oldContent []byte
	newContent []byte
}

func (u *pendingUpdate) write(content []byte) error {
	log.Printf("Записываем конфигурацию подписки %q в %s.", u.sub.tag, u.path)
	if err := writeFileAtomic(u.path, content); err != nil {
		return fmt.Errorf("ошибка записи файла %s: %w", u.path, err)
	}
	return nil
}

// writeFileAtomic пишет содержимое во временный файл рядом с path и переименовывает его в
// path. Имя временного файла оканчивается на .tmp, поэтому Xray его не читает.
func writeFileAtomic(path string, content []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)

	if _, err := tmp.Write(content); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmpPath, 0644); err != nil {
		return err
	}
	return os.Rename(tmpPath, path)
}

func execute(cfg config) error {
	if cfg.sendHWID {
		device, err := fetchDeviceInfo()
		if err != nil {
			return fmt.Errorf("не удалось получить HWID роутера, используйте --no-hwid: %w", err)
		}
		log.Printf("Отправляем HWID роутера: %s.", device.HWID)
		cfg.device = device
	}

	var updates []*pendingUpdate
	for _, sub := range cfg.subscriptions {
		update, err := prepareUpdate(sub, cfg)
		if err != nil {
			log.Printf("Ошибка при обработке подписки %q, пропускаем: %v", sub.tag, err)
			continue
		}
		if update != nil {
			updates = append(updates, update)
		}
	}

	if len(updates) == 0 {
		log.Println("Изменений в подписках не найдено, завершаем работу.")
		return nil
	}

	if !cfg.applyToXray {
		for _, update := range updates {
			if err := update.write(update.newContent); err != nil {
				log.Printf("Ошибка при обработке подписки %q: %v", update.sub.tag, err)
			}
		}
		return nil
	}

	addr, err := findAPIAddress(cfg.outputDir)
	if err != nil {
		return err
	}
	api := xrayAPI{addr: addr}

	var errs []error
	for _, update := range updates {
		if err := applyUpdate(api, update); err != nil {
			errs = append(errs, fmt.Errorf("подписка %q: %w", update.sub.tag, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("не удалось применить изменения подписок:\n%w", errors.Join(errs...))
	}
	return nil
}

func applyUpdate(api outboundAPI, update *pendingUpdate) error {
	oldOutbounds, err := parseOutboundsFile(update.oldContent)
	if err != nil {
		return fmt.Errorf("ошибка разбора файла %s: %w", update.path, err)
	}
	newOutbounds, err := parseOutboundsFile(update.newContent)
	if err != nil {
		return fmt.Errorf("ошибка разбора новой конфигурации: %w", err)
	}
	changes := diffOutbounds(oldOutbounds, newOutbounds)
	log.Printf("Применяем изменения подписки %q к Xray: %d добавлено или изменено, %d удалено.",
		update.sub.tag, len(changes.upserts), len(changes.removals))
	failed, applyErr := applyChanges(api, changes)
	if applyErr == nil {
		return update.write(update.newContent)
	}

	appliedList := appliedOutbounds(oldOutbounds, newOutbounds, failed)
	if reflect.DeepEqual(outboundsByTag(appliedList), outboundsByTag(oldOutbounds)) {
		return applyErr
	}
	applied, err := marshalOutbounds(appliedList)
	if err != nil {
		return errors.Join(applyErr, err)
	}
	log.Printf("Изменения подписки %q применены частично, сохраняем применённую часть.", update.sub.tag)
	if err := update.write(applied); err != nil {
		return errors.Join(applyErr, err)
	}
	return applyErr
}

// prepareUpdate получает подписку и генерирует новое содержимое файла, ничего не записывая.
// Возвращает nil, если содержимое не изменилось.
func prepareUpdate(sub subscription, cfg config) (*pendingUpdate, error) {
	outputPath := filepath.Join(cfg.outputDir, fmt.Sprintf("04_outbounds.%s.json", sub.tag))

	outbounds, err := getOutbounds(sub, cfg)
	if err != nil {
		return nil, err
	}

	newContent, err := marshalOutbounds(outbounds)
	if err != nil {
		return nil, err
	}

	existingContent, err := os.ReadFile(outputPath)
	if err != nil {
		existingContent = nil
	} else if bytes.Equal(existingContent, newContent) {
		log.Printf("Изменения в подписке %q не найдены, пропускаем.", sub.tag)
		return nil, nil
	}

	return &pendingUpdate{
		sub:        sub,
		path:       outputPath,
		oldContent: existingContent,
		newContent: newContent,
	}, nil
}

func getOutbounds(sub subscription, cfg config) ([]any, error) {
	log.Printf("Запрашиваем URL подписки: %s.", sub.url)

	proxyURLs, err := fetchProxyURLs(sub, cfg.device)
	if err != nil {
		return nil, err
	}
	sort.Strings(proxyURLs)

	tagCounters := make(map[string]int)
	var result []any

	filtered := 0
	for _, proxyURL := range proxyURLs {
		if !cfg.filter.allows(rawProxyName(proxyURL)) {
			filtered++
			continue
		}

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

	if filtered > 0 {
		log.Printf("В подписке %q отфильтровано узлов по --include/--exclude: %d.", sub.tag, filtered)
	}
	return result, nil
}
