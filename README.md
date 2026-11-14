# xkeen-subscription-watcher

[![Test](https://github.com/tkukushkin/xkeen-subscription-watcher/actions/workflows/test.yml/badge.svg)](https://github.com/tkukushkin/xkeen-subscription-watcher/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/tkukushkin/xkeen-subscription-watcher/graph/badge.svg)](https://codecov.io/gh/tkukushkin/xkeen-subscription-watcher)

> [!NOTE]
> Сам я этой утилитой больше не пользуюсь: перешёл в XKeen на ядро
> [mihomo](https://github.com/MetaCubeX/mihomo), которое умеет само отслеживать подписки
> (`proxy-providers`). Рекомендую попробовать его — это не так сложно, как кажется:
> любой AI-ассистент поможет настроить mihomo под ваши задачи.
>
> При этом утилиту я продолжаю поддерживать: если чего-то не хватает или что-то не
> работает, заводите [issue](https://github.com/tkukushkin/xkeen-subscription-watcher/issues).
>
> <details>
> <summary>Пример моего конфига mihomo</summary>
>
> ```yaml
> log-level: silent
>
> mixed-port: 1080
> redir-port: 1182
> tproxy-port: 1181
> allow-lan: true
> find-process-mode: 'off'
>
> external-controller: 0.0.0.0:9090
> external-ui: ui
>
> geo-auto-update: true
> geo-update-interval: 24
>
> proxy-providers:
>   proxy:
>     type: http
>     url: <URL подписки>
>     interval: 3600
>     path: ./proxies/proxy
>
> proxy-groups:
>   - name: PROXY
>     type: select
>     use: [proxy]
>
> rule-providers:
>   refilter-ips:
>     type: http
>     behavior: ipcidr
>     format: text
>     url: "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/ipsum.lst"
>     interval: 86400
>     path: ./rules/refilter-ips
>   refilter-domains:
>     type: http
>     behavior: domain
>     format: text
>     url: "https://github.com/1andrevich/Re-filter-lists/releases/latest/download/domains_all.lst"
>     interval: 86400
>     path: ./rules/refilter-domains
>
> sniffer:
>   enable: true
>   force-dns-mapping: true
>   sniff:
>     HTTP:
>     TLS:
>     QUIC:
>
> rules:
>   # Блокируем небезопасные UDP порты
>   - AND,((NETWORK,udp),(DST-PORT,135/137-139)),REJECT
>   # Блокируем QUIC трафик
>   - AND,((NETWORK,udp),(DST-PORT,443)),REJECT
>   # Блокируем рекламу
>   - GEOSITE,category-ads-all,REJECT
>   # SOCKS5 и HTTP проксируем без исключений
>   - IN-TYPE,socks/http,PROXY
>   # Заблокированные сайты
>   - RULE-SET,refilter-domains,PROXY
>   - GEOSITE,ookla-speedtest,PROXY
>   - GEOSITE,youtube,PROXY
>   - GEOSITE,openai,PROXY
>   - GEOSITE,meta,PROXY
>   - GEOSITE,jetbrains,PROXY
>   - GEOSITE,github,PROXY
>   - GEOSITE,x,PROXY
>   - GEOSITE,notion,PROXY
>   - GEOSITE,tiktok,PROXY
>   - GEOSITE,hashicorp,PROXY
>   - GEOSITE,redis,PROXY
>   - GEOSITE,reddit,PROXY
>   - GEOSITE,tailscale,PROXY
>   - GEOSITE,anthropic,PROXY
>   # Заблокированные IP
>   - RULE-SET,refilter-ips,PROXY
>   # Для тестов
>   - DOMAIN,ifconfig.co,PROXY
>   # Остальной трафик пропускаем напрямую
>   - MATCH,DIRECT
> ```
>
> </details>

## Использование

```bash
xkeen-subscription-watcher --tag <tag> --url '<url>'
```

Скрипт получает из подписки прокси и генерирует конфиг `04_outbounds.<tag>.json`.
Тег `<tag>` становится и префиксом тегов узлов: `<tag>--<имя узла>`.

Если конфиги изменились, изменения применяются к работающему Xray через его API, без
перезапуска XKeen и без разрыва соединений. Трогаются только изменившиеся узлы:
изменённые заменяются, новые добавляются, исчезнувшие удаляются. Для этого в конфиге
Xray должен быть включён API (см. [Настройка Xray](#настройка-xray)).

### Поддерживаемые протоколы

- `vless` (reality / tls / none; транспорты `tcp`, `raw`, `ws`, `httpupgrade`, `grpc`, `xhttp`)
- `vmess` (формат `vmess://base64(JSON)`)
- `trojan`
- `shadowsocks` (`ss`)
- `hysteria2`

Для `vmess` и `trojan` поддерживаются транспорты `tcp`, `raw`, `ws`, `httpupgrade`, `grpc`.
Узлы с транспортами, которые удалены из актуального Xray (`h2`/`http`, `quic`,
`kcp` и т.п.), пропускаются с предупреждением в логе — чтобы один такой узел не
ломал весь конфиг.

### Флаги

- `--tag <tag>` — тег подписки: имя файла `04_outbounds.<tag>.json` и префикс тегов узлов
- `--url <url>` — URL подписки
- `--output-dir <path>` — каталог для конфигов (по умолчанию `/opt/etc/xray/configs`)
- `--no-restart` — только записать конфиги, не применяя их к Xray (для локальной проверки)
- `--single-proxy` — брать только первый прокси из подписки
- `--reality-fingerprint <fp>` — переопределить fingerprint для Reality
- `--dialer-proxies=<proxy1>,<proxy2>` — dialer proxies через запятую
- `--no-hwid` — не отправлять HWID роутера при запросе подписок
- `--include <маска>` — оставить только узлы, имя которых подходит под маску; можно указать несколько раз
- `--exclude <маска>` — отбросить узлы, имя которых подходит под маску; можно указать несколько раз

Маска сравнивается с именем узла целиком, без учёта регистра: `*` — любые символы,
`?` — один символ, `[...]` — один из символов. Маски нужно брать в кавычки:

```bash
xkeen-subscription-watcher --exclude '*Russia*' --exclude '*🇷🇺*' --tag <tag> --url '<url>'
```

## Установка

```shell
curl -sSf https://raw.githubusercontent.com/tkukushkin/xkeen-subscription-watcher/master/install.sh | sh
```

Или вручную — скачать бинарник для своей архитектуры из [Releases](https://github.com/tkukushkin/xkeen-subscription-watcher/releases/latest):

```shell
curl -sSLo /opt/sbin/xkeen-subscription-watcher <url-бинарника>
chmod +x /opt/sbin/xkeen-subscription-watcher
```

### Crontab

```shell
crontab -e
```

Добавляем что-то вроде:

```crontab
0 * * * * /opt/sbin/xkeen-subscription-watcher --tag <tag> --url '<url>'
```

Для нескольких подписок команду добавляем несколько раз, по строке на подписку, каждую
со своими настройками:

```crontab
0 * * * * /opt/sbin/xkeen-subscription-watcher --exclude '*Russia*' --tag <tag1> --url '<url1>'
0 * * * * /opt/sbin/xkeen-subscription-watcher --include '*Germany*' --tag <tag2> --url '<url2>'
```

### Настройка Xray

Включаем API Xray с `HandlerService`, например отдельным файлом `00_api.json`:

```json
{
  "api": {
    "tag": "api",
    "listen": "127.0.0.1:10085",
    "services": ["HandlerService"]
  }
}
```

Без этой секции watcher завершается с ошибкой. После её добавления один раз выполняем
`xkeen -restart`.

Убираем из `04_outbounds.json` прокси, которые будут теперь генерироваться из подписок,
иначе теги будут конфликтовать, оставляем например такое:

```json
{
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom"
    },
    {
      "tag": "block",
      "protocol": "blackhole",
      "response": {
        "type": "HTTP"
      }
    }
  ]
}
```

В `05_routing.json` добавляем конфигурацию `balancers` и `burstObservatory` для автоматического выбора лучшего прокси,
далее в `rules` используем `balancerTag` вместо `outboundTag`, например:

```json
{
  "routing": {
    "domainStrategy": "AsIs",
    "balancers": [
      {
        "tag": "proxy",
        "selector": ["<tag>"],
        "strategy": {
          "type": "leastPing"
        }
      }
    ],
    "rules": [
      {
        "inboundTag": ["socks", "http"],
        "balancerTag": "proxy"
      }
    ]
  },
  "burstObservatory": {
    "subjectSelector": ["<tag>"],
    "pingConfig": {
      "interval": "15s",
      "sampling": 4
    }
  }
}
```

Балансировщик начинает использовать новый узел только после того, как узел пропингован.
С `pingConfig` из примера это занимает до ~2 минут, со значениями по умолчанию — до ~20.

Разово запускаем команду из crontab, проверяем, что всё работает.
