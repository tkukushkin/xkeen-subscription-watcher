# xkeen-subscription-watcher

[![Test](https://github.com/tkukushkin/xkeen-subscription-watcher/actions/workflows/test.yml/badge.svg)](https://github.com/tkukushkin/xkeen-subscription-watcher/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/tkukushkin/xkeen-subscription-watcher/graph/badge.svg)](https://codecov.io/gh/tkukushkin/xkeen-subscription-watcher)

## Использование

```bash
xkeen-subscription-watcher <tag>=<url>
```

Можно передать несколько пар `<tag>=<url>`

Скрипт получает из переданных подписок прокси, генерирует конфиги `04_outbounds.<tag>.json`.

Если конфиги изменились, выполняется `xkeen -restart`.

### Флаги

- `--output-dir <path>` — каталог для конфигов (по умолчанию `/opt/etc/xray/configs`)
- `--no-restart` — не перезапускать XKeen после обновления
- `--single-proxy` — брать только первый прокси из подписки
- `--reality-fingerprint <fp>` — переопределить fingerprint для Reality
- `--dialer-proxies=<proxy1>,<proxy2>` — dialer proxies через запятую

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
0 * * * * /opt/sbin/xkeen-subscription-watcher <tag>=<url>
```

### Настройка Xray

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
    "pingConfig": {}
  }
}
```

Разово запускаем команду из crontab, проверяем, что всё работает.
