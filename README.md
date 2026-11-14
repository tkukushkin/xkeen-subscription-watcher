# xkeen-subscription-watcher

[![Test](https://github.com/tkukushkin/xkeen-subscription-watcher/actions/workflows/test.yml/badge.svg)](https://github.com/tkukushkin/xkeen-subscription-watcher/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/tkukushkin/xkeen-subscription-watcher/graph/badge.svg)](https://codecov.io/gh/tkukushkin/xkeen-subscription-watcher)

## Использование

```bash
xkeen-subscription-watcher <tag>=<url>
```

Можно передать несколько пар `<tag>=<url>`

Скрипт получает из переданных подписок прокси, генерирует конфиги `04_outbounds.<tag>.json`.

Если конфиги изменились, изменения применяются к работающему Xray через его API, без
перезапуска XKeen и без разрыва соединений. Трогаются только изменившиеся узлы:
изменённые заменяются, новые добавляются, исчезнувшие удаляются. Для этого в конфиге
Xray должен быть включён API (см. [Настройка Xray](#настройка-xray)).

### Поддерживаемые протоколы

- `vless` (reality / tls / none; транспорты `tcp`, `raw`, `ws`, `grpc`, `xhttp`)
- `vmess` (формат `vmess://base64(JSON)`)
- `trojan`
- `shadowsocks` (`ss`)
- `hysteria2`

Для `vmess` и `trojan` поддерживаются транспорты `tcp`, `raw`, `ws`, `grpc`.
Узлы с транспортами, которые удалены из актуального Xray (`h2`/`http`, `quic`,
`kcp` и т.п.), пропускаются с предупреждением в логе — чтобы один такой узел не
ломал весь конфиг.

### Флаги

- `--output-dir <path>` — каталог для конфигов (по умолчанию `/opt/etc/xray/configs`)
- `--no-restart` — только записать конфиги, не применяя их к Xray (для локальной проверки)
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
`xkeen -restart`: API начинает слушать только при старте Xray, до этого каждый запуск
watcher будет падать по таймауту.

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

Балансировщик `leastPing` выбирает только из узлов, которые `burstObservatory` уже
пропинговал. Узел, добавленный без перезапуска, получает первый пинг только в следующем
раунде, а раунд длится `interval × sampling`. С настройками выше это 1 минута, и новые
узлы подхватываются в пределах ~2 минут. С `"pingConfig": {}` раунд длится 10 минут, и
ждать придётся до ~20. Это важно, когда провайдер переименовывает все узлы: пока ни
один новый узел не пропингован, балансировщику не из чего выбирать. Изменённые узлы с
прежним именем не страдают, результаты их пингов сохраняются. `fallbackTag` для этого
не рекомендуем.

Разово запускаем команду из crontab, проверяем, что всё работает.

## Обновление с прежних версий

Раньше при изменении подписок выполнялся `xkeen -restart`. Теперь изменения применяются
через API Xray, а без секции `api` watcher завершается с ошибкой. При обновлении:

1. Добавить секцию `api` с `HandlerService` (см. [Настройка Xray](#настройка-xray)).
2. Один раз выполнить `xkeen -restart`.
3. По желанию уменьшить `pingConfig` у `burstObservatory`, как в примере выше.
