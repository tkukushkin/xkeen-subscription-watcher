# xkeen-subscription-watcher

[![Test](https://github.com/tkukushkin/xkeen-subscription-watcher/actions/workflows/test.yml/badge.svg)](https://github.com/tkukushkin/xkeen-subscription-watcher/actions/workflows/test.yml)
[![codecov](https://codecov.io/gh/tkukushkin/xkeen-subscription-watcher/graph/badge.svg)](https://codecov.io/gh/tkukushkin/xkeen-subscription-watcher)

## Использование

```bash
xkeen-subscription-watcher --tag <tag> --url '<url>'
```

Скрипт получает из подписки прокси и генерирует конфиг `04_outbounds.<tag>.json`.
Тег `<tag>` становится и префиксом тегов узлов: `<tag>--<имя узла>`.

Для совместимости поддерживается и прежняя форма с несколькими подписками в одном
запуске: `xkeen-subscription-watcher <tag1>=<url1> <tag2>=<url2>`.

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
