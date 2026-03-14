# xkeen-subscription-watcher

## Использование

```bash
xkeen-subscription-watcher <tag>=<url>
```

Можно передать несколько пар `<tag>=<url>`

Скрипт получает из переданных подписок прокси, генерирует конфиги `04_outbounds.<tag>.json`.

Если конфиги изменились, выполняется `xkeen -restart`.

## Установка

```shell
opkg install python3
curl -sSo /opt/sbin/xkeen-subscription-watcher https://raw.githubusercontent.com/tkukushkin/xkeen-subscription-watcher/refs/heads/master/src/xkeen_subscription_watcher/main.py
chmod +x /opt/sbin/xkeen-subscription-watcher
crontab -e
```

Добавляем что-то вроде:

```crontab
0 * * * * /opt/sbin/xkeen-subscription-watcher <tag>=<url>
```

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
