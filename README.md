# xkeen-subscription-watcher

## Использование

```bash
xkeen-subscription-watcher <tag>=<url>
```

Можно передать несколько пар `<tag>=<url>`

Скрипт получает из переданных подписок прокси, генерирует конфиг `04_outbounds.generated.json`. От каждой подписки берется только один прокси.

Если конфиг изменился, выполняется `xkeen -restart`.

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
 
Убираем из 04_outbounds.json прокси, которые будут теперь генерироваться из подписок, иначе теги будут конфликтовать,
оставляем например такое:

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

Разово запускаем команду из crontab, проверяем, что всё работает.
