# Port Scanner

Python портовый сканер с поддержкой TCP/UDP и определением протоколов.

## Использование

```bash
portscan [OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...
```

## Опции

- `-t, --timeout` - таймаут в секундах (по умолчанию: 2.0)
- `-v, --verbose` - подробный вывод
- `-g, --guess` - определение протокола (HTTP, ECHO, DNS)

## Примеры

```bash
portscan 192.168.1.1 tcp/80,443
portscan 192.168.1.1 udp/53 -g DNS -v
portscan 192.168.1.1 tcp/1-1000 udp/53,161
portscan 192.168.1.1 tcp -g HTTP
```

## Установка

```bash
pip install scapy
```

**Примечание:** Используйте только для легального тестирования сетей.