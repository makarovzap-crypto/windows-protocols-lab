# Windows Protocols Lab

Стенд для исследования сетевых протоколов Windows (SMB, WebDAV, LDAP, RDP, WinRM, WMI,
PowerShell Remoting Protocol) с помощью анализатора пакетов Wireshark.

Стенд воспроизводит типовой обмен по каждому протоколу в открытом и защищённом (TLS)
вариантах и записывает трафик в файл захвата `.pcap`. Встроенный анализатор показывает,
что видит сторонний наблюдатель: учётные данные, команды, содержимое файлов, структуру
каталога. Для защищённых соединений он показывает только параметры TLS.

## Требования к среде

- Python 3.10 или новее (проверено на 3.12 и 3.14);
- Windows 10, 11 или Windows Server 2016 и новее для всех сценариев. В Linux, macOS и Docker
  работают все сценарии, кроме `wmi_dcom`;
- Wireshark 4.x — для просмотра файла захвата (необязательно, анализатор работает без него);
- Docker 20+ — только для запуска в контейнере;
- свободные TCP-порты 13389–28443 на 127.0.0.1 (список выводит `python main.py list`);
- около 100 МБ на диске для виртуального окружения Python.

Зависимости Python (`requirements.txt`): `impacket`, `ldap3`, `cryptography`, `pytest`.

## Архитектура

```
 клиентские сценарии ──► записывающий прокси ──► учебные серверы (127.0.0.1)
  (Impacket, ldap3,       (stand/recorder.py)     SMB, WebDAV, LDAP, RDP, WinRM
   http.client, ssl)              │                + служба RPC Windows (порт 135)
                                  ▼
               output/windows_protocols.pcap ──► Wireshark
                                  │
                                  ▼
               анализатор (stand/analysis) ──► output/report.md, report.json
```

- **Учебные серверы** (`stand/servers`) реализуют нужную для демонстрации часть протоколов.
- **Записывающий прокси** пересылает байты между клиентом и сервером и записывает их в pcap
  как TCP-соединение `192.168.56.10 (WS01) → 192.168.56.2 (DC01)` на стандартном порту
  протокола. Wireshark сразу применяет нужные диссекторы. Драйвер Npcap и права
  администратора не нужны.
- **Анализатор** (`stand/analysis`) собирает TCP-потоки, определяет протокол и ищет данные,
  передаваемые в открытом виде. Работает и с файлами `.pcapng` из Wireshark.

Структура проекта:

```
windows-protocols-lab/
├── main.py                 точка входа (run / analyze / list)
├── requirements.txt
├── Makefile, build.sh, build.ps1, Dockerfile, .dockerignore
├── stand/
│   ├── config.py           учётные данные, порты, виртуальная сеть
│   ├── pcap.py             запись и чтение pcap/pcapng, модель TCP
│   ├── recorder.py         записывающий TCP-прокси
│   ├── tls.py              сертификат и контексты TLS, журнал ключей
│   ├── ber.py              кодирование BER (LDAP)
│   ├── psrp.py             сообщения PowerShell Remoting Protocol
│   ├── wsman.py            SOAP-конверты WS-Management
│   ├── scenarios.py        клиентские сценарии
│   ├── runner.py           запуск серверов, прокси и сценариев
│   ├── servers/            smb, webdav, ldap_server, rdp, winrm, http_common
│   └── analysis/           streams, inspectors, model (анализатор)
└── tests/
    ├── test_units.py       модульные тесты
    └── test_integration.py интеграционные тесты
```

## Пошаговая установка и запуск

### Шаг 1. Клонирование проекта

    git clone https://github.com/makarovzap-crypto/windows-protocols-lab.git
    cd windows-protocols-lab

### Шаг 2. Установка зависимостей

Windows (PowerShell):

    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt

Linux/macOS:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

Те же действия выполняет `build.ps1 install` или `./build.sh install`.

### Шаг 3. Проверка тестами

    python -m pytest -v

Ожидаемый результат: `22 passed`.

### Шаг 4. Запуск стенда

    python main.py run

Сценарии выполняются примерно за 5 секунд. Результаты сохраняются в каталог `output`.

### Шаг 5. Просмотр в Wireshark

Откройте `output/windows_protocols.pcap` (*File → Open*). Чтобы расшифровать TLS, укажите
`output/tls_keys.log` в *Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename*.

### Шаг 6. Очистка

    powershell -ExecutionPolicy Bypass -File build.ps1 clean     # или: make clean

## Сценарии и примеры использования

Все сценарии выполняются командой `python main.py run`, выбранные — ключом `--only`.
Тестовая учётная запись: `LAB\student`, пароль `P@ssw0rd2026` (`stand/config.py`).

### Сценарий 1. SMB2 без шифрования (`smb`, порт 445)

Действия: аутентификация NTLMv2, перечисление общих ресурсов через канал `\srvsvc`, запись и
чтение файла `secret.txt`, просмотр каталога.

    python main.py run --only smb

Ожидаемый результат: в отчёте видны имя пользователя `LAB\student`, ответ NTLMv2, путь к
ресурсу и содержимое файла в сообщениях WRITE и READ. Фильтр Wireshark: `smb2 || ntlmssp`.

### Сценарий 2. WebDAV по HTTP и HTTPS (`webdav`, `webdav_tls`, порты 80 и 443)

Действия: OPTIONS, PROPFIND без пароля (ответ 401), PROPFIND, MKCOL, PUT, LOCK, GET, DELETE.

    python main.py run --only webdav webdav_tls

Ожидаемый результат: на порту 80 видны логин и пароль в заголовке `Authorization: Basic`,
содержимое файла и структура каталогов; на порту 443 — только TLS 1.3. Фильтр:
`http.request.method == "PROPFIND"`.

### Сценарий 3. LDAP, StartTLS и LDAPS (`ldap`, `ldap_starttls`, `ldaps`, порты 389 и 636)

Действия: простая привязка (simple bind), поиск пользователей и компьютеров, UnbindRequest.

    python main.py run --only ldap ldap_starttls ldaps

Ожидаемый результат: в открытом LDAP видны DN и пароль привязки, фильтры поиска и записи
каталога. После StartTLS и в LDAPS виден только TLS. Фильтр: `ldap.simple`.

### Сценарий 4. RDP с Enhanced RDP Security (`rdp`, порт 3389)

Действия: X.224 Connection Request с cookie `mstshash`, Connection Confirm, переход на TLS.

    python main.py run --only rdp

Ожидаемый результат: имя пользователя в cookie и согласованный протокол безопасности (TLS)
видны открыто, остальное зашифровано. Фильтр: `tpkt || rdp`.

### Сценарий 5. WinRM, WMI и PSRP (`winrm`, `winrm_tls`, порты 5985 и 5986)

Действия: Identify, запрос WMI `Win32_OperatingSystem` (Enumerate/Pull), создание пула
PowerShell, выполнение трёх команд и получение их вывода.

    python main.py run --only winrm winrm_tls

Ожидаемый результат: на порту 5985 видны логин и пароль Basic, сведения WMI, тексты команд
PowerShell (сообщения CREATE_PIPELINE) и результаты (PIPELINE_OUTPUT); на порту 5986 — только TLS.
Фильтр: `tcp.port in {5985, 5986}`.

### Сценарий 6. WMI через DCOM/RPC (`wmi_dcom`, порт 135)

Действия: вызов `IObjectExporter::ServerAlive2` и запрос к Endpoint Mapper у настоящей службы
RPC компьютера (без аутентификации).

    python main.py run --only wmi_dcom

Ожидаемый результат: привязки к интерфейсам RPC, вызовы без аутентификации, сетевое имя и
IP-адреса компьютера в ответе ServerAlive2. Фильтр: `dcerpc || epm`.
**Внимание:** ответ содержит реальные имя и адреса компьютера, поэтому их нужно скрыть перед
публикацией результатов.

### Анализ собственного файла захвата

    python main.py analyze capture.pcapng --out results

Входные данные: файл `.pcap` или `.pcapng` (например, сохранённый в Wireshark).
Выходные данные: `results/report.md`, `results/report.json` и сводка в консоли.

### Входные и выходные данные

| Файл                          | Содержимое                                               |
|-------------------------------|----------------------------------------------------------|
| `output/windows_protocols.pcap` | захват всего обмена (формат pcap, Ethernet)            |
| `output/tls_keys.log`         | сеансовые ключи TLS (NSS Key Log) для Wireshark          |
| `output/certs/server.crt, .key` | самоподписанный сертификат `dc01.lab.local`            |
| `output/report.md`            | сводная таблица и находки по каждому TCP-потоку          |
| `output/report.json`          | те же результаты в машиночитаемом виде                   |

Коды завершения `main.py run`: 0, если все сценарии выполнены, и 1, если хотя бы один завершился ошибкой.

## Тестирование

Используется библиотека pytest.

    python -m pytest -v

- `tests/test_units.py` — 17 модульных тестов: контрольная сумма RFC 1071, запись и чтение
  pcap, сборка TCP-потоков, BER, фильтры и области поиска LDAP, PSRP, разбор HTTP, RDP, SMB2, TLS;
- `tests/test_integration.py` — 5 интеграционных тестов: стенд запускается целиком. Тесты
  проверяют, что пароль виден в открытых протоколах и не виден в протоколах с TLS.

Ожидаемый результат: `22 passed`.

## Контейнеризация

Образ строится на базе `python:3.12-slim`. Тесты выполняются при сборке образа.

    docker build -t win-protocols-stand .
    docker run --rm -v "$PWD/output:/app/output" win-protocols-stand

Сценарий `wmi_dcom` в контейнере пропускается автоматически.

## Файлы сборки

- `build.ps1` — Windows PowerShell: цели `install`, `test`, `run`, `clean`, `all`;
- `build.sh` — Linux/macOS: те же цели;
- `Makefile` — цели `install`, `test`, `run`, `clean`, `docker-build`, `docker-run`, `all`.

## Ограничения

- Учебные серверы реализуют только часть протоколов, нужную для демонстрации. Команды PowerShell
  не выполняются.
- Kerberos и шифрование сообщений WinRM (Negotiate/CredSSP) требуют домена Active Directory,
  поэтому не воспроизводятся. Шифрование SMB 3.x не поддерживается сервером Impacket.
- Проверка сертификата TLS на клиенте отключена: в стенде нет удостоверяющего центра.
