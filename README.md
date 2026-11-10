# Windows Protocols Lab

Стенд для исследования сетевых протоколов Windows (SMB, WebDAV, LDAP, RDP, WinRM, WMI, PowerShell Remoting Protocol) с помощью анализатора пакетов Wireshark.

## Требования к среде

- Python 3.10 или новее
- Git (опционально, для клонирования репозитория)
- Windows 10, 11 или Windows Server 2016 и новее (в Linux, macOS и Docker работают все сценарии, кроме wmi_dcom)
- Wireshark 4.x (для просмотра файла захвата)
- Docker 20 или новее (опционально, для запуска в контейнере)
- Свободные TCP-порты 13389–28443 на адресе 127.0.0.1
- 100 МБ свободного места на диске

## Архитектура

Стенд запускает на адресе 127.0.0.1 учебные серверы протоколов SMB, WebDAV, LDAP, RDP и WinRM. Клиентские сценарии подключаются к ним через записывающий прокси, который сохраняет весь обмен в файл захвата `output/windows_protocols.pcap`. В файле соединения записаны как обмен между рабочей станцией 192.168.56.10 и сервером 192.168.56.2 на стандартных портах протоколов, поэтому Wireshark сразу применяет нужные диссекторы. Драйвер Npcap и права администратора не нужны. Встроенный анализатор разбирает файл захвата и формирует отчёт о данных, которые видит сторонний наблюдатель. Каждый протокол исследуется в открытом варианте и в варианте с шифрованием TLS.

Структура проекта:

    windows-protocols-lab/
    ├── main.py
    ├── requirements.txt
    ├── Makefile
    ├── build.sh
    ├── build.ps1
    ├── Dockerfile
    ├── README.md
    ├── stand/
    │   ├── config.py
    │   ├── pcap.py
    │   ├── recorder.py
    │   ├── tls.py
    │   ├── ber.py
    │   ├── psrp.py
    │   ├── wsman.py
    │   ├── scenarios.py
    │   ├── runner.py
    │   ├── servers/
    │   │   ├── http_common.py
    │   │   ├── smb.py
    │   │   ├── webdav.py
    │   │   ├── ldap_server.py
    │   │   ├── rdp.py
    │   │   └── winrm.py
    │   └── analysis/
    │       ├── streams.py
    │       ├── inspectors.py
    │       └── model.py
    └── tests/
        ├── test_units.py
        └── test_integration.py

## Пошаговая установка и запуск

### Шаг 1. Клонирование проекта

    git clone https://github.com/makarovzap-crypto/windows-protocols-lab.git
    cd windows-protocols-lab

Или скачайте ZIP-архив (кнопка Code → Download ZIP на странице репозитория) и распакуйте его.

### Шаг 2. Установка зависимостей

Windows (PowerShell):

    python -m venv .venv
    .venv\Scripts\activate
    pip install -r requirements.txt

Linux и macOS:

    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt

### Шаг 3. Запуск стенда

    python main.py run

Все сценарии выполняются примерно за 5 секунд. Результаты сохраняются в папку output.

### Шаг 4. Просмотр в Wireshark

Откройте файл `output/windows_protocols.pcap` (File → Open). Для расшифровки TLS укажите файл `output/tls_keys.log` в Edit → Preferences → Protocols → TLS → (Pre)-Master-Secret log filename.

### Шаг 5. Очистка

    powershell -ExecutionPolicy Bypass -File build.ps1 clean

## Сценарии и примеры использования

Тестовая учётная запись: `LAB\student`, пароль `P@ssw0rd2026` (задаётся в stand/config.py).

### Сценарий 1. SMB2 без шифрования

Уязвимость: SMB 2 без шифрования передаёт имя пользователя, ответ NTLMv2 и содержимое файлов в открытом виде.

Запуск:

    python main.py run --only smb

Фильтр Wireshark:

    smb2 || ntlmssp

Ожидаемый результат: в отчёте видны имя пользователя `LAB\student`, ответ NTLMv2, путь к общему ресурсу и содержимое файла secret.txt в сообщениях WRITE и READ.

Входные данные: учётная запись LAB\student, файл secret.txt.
Выходные данные: TCP-поток на порту 445 в файле захвата, находки в output/report.md.

### Сценарий 2. WebDAV по HTTP и HTTPS

Уязвимость: Basic-аутентификация без TLS передаёт логин и пароль в каждом запросе.

Запуск:

    python main.py run --only webdav webdav_tls

Фильтр Wireshark:

    http.authorization

Ожидаемый результат: на порту 80 Wireshark показывает поле Credentials: `LAB\student:P@ssw0rd2026`, содержимое файла и структуру каталогов; на порту 443 виден только TLS 1.3.

Входные данные: запросы OPTIONS, PROPFIND, MKCOL, PUT, LOCK, GET, DELETE.
Выходные данные: TCP-потоки на портах 80 и 443, находки в output/report.md.

### Сценарий 3. LDAP, StartTLS и LDAPS

Уязвимость: простая привязка LDAP без TLS передаёт пароль открытым текстом.

Запуск:

    python main.py run --only ldap ldap_starttls ldaps

Фильтр Wireshark:

    ldap.simple

Ожидаемый результат: в открытом LDAP видны DN пользователя, пароль, фильтры поиска и записи каталога; после StartTLS и в LDAPS виден только TLS.

Входные данные: привязка CN=student,OU=Users,DC=lab,DC=local, два поисковых запроса.
Выходные данные: TCP-потоки на портах 389 и 636, находки в output/report.md.

### Сценарий 4. RDP

Уязвимость: имя пользователя передаётся в cookie mstshash до начала шифрования.

Запуск:

    python main.py run --only rdp

Фильтр Wireshark:

    rdp || tpkt

Ожидаемый результат: в сообщении X.224 Connection Request видно `Cookie: mstshash=student`, далее начинается рукопожатие TLS 1.3.

Входные данные: X.224 Connection Request с запросом протоколов TLS и CredSSP.
Выходные данные: TCP-поток на порту 3389, находки в output/report.md.

### Сценарий 5. WinRM, WMI и PowerShell Remoting

Уязвимость: WinRM по HTTP с Basic-аутентификацией раскрывает учётные данные, запросы WMI и команды PowerShell.

Запуск:

    python main.py run --only winrm winrm_tls

Фильтр Wireshark:

    tcp.port in {5985, 5986}

Ожидаемый результат: на порту 5985 видны логин и пароль, сведения WMI о системе (Win32_OperatingSystem), тексты команд PowerShell и результаты их выполнения; на порту 5986 виден только TLS.

Входные данные: Identify, перечисление Win32_OperatingSystem, три команды PowerShell.
Выходные данные: TCP-потоки на портах 5985 и 5986, находки в output/report.md.

### Сценарий 6. WMI через DCOM/RPC (только Windows)

Уязвимость: вызовы RPC без аутентификации раскрывают сетевое имя и IP-адреса компьютера.

Запуск:

    python main.py run --only wmi_dcom

Фильтр Wireshark:

    dcerpc || epm

Ожидаемый результат: в ответе ServerAlive2 видны сетевое имя и адреса компьютера, вызовы выполнены без аутентификации.

Входные данные: вызовы ServerAlive2 и Endpoint Mapper к службе RPC компьютера на порту 135.
Выходные данные: TCP-поток на порту 135, находки в output/report.md.

Внимание: ответ содержит реальные имя и адреса компьютера, перед публикацией результатов их нужно скрыть.

### Анализ собственного файла захвата

    python main.py analyze capture.pcapng --out results

Входные данные: файл .pcap или .pcapng, например сохранённый в Wireshark.
Выходные данные: results/report.md, results/report.json и сводка в консоли.

## Тестирование

Используется библиотека pytest.

Запуск всех тестов:

    python -m pytest -v

Ожидаемый результат: 22 теста PASSED (17 модульных и 5 интеграционных).

## Контейнеризация

Образ собирается на базе python:3.12-slim, тесты выполняются при сборке образа. Сценарий wmi_dcom в контейнере пропускается.

Сборка образа:

    docker build -t win-protocols-stand .

Запуск:

    docker run --rm -v "$PWD/output:/app/output" win-protocols-stand

## Файлы сборки

- Makefile — цели install, test, run, clean, docker-build, docker-run, all
- build.sh — установка, тесты и запуск в Linux и macOS
- build.ps1 — установка, тесты и запуск в Windows
