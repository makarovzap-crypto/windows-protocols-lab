# Образ стенда исследования протоколов Windows.
# Сценарий wmi_dcom в контейнере пропускается: ему нужна служба RPC Windows (порт 135).
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY stand ./stand
COPY tests ./tests
COPY main.py pytest.ini ./

# Тесты выполняются при сборке образа: образ не соберётся, если стенд неисправен.
RUN python -m pytest -q tests

# Результаты (pcap, ключи TLS, отчёты) сохраняются в /app/output – подключите том.
VOLUME ["/app/output"]
ENTRYPOINT ["python", "main.py"]
CMD ["run"]
