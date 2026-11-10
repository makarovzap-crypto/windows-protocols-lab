"""Записывающий TCP-прокси.

Прокси принимает подключения клиента, устанавливает соединение с реальным
сервером и прозрачно пересылает байты в обе стороны. Каждая порция данных
перед пересылкой записывается в pcap как сегмент TCP «виртуального»
соединения WS01 -> DC01 на стандартном порту протокола. Таким образом стенд
получает файл захвата без драйвера перехвата (Npcap) и прав администратора,
а содержимое пакетов в точности совпадает с тем, что передавалось по сети.
"""

from __future__ import annotations

import itertools
import logging
import socket
import threading

from . import config
from .pcap import PcapWriter, TcpSession

log = logging.getLogger("recorder")

# Эфемерные порты клиента в «виртуальной» сети (диапазон Windows 49152–65535).
_ephemeral = itertools.count(50000)
_ephemeral_lock = threading.Lock()


def _next_client_port() -> int:
    """Возвращает следующий свободный эфемерный порт клиента."""
    with _ephemeral_lock:
        return next(_ephemeral)


class RecordingProxy:
    """TCP-прокси, записывающий проходящий трафик в pcap."""

    def __init__(self, writer: PcapWriter, service: config.Service):
        """Аргументы:
            writer: объект записи pcap;
            service: описание сервиса (порты прокси, реального сервера и pcap).
        """
        self.writer = writer
        self.service = service
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((config.LOCALHOST, service.proxy_port))
        self._sock.listen(16)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True,
                                        name=f"proxy-{service.name}")

    def start(self) -> "RecordingProxy":
        """Запускает поток приёма подключений."""
        self._thread.start()
        return self

    def stop(self) -> None:
        """Останавливает прокси."""
        self._stop.set()
        try:
            self._sock.close()
        except OSError:
            pass

    def _accept_loop(self) -> None:
        """Принимает подключения и создаёт для каждого пару потоков пересылки."""
        while not self._stop.is_set():
            try:
                client, _ = self._sock.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(client,), daemon=True).start()

    def _handle(self, client: socket.socket) -> None:
        """Обслуживает одно клиентское подключение."""
        svc = self.service
        try:
            upstream = socket.create_connection((svc.real_host, svc.real_port), timeout=10)
        except OSError as exc:
            log.error("%s: нет связи с сервером %s:%s: %s", svc.name, svc.real_host,
                      svc.real_port, exc)
            client.close()
            return
        upstream.settimeout(None)
        session = TcpSession(self.writer,
                             (config.CLIENT_IP, _next_client_port()),
                             (config.SERVER_IP, svc.virtual_port),
                             config.CLIENT_MAC, config.SERVER_MAC)
        done = threading.Event()

        def pump(src: socket.socket, dst: socket.socket, side: str) -> None:
            """Пересылает данные src -> dst, предварительно записывая их в pcap."""
            try:
                while True:
                    data = src.recv(65536)
                    if not data:
                        break
                    session.send(side, data)
                    dst.sendall(data)
            except OSError:
                pass
            finally:
                # Половинное закрытие: сообщаем другой стороне об окончании данных.
                try:
                    dst.shutdown(socket.SHUT_WR)
                except OSError:
                    pass
                if done.is_set():
                    session.close("c" if side == "c" else "s")
                done.set()

        t1 = threading.Thread(target=pump, args=(client, upstream, "c"), daemon=True)
        t2 = threading.Thread(target=pump, args=(upstream, client, "s"), daemon=True)
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        client.close()
        upstream.close()
