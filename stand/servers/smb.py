"""Учебный SMB-сервер на основе библиотеки Impacket.

Impacket – свободно распространяемая библиотека на языке Python с
реализацией сетевых протоколов Microsoft (SMB1/SMB2, DCE/RPC, NTLM,
Kerberos). Сервер SimpleSMBServer публикует общий ресурс LAB и
аутентифицирует пользователя по протоколу NTLM (NTLMv2).
"""

from __future__ import annotations

import logging
import os
import threading

from impacket import smbserver
from impacket.ntlm import compute_lmhash, compute_nthash

from .. import config


def start(port: int, share_dir: str) -> smbserver.SimpleSMBServer:
    """Запускает SMB-сервер в фоновом потоке.

    Аргументы:
        port: TCP-порт прослушивания на 127.0.0.1;
        share_dir: каталог, публикуемый как общий ресурс LAB.
    Возвращает:
        Экземпляр сервера (для последующей остановки).
    """
    os.makedirs(share_dir, exist_ok=True)
    logging.getLogger("impacket").setLevel(logging.WARNING)
    server = smbserver.SimpleSMBServer(listenAddress=config.LOCALHOST, listenPort=port)
    server.addShare("LAB", share_dir, "Учебный общий ресурс")
    server.setSMB2Support(True)
    server.setSMBChallenge("")
    server.addCredential(config.USERNAME, 0, compute_lmhash(config.PASSWORD).hex(),
                         compute_nthash(config.PASSWORD).hex())
    server.setLogFile("")
    threading.Thread(target=server.start, daemon=True, name="smb-server").start()
    return server
