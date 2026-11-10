"""Учебная служба WinRM (WS-Management) с поддержкой WMI и PowerShell Remoting.

Сервер принимает SOAP-запросы на /wsman и обрабатывает:
  * Identify – сведения о реализации WS-Management;
  * Enumerate/Pull для класса WMI Win32_OperatingSystem (WMI поверх WinRM);
  * Create/Command/Receive/Delete для ресурса Microsoft.PowerShell (PSRP).
Команды PowerShell не выполняются: сервер возвращает заранее подготовленный
результат, достаточный для демонстрации структуры сообщений.
"""

from __future__ import annotations

import re
import uuid
import xml.etree.ElementTree as ET

from .. import psrp, wsman
from .http_common import BaseHandler

NS = wsman.NS

# Ответы на команды PowerShell, которые «выполняет» учебный сервер.
CANNED_OUTPUT = {
    "whoami": "lab\\student",
    "hostname": "DC01",
    "Get-Service WinRM": "Running  WinRM  Windows Remote Management (WS-Management)",
}


def _text(root: ET.Element, path: str) -> str:
    """Возвращает текст элемента по пути XPath или пустую строку."""
    el = root.find(path, NS)
    return (el.text or "").strip() if el is not None else ""


class WinRmHandler(BaseHandler):
    """Обработчик POST-запросов WS-Management."""

    realm = "WSMAN"
    shells: dict[str, uuid.UUID] = {}   # ShellId -> RPID пула выполнения
    pipelines: dict[str, str] = {}      # CommandId -> текст команды

    def do_POST(self) -> None:
        """Разбирает SOAP-конверт и вызывает обработчик действия."""
        if not self.authorized():
            return
        body = self.read_body()
        root = ET.fromstring(body)
        if root.find(".//wsmid:Identify", NS) is not None:
            return self._reply(self._identify())
        action = _text(root, "s:Header/a:Action")
        msg_id = _text(root, "s:Header/a:MessageID")
        resource = _text(root, "s:Header/w:ResourceURI")
        if action == wsman.ACTION_ENUMERATE:
            resp = wsman.envelope(action + "Response", None,
                                  "<n:EnumerateResponse><n:EnumerationContext>uuid:"
                                  f"{uuid.uuid4()}</n:EnumerationContext></n:EnumerateResponse>",
                                  relates_to=msg_id)
        elif action == wsman.ACTION_PULL:
            resp = wsman.envelope(action + "Response", None, self._wmi_items(resource), relates_to=msg_id)
        elif action == wsman.ACTION_CREATE:
            resp = self._create(root, msg_id)
        elif action == wsman.ACTION_COMMAND:
            resp = self._command(root, msg_id)
        elif action == wsman.ACTION_RECEIVE:
            resp = self._receive(root, msg_id)
        elif action == wsman.ACTION_DELETE:
            resp = wsman.envelope(action + "Response", None, "", relates_to=msg_id)
        else:
            return self.send_bytes(500, b"", "application/soap+xml;charset=UTF-8")
        self._reply(resp)

    def _reply(self, xml: str) -> None:
        """Отправляет SOAP-ответ с кодом 200."""
        self.send_bytes(200, xml.encode("utf-8"), "application/soap+xml;charset=UTF-8")

    @staticmethod
    def _identify() -> str:
        """Формирует ответ IdentifyResponse."""
        return (f'<?xml version="1.0" encoding="utf-8"?><s:Envelope xmlns:s="{NS["s"]}" '
                f'xmlns:wsmid="{NS["wsmid"]}"><s:Header/><s:Body><wsmid:IdentifyResponse>'
                "<wsmid:ProtocolVersion>http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd</wsmid:ProtocolVersion>"
                "<wsmid:ProductVendor>Microsoft Corporation</wsmid:ProductVendor>"
                "<wsmid:ProductVersion>OS: 10.0.20348 SP: 0.0 Stack: 3.0</wsmid:ProductVersion>"
                "</wsmid:IdentifyResponse></s:Body></s:Envelope>")

    @staticmethod
    def _wmi_items(resource: str) -> str:
        """Формирует тело PullResponse с экземпляром класса Win32_OperatingSystem."""
        cls = resource.rsplit("/", 1)[-1]
        ns = resource
        return (f"<n:PullResponse><n:Items><p:{cls} xmlns:p=\"{ns}\">"
                "<p:Caption>Microsoft Windows Server 2022 Standard</p:Caption>"
                "<p:Version>10.0.20348</p:Version><p:BuildNumber>20348</p:BuildNumber>"
                "<p:CSName>DC01</p:CSName><p:RegisteredUser>Администратор</p:RegisteredUser>"
                "<p:OSArchitecture>64-разрядная</p:OSArchitecture>"
                f"</p:{cls}></n:Items><n:EndOfSequence/></n:PullResponse>")

    def _create(self, root: ET.Element, msg_id: str) -> str:
        """Создаёт пул выполнения: разбирает creationXml, возвращает ShellId."""
        shell_el = root.find(".//rsp:Shell", NS)
        shell_id = shell_el.get("ShellId") if shell_el is not None else str(uuid.uuid4()).upper()
        creation = root.find(".//{http://schemas.microsoft.com/powershell}creationXml")
        msgs = psrp.decode_blob(creation.text) if creation is not None and creation.text else []
        rpid = msgs[0].rpid if msgs else uuid.uuid4()
        self.shells[shell_id] = rpid
        body = (f"<x:ResourceCreated xmlns:x=\"http://schemas.xmlsoap.org/ws/2004/09/transfer\">"
                f"<a:Address>http://dc01.lab.local:5985/wsman</a:Address><a:ReferenceParameters>"
                f"<w:ResourceURI>{wsman.RESOURCE_PS}</w:ResourceURI>{wsman.selector(shell_id)}"
                "</a:ReferenceParameters></x:ResourceCreated>")
        return wsman.envelope(wsman.ACTION_CREATE + "Response", None, body, relates_to=msg_id)

    def _command(self, root: ET.Element, msg_id: str) -> str:
        """Запускает конвейер: извлекает текст команды из CREATE_PIPELINE."""
        cmd_el = root.find(".//rsp:CommandLine", NS)
        pipeline_id = cmd_el.get("CommandId") if cmd_el is not None else str(uuid.uuid4()).upper()
        args = _text(root, ".//rsp:Arguments")
        script = ""
        for m in psrp.decode_blob(args) if args else []:
            if m.message_type == psrp.CREATE_PIPELINE:
                found = re.search(r'<S N="Cmd">([^<]*)</S>', m.data)
                script = found.group(1) if found else ""
        self.pipelines[pipeline_id] = script
        body = f"<rsp:CommandResponse><rsp:CommandId>{pipeline_id}</rsp:CommandId></rsp:CommandResponse>"
        return wsman.envelope(wsman.ACTION_COMMAND + "Response", None, body, relates_to=msg_id)

    def _receive(self, root: ET.Element, msg_id: str) -> str:
        """Возвращает вывод конвейера в виде сообщений PIPELINE_OUTPUT и PIPELINE_STATE."""
        shell_id = _text(root, ".//w:Selector")
        stream_el = root.find(".//rsp:DesiredStream", NS)
        pipeline_id = stream_el.get("CommandId") if stream_el is not None else None
        rpid = self.shells.get(shell_id, uuid.uuid4())
        if pipeline_id:
            pid = uuid.UUID(pipeline_id)
            script = self.pipelines.get(pipeline_id, "")
            text = CANNED_OUTPUT.get(script, f"Команда «{script}» выполнена")
            msgs = [psrp.build_message(psrp.DEST_CLIENT, psrp.PIPELINE_OUTPUT, rpid, pid,
                                       psrp.pipeline_output(text)),
                    psrp.build_message(psrp.DEST_CLIENT, psrp.PIPELINE_STATE, rpid, pid,
                                       psrp.pipeline_state())]
            attrs, state = f' CommandId="{pipeline_id}"', "Done"
        else:
            msgs = [psrp.build_message(psrp.DEST_CLIENT, psrp.SESSION_CAPABILITY, rpid, None,
                                       psrp.session_capability()),
                    psrp.build_message(psrp.DEST_CLIENT, psrp.RUNSPACEPOOL_STATE, rpid, None,
                                       psrp.runspace_state())]
            attrs, state = "", "Running"
        stream = psrp.encode_messages(msgs)
        body = (f'<rsp:ReceiveResponse><rsp:Stream Name="stdout"{attrs}>{stream}</rsp:Stream>'
                f'<rsp:CommandState{attrs} State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/'
                f'CommandState/{state}"/></rsp:ReceiveResponse>')
        return wsman.envelope(wsman.ACTION_RECEIVE + "Response", None, body, relates_to=msg_id)
