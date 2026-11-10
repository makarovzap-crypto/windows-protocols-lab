"""Построение SOAP-сообщений WS-Management (DMTF DSP0226, MS-WSMV).

WinRM передаёт запросы и ответы в виде XML-документов SOAP 1.2 внутри
HTTP POST на адрес /wsman. Заголовок SOAP содержит адрес назначения
(wsa:To), действие (wsa:Action), идентификатор ресурса (wsman:ResourceURI)
и идентификатор сообщения (wsa:MessageID); тело – параметры операции.
"""

from __future__ import annotations

import uuid
from xml.sax.saxutils import escape

NS = {
    "s": "http://www.w3.org/2003/05/soap-envelope",
    "a": "http://schemas.xmlsoap.org/ws/2004/08/addressing",
    "w": "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd",
    "p": "http://schemas.microsoft.com/wbem/wsman/1/wsman.xsd",
    "rsp": "http://schemas.microsoft.com/wbem/wsman/1/windows/shell",
    "n": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
    "wsmid": "http://schemas.dmtf.org/wbem/wsman/identity/1/wsmanidentity.xsd",
}

ACTION_CREATE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
ACTION_DELETE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
ACTION_ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
ACTION_PULL = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
ACTION_COMMAND = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command"
ACTION_RECEIVE = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive"
ACTION_SIGNAL = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal"

RESOURCE_PS = "http://schemas.microsoft.com/powershell/Microsoft.PowerShell"
RESOURCE_WMI_OS = "http://schemas.microsoft.com/wbem/wsman/1/wmi/root/cimv2/Win32_OperatingSystem"

_XMLNS = " ".join(f'xmlns:{k}="{v}"' for k, v in NS.items())


def envelope(action: str, resource: str | None, body: str, to: str = "http://dc01.lab.local:5985/wsman",
             extra_header: str = "", relates_to: str | None = None) -> str:
    """Собирает полный SOAP-конверт.

    Аргументы:
        action: URI действия WS-Management;
        resource: URI ресурса (ResourceURI) или None для ответов;
        body: XML содержимого тела;
        to: адрес службы WinRM;
        extra_header: дополнительные элементы заголовка;
        relates_to: MessageID запроса (для ответов сервера).
    """
    hdr = [f"<a:To>{escape(to)}</a:To>", f"<a:Action s:mustUnderstand=\"true\">{escape(action)}</a:Action>",
           f"<a:MessageID>uuid:{uuid.uuid4()}</a:MessageID>"]
    if resource:
        hdr.append(f"<w:ResourceURI s:mustUnderstand=\"true\">{escape(resource)}</w:ResourceURI>")
        hdr.append("<a:ReplyTo><a:Address s:mustUnderstand=\"true\">"
                   "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
                   "<w:MaxEnvelopeSize s:mustUnderstand=\"true\">512000</w:MaxEnvelopeSize>"
                   "<w:Locale xml:lang=\"ru-RU\" s:mustUnderstand=\"false\"/>"
                   "<w:OperationTimeout>PT20S</w:OperationTimeout>")
    if relates_to:
        hdr.append(f"<a:RelatesTo>{escape(relates_to)}</a:RelatesTo>")
    hdr.append(extra_header)
    return (f'<?xml version="1.0" encoding="utf-8"?><s:Envelope {_XMLNS}><s:Header>'
            + "".join(hdr) + f"</s:Header><s:Body>{body}</s:Body></s:Envelope>")


def selector(shell_id: str) -> str:
    """Элемент SelectorSet с идентификатором оболочки (ShellId)."""
    return f'<w:SelectorSet><w:Selector Name="ShellId">{shell_id}</w:Selector></w:SelectorSet>'


# ---- Запросы клиента -------------------------------------------------------

def identify() -> str:
    """Запрос Identify – проверка доступности службы WinRM."""
    return (f'<?xml version="1.0" encoding="utf-8"?><s:Envelope {_XMLNS}><s:Header/>'
            "<s:Body><wsmid:Identify/></s:Body></s:Envelope>")


def enumerate_wmi(resource: str = RESOURCE_WMI_OS) -> str:
    """Запрос Enumerate для перечисления экземпляров класса WMI через WinRM."""
    return envelope(ACTION_ENUMERATE, resource,
                    "<n:Enumerate><w:OptimizeEnumeration/><w:MaxElements>32000</w:MaxElements></n:Enumerate>")


def pull(context: str, resource: str = RESOURCE_WMI_OS) -> str:
    """Запрос Pull – получение очередной порции результатов перечисления."""
    return envelope(ACTION_PULL, resource,
                    f"<n:Pull><n:EnumerationContext>{context}</n:EnumerationContext>"
                    "<n:MaxElements>32000</n:MaxElements></n:Pull>")


def create_shell(creation_xml_b64: str) -> str:
    """Запрос Create – создание пула выполнения PowerShell (RunspacePool)."""
    body = ('<rsp:Shell ShellId="' + str(uuid.uuid4()).upper() + '"><rsp:Name>WinRM1</rsp:Name>'
            "<rsp:InputStreams>stdin pr</rsp:InputStreams><rsp:OutputStreams>stdout</rsp:OutputStreams>"
            f'<creationXml xmlns="http://schemas.microsoft.com/powershell">{creation_xml_b64}</creationXml>'
            "</rsp:Shell>")
    opts = '<w:OptionSet><w:Option Name="protocolversion" MustComply="true">2.3</w:Option></w:OptionSet>'
    return envelope(ACTION_CREATE, RESOURCE_PS, body, extra_header=opts)


def command(shell_id: str, pipeline_id: str, arguments_b64: str) -> str:
    """Запрос Command – запуск конвейера (Pipeline) с сообщением CREATE_PIPELINE."""
    body = (f'<rsp:CommandLine CommandId="{pipeline_id}"><rsp:Command></rsp:Command>'
            f"<rsp:Arguments>{arguments_b64}</rsp:Arguments></rsp:CommandLine>")
    return envelope(ACTION_COMMAND, RESOURCE_PS, body, extra_header=selector(shell_id))


def receive(shell_id: str, pipeline_id: str) -> str:
    """Запрос Receive – получение потока вывода конвейера."""
    body = f'<rsp:Receive><rsp:DesiredStream CommandId="{pipeline_id}">stdout</rsp:DesiredStream></rsp:Receive>'
    return envelope(ACTION_RECEIVE, RESOURCE_PS, body, extra_header=selector(shell_id))


def delete_shell(shell_id: str) -> str:
    """Запрос Delete – закрытие пула выполнения."""
    return envelope(ACTION_DELETE, RESOURCE_PS, "", extra_header=selector(shell_id))
