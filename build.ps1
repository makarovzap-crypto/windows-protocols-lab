<#
.SYNOPSIS
    Сборка и запуск стенда в Windows PowerShell.
.DESCRIPTION
    install – создать виртуальное окружение .venv и установить зависимости;
    test    – выполнить модульные и интеграционные тесты (pytest);
    run     – запустить стенд и сформировать отчёт в каталоге output;
    clean   – удалить результаты и кэш;
    all     – install, test, run.
.EXAMPLE
    powershell -ExecutionPolicy Bypass -File build.ps1 all
#>
param([ValidateSet("install", "test", "run", "clean", "all")][string]$Target = "all")

$ErrorActionPreference = "Stop"
$Root = $PSScriptRoot
$Py = Join-Path $Root ".venv\Scripts\python.exe"

function Install {
    if (-not (Test-Path $Py)) { python -m venv (Join-Path $Root ".venv") }
    & $Py -m pip install --upgrade pip -q
    & $Py -m pip install -r (Join-Path $Root "requirements.txt") -q
}
function Test { & $Py -m pytest -q (Join-Path $Root "tests") }
function Run { Push-Location $Root; try { & $Py main.py run } finally { Pop-Location } }
function Clean {
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue (Join-Path $Root "output"), (Join-Path $Root ".pytest_cache")
    Get-ChildItem $Root -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
}

switch ($Target) {
    "install" { Install }
    "test"    { Test }
    "run"     { Run }
    "clean"   { Clean }
    "all"     { Install; Test; Run }
}
