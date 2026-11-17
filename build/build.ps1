# 一键编译脚本
# 用法：powershell -ExecutionPolicy Bypass -File .\build\build.ps1
# 输出：build\output\SC2TimeResume.exe

$ErrorActionPreference = 'Stop'

$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $root 'src'
$out  = Join-Path $PSScriptRoot 'output'

$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) {
    $csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework\v4.0.30319\csc.exe'
}
if (-not (Test-Path $csc)) {
    Write-Error '未找到 C# 编译器（csc.exe），请确认已安装 .NET Framework 4.0+。'
    exit 1
}

if (-not (Test-Path $out)) { New-Item -ItemType Directory -Path $out -Force | Out-Null }

$target = Join-Path $out 'SC2TimeResume.exe'
$source = Join-Path $src 'SC2TimeResume.cs'

$args = @(
    '/nologo', '/optimize+', '/platform:x64', '/target:winexe',
    '/reference:System.Windows.Forms.dll',
    '/reference:System.Drawing.dll',
    '/reference:System.Security.dll',
    '/reference:System.Management.dll',
    "/out:$target",
    $source
)

Write-Host '编译 SC2TimeResume.exe ...' -ForegroundColor Cyan
& $csc @args

if ($LASTEXITCODE -ne 0) {
    Write-Host '编译失败。' -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host '编译完成：' -ForegroundColor Green
Get-Item $target |
    Select-Object FullName, @{n = 'Size'; e = { '{0:N0} 字节' -f $_.Length } } |
    Format-List
