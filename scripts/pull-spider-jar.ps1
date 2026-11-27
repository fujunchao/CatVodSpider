<#
.SYNOPSIS
  从 GitHub Release 拉取最新的 custom_spider.jar 到本地产线目录。

.DESCRIPTION
  spider-jar workflow 每次构建都会覆盖发布 spider-latest 这个滚动 Release。
  本脚本用本机已登录的 gh CLI 下载 jar 与 md5，校验后落到目标目录。

.PARAMETER Dest
  目标目录，默认 D:\augment-projects\tvb（产线目录）。

.EXAMPLE
  .\pull-spider-jar.ps1
  .\pull-spider-jar.ps1 -Dest D:\augment-projects\tvb -KeepDir
#>
param(
    [string] $Repo = 'fujunchao/CatVodSpider',
    [string] $Tag = 'spider-latest',
    [string] $Dest = 'D:\augment-projects\tvb',
    [switch] $KeepDir
)

$ErrorActionPreference = 'Stop'

if (-not (Get-Command gh -ErrorAction SilentlyContinue)) {
    throw 'gh CLI not found in PATH'
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("spider-jar-" + [Guid]::NewGuid().ToString('N').Substring(0, 12))
New-Item -ItemType Directory -Path $tmp -Force | Out-Null

try {
    Write-Host "Downloading $Repo @ $Tag ..."
    & gh release download $Tag -R $Repo -p 'custom_spider.jar*' -D $tmp --clobber
    if ($LASTEXITCODE -ne 0) { throw "gh release download failed (exit $LASTEXITCODE)" }

    $jar = Join-Path $tmp 'custom_spider.jar'
    $md5File = "$jar.md5"
    if (-not (Test-Path -LiteralPath $jar)) { throw "missing jar: $jar" }
    if (-not (Test-Path -LiteralPath $md5File)) { throw "missing md5: $md5File" }

    $expected = (Get-Content -Raw -LiteralPath $md5File).Trim().ToLowerInvariant()
    $actual = (Get-FileHash -LiteralPath $jar -Algorithm MD5).Hash.ToLowerInvariant()
    if ($actual -ne $expected) { throw "md5 mismatch: $actual != $expected" }

    $size = (Get-Item -LiteralPath $jar).Length
    New-Item -ItemType Directory -Path $Dest -Force | Out-Null
    $target = Join-Path $Dest 'custom_spider.jar'
    Copy-Item -LiteralPath $jar -Destination $target -Force
    Copy-Item -LiteralPath $md5File -Destination "$target.md5" -Force

    Write-Host ""
    Write-Host "OK  $target"
    Write-Host "    size : $size B"
    Write-Host "    md5  : $actual"
    Write-Host "    1.json 引用写法: ./custom_spider.jar;$actual"
} finally {
    if (-not $KeepDir -and (Test-Path -LiteralPath $tmp)) {
        Remove-Item -LiteralPath $tmp -Recurse -Force
    }
}
