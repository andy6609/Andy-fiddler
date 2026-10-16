<#
.SYNOPSIS
  Windows 에서 WireScope 를 빌드/테스트/패키징한다 (MSVC + vcpkg).

.DESCRIPTION
  필요한 것
    - Visual Studio 2022 이상 + "C++를 사용한 데스크톱 개발" 워크로드
      (이 워크로드에 MSVC, CMake, vcpkg 가 함께 들어 있다)
    - 또는 따로 설치한 CMake 3.25+ 와 vcpkg (환경 변수 VCPKG_ROOT)
  필요 없는 것
    - Npcap: 빌드에는 쓰지 않는다. WireScope 는 실행 중에 %SystemRoot%\System32\Npcap\wpcap.dll 을 찾는다.
      패킷 캡처를 쓰려면 https://npcap.com 에서 설치 (loopback 캡처 옵션 포함).

  OpenSSL 과 nghttp2 는 vcpkg.json 을 보고 vcpkg 가 처음 한 번 소스에서 빌드한다 (수 분).

.EXAMPLE
  .\scripts\build-windows.ps1                # 빌드 + core 단위 테스트
.EXAMPLE
  .\scripts\build-windows.ps1 -Test all      # integration/lab 까지 (Python, curl, openssl, 'pip install h2' 필요)
.EXAMPLE
  .\scripts\build-windows.ps1 -Package       # dist\WireScope-windows-x64.zip 생성
#>
param(
  [ValidateSet('none', 'core', 'all')][string]$Test = 'core',
  [switch]$Package
)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# 외부 프로그램은 실패해도 PowerShell 이 멈추지 않는다 -> 종료 코드를 직접 확인한다.
function Invoke-Checked([string]$exe, [string[]]$arguments) {
  Write-Host "> $exe $($arguments -join ' ')" -ForegroundColor DarkGray
  & $exe @arguments
  if ($LASTEXITCODE -ne 0) { throw "$exe failed with exit code $LASTEXITCODE" }
}

# 1) Visual Studio 위치 (vswhere 는 VS 설치 관리자와 함께 항상 같은 경로에 깔린다)
$vs = $null
$vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
if (Test-Path $vswhere) {
  $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
}
if (-not $vs) { Write-Warning 'MSVC(C++ 데스크톱 개발 워크로드)가 있는 Visual Studio 를 찾지 못했습니다. CMake 구성 단계에서 실패할 수 있습니다.' }

# 2) vcpkg: VCPKG_ROOT -> Visual Studio 에 들어 있는 vcpkg
if (-not $env:VCPKG_ROOT -and $vs -and (Test-Path (Join-Path $vs 'VC\vcpkg\vcpkg.exe'))) {
  $env:VCPKG_ROOT = Join-Path $vs 'VC\vcpkg'
}
if (-not $env:VCPKG_ROOT -or -not (Test-Path (Join-Path $env:VCPKG_ROOT 'scripts\buildsystems\vcpkg.cmake'))) {
  throw @'
vcpkg 를 찾지 못했습니다. 둘 중 하나를 하세요.
  - Visual Studio Installer 에서 "C++를 사용한 데스크톱 개발" 워크로드의 vcpkg 패키지 관리자 구성 요소를 설치
  - git clone https://github.com/microsoft/vcpkg C:\vcpkg; C:\vcpkg\bootstrap-vcpkg.bat; $env:VCPKG_ROOT = 'C:\vcpkg'
'@
}
Write-Host "vcpkg: $env:VCPKG_ROOT"

# 3) cmake: PATH -> Visual Studio 에 들어 있는 cmake
$cmake = (Get-Command cmake -ErrorAction SilentlyContinue).Source
$ctest = (Get-Command ctest -ErrorAction SilentlyContinue).Source
if (-not $cmake -and $vs) {
  $bin = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin'
  if (Test-Path (Join-Path $bin 'cmake.exe')) { $cmake = Join-Path $bin 'cmake.exe'; $ctest = Join-Path $bin 'ctest.exe' }
}
if (-not $cmake) { throw 'cmake 를 찾지 못했습니다 (Visual Studio 의 C++ CMake 도구 또는 https://cmake.org).' }

# 4) 구성 + 빌드 (CMakePresets.json 의 windows-msvc / windows-release)
Invoke-Checked $cmake @('--preset', 'windows-msvc')
Invoke-Checked $cmake @('--build', '--preset', 'windows-release', '--parallel')

# 5) 테스트
if ($Test -eq 'core') {
  Invoke-Checked $ctest @('--preset', 'windows-release', '-R', '^core$')
} elseif ($Test -eq 'all') {
  Invoke-Checked $ctest @('--preset', 'windows-release')
}

# 6) 패키지: WireScope.exe + web\ + vcpkg 가 붙여 주는 OpenSSL/nghttp2 DLL
if ($Package) {
  $stage = Join-Path $root 'dist\WireScope'
  if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
  Invoke-Checked $cmake @('--install', 'build-windows', '--config', 'Release', '--prefix', $stage)
  $zip = Join-Path $root 'dist\WireScope-windows-x64.zip'
  if (Test-Path $zip) { Remove-Item -Force $zip }
  Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
  Write-Host "package: $zip"
}

$exe = Join-Path $root 'build-windows\Release\WireScope.exe'
Write-Host ''
Write-Host "실행: $exe" -ForegroundColor Green
Write-Host '      (브라우저가 http://127.0.0.1:17890 을 연다. 프록시/캡처는 화면에서 직접 시작할 때까지 꺼져 있다)'
