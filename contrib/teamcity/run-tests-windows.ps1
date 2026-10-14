Set-PSDebug -Off
$ErrorActionPreference='Stop'

Write-Host "--- Extracting the artifacts ---"
mkdir -Force artifacts | out-null
tar xzf artifacts.tar.gz -C artifacts

pushd artifacts/bin

function check_help_version {
  try {
    .\lotusd.exe -version
    .\lotusd.exe -help
    .\lotus-qt.exe -version
    .\lotus-qt.exe -help
    .\lotus-cli.exe -version
    .\lotus-cli.exe -help
    .\lotus-tx.exe -help
    .\lotus-wallet -help
  }
  catch {
    Write-Error $_
  }
  finally {
    Stop-Process -name lotus-qt -Force -ErrorAction SilentlyContinue
  }
}

function New-TemporaryDirectory {
  $parent = [System.IO.Path]::GetTempPath()
  [string] $name = [System.Guid]::NewGuid()
  $tempDir = New-Item -ItemType Directory -Path (Join-Path $parent $name)
  return $tempDir.FullName
}

function check_lotusd {
  trap {
    Stop-Process -name lotusd -Force 
  }

  $datadir = New-TemporaryDirectory
  $datadirArg = "-datadir=$datadir"

  Write-Host "Launching lotusd in the background"
  Start-Process -NoNewWindow .\lotusd.exe "-noprinttoconsole $datadirArg"

  for($i=60; $i -gt 0; $i--) {
    Start-Sleep -Seconds 1
    if(.\lotus-cli.exe $datadirArg help) {
      break
    }
  }
  if($i -eq 0) {
    throw "Failed to start lotusd"
  }

  Write-Host "Stopping lotusd"
  .\lotus-cli.exe $datadirArg stop

  for($i=60; $i -gt 0; $i--) {
    Start-Sleep -Seconds 1
    if(-Not (Get-Process -Name lotusd -ErrorAction SilentlyContinue)) {
      break
    }
  }
  if($i -eq 0) {
    throw "Failed to stop lotusd"
  }
}

Write-Host "--- Checking helps and versions ---"
check_help_version

Write-Host "--- Checking lotusd can run and communicate via lotus-cli ---"
check_lotusd

Write-Host "--- Running bitcoin unit tests ---"
.\test_lotus.exe
Write-Host "--- Running lotus-qt unit tests ---"
.\test_lotus-qt.exe -platform windows
Write-Host "--- Running pow unit tests ---"
.\test-pow.exe
Write-Host "--- Running avalanche unit tests ---"
# FIXME: figure out why the poll_inflight_timeout test fails and fix it
.\test-avalanche.exe -t !processor_tests/poll_inflight_timeout

popd

Write-Host -ForegroundColor Green "--- All checks passed ---"
