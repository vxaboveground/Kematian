@echo off
setlocal

rem ────────────────────────────────────────────────────────────────────────
rem  devtool.bat — compile & run the standalone Kematian recovery devtool
rem
rem  Builds the Rust injected DLL, then native/cmd/devtool/main.go into a
rem  standalone .exe (not a plugin), and runs it, forwarding any arguments you
rem  pass through. It emulates the plugin host + server and prints a summary
rem  (or full JSON with -verbose) to the console.
rem
rem  Usage:
rem    devtool.bat                          collect everything (summary)
rem    devtool.bat -cookies -browser Brave  just Brave cookies
rem    devtool.bat -passwords -out out.json write result to a file
rem    devtool.bat -verbose                 dump full JSON events
rem    devtool.bat -no-inject               skip DLL injection (faster)
rem
rem  See "go run ./cmd/devtool -h" (from native/) for the full flag list.
rem ────────────────────────────────────────────────────────────────────────

set "GOWORK=off"

set "PLUGIN_DIR=%~dp0"
set "NATIVE_DIR=%PLUGIN_DIR%native"
set "RUST_DIR=%PLUGIN_DIR%rust-extractor"
set "RUST_DLL=%RUST_DIR%\target\x86_64-pc-windows-gnu\release\recovery_key_extractor.dll"
set "EXTRACTOR_OUT=%NATIVE_DIR%\recovery\platform\recovery-key-extractor.dll"
set "OUT=%PLUGIN_DIR%kematian-devtool.exe"

rem ── Embedded key-extractor DLL (Rust, required by go:embed) ─────────────
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

if not exist "%NATIVE_DIR%\go.mod" (
  echo [error] native\go.mod not found
  exit /b 1
)

rem ── Build the standalone devtool exe ────────────────────────────────────
echo [build] kematian-devtool.exe
pushd "%NATIVE_DIR%"
set "GOOS=windows"
set "GOARCH=amd64"
set "CGO_ENABLED=1"
go build -o "%OUT%" ./cmd/devtool
if errorlevel 1 (
  set "GOOS="
  set "GOARCH="
  set "CGO_ENABLED="
  popd
  echo [error] build failed
  exit /b 1
)
set "GOOS="
set "GOARCH="
set "CGO_ENABLED="
popd
echo [ok] %OUT%

rem ── Run with forwarded args ─────────────────────────────────────────────
echo [run] kematian-devtool.exe %*
"%OUT%" %*
exit /b %errorlevel%
