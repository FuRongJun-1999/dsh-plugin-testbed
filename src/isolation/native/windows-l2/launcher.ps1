<#
Windows L2 launcher entry point (AppContainer + Job Object).

Modes
  inspect         compile the native backend in-memory and run a read-only probe
                  (creates/closes a transient Job Object; creates no profile and
                  launches no worker).
  execute         launch one worker attempt. REQUIRES a separate authorization
                  file approved by the team captain; without it this mode emits a
                  structured `blocked` status and starts nothing.
  delete-profile  delete the AppContainer profile. REQUIRES authorization.

The native P/Invoke implementation lives in NativeL2.cs next to this script and
is compiled in-memory with Add-Type (no build artifact, no global install).

Authorization is a governance gate, not a cryptographic proof: the file must
name the approver, exact scope, profile and expiry. See AUTHORIZATION-REQUEST.md
for the exact operations/impact/rollback that must be approved before use.
#>
[CmdletBinding()]
param(
  [ValidateSet('inspect', 'create-profile', 'execute', 'delete-profile')]
  [string]$Mode = 'inspect',
  [string]$RequestPath,
  [string]$AuthorizationPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$nativeSource = Join-Path $scriptDir 'NativeL2.cs'
$statusPrefix = 'DSH_L2_STATUS '

function Write-StatusJson {
  param([hashtable]$Value)
  [Console]::Error.WriteLine($statusPrefix + ($Value | ConvertTo-Json -Compress -Depth 10))
  [Console]::Error.Flush()
}

function Fail-Blocked {
  param([string]$Stage, [string]$Message)
  Write-StatusJson @{ status = 'blocked'; stage = $Stage; error = $Message }
  exit 2
}

function Read-JsonFile {
  param([string]$Path, [string]$Label)
  if ([string]::IsNullOrWhiteSpace($Path) -or -not (Test-Path -LiteralPath $Path -PathType Leaf)) {
    Fail-Blocked $Label "$Label file is required and must exist"
  }
  try {
    $raw = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
    return ($raw | ConvertFrom-Json -ErrorAction Stop)
  } catch {
    Fail-Blocked $Label "$Label is not valid JSON"
  }
}

function Assert-Object {
  param($Value, [string]$Label)
  if ($null -eq $Value -or $Value -isnot [pscustomobject]) { Fail-Blocked $Label "$Label must be an object" }
}

function Assert-NonEmptyString {
  param($Value, [string]$Label)
  if ($Value -isnot [string] -or [string]::IsNullOrWhiteSpace($Value)) { Fail-Blocked $Label "$Label must be a non-empty string" }
}

function Assert-Sha256 {
  param($Value, [string]$Label)
  if ($Value -isnot [string] -or $Value -notmatch '^sha256:[0-9a-f]{64}$') { Fail-Blocked $Label "$Label must be a sha256 digest" }
}

function Test-SecretLike {
  param([string]$Key, [string]$Value)
  if ($Key -match '^(private[_-]?key|privatekey|password|passwd|client[_-]?secret|api[_-]?key|access[_-]?token|refresh[_-]?token|secret[_-]?key|signing[_-]?key)$') { return $true }
  if ($Value -match '-----BEGIN [A-Z ]*PRIVATE KEY-----') { return $true }
  if ($Value -match '^\s*(sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\s*$') { return $true }
  return $false
}

if (-not (Test-Path -LiteralPath $nativeSource -PathType Leaf)) {
  Fail-Blocked 'native-source' 'NativeL2.cs is missing'
}

try {
  # Compile a uniquely named copy: concurrent inspect/execute invocations must
  # not share a compiler temp artifact. The copy is removed immediately after
  # Add-Type completes; no build artifact is installed.
  $nativeCompilePath = Join-Path ([IO.Path]::GetTempPath()) ('dsh-l2-native-' + [guid]::NewGuid().ToString('N') + '.cs')
  Copy-Item -LiteralPath $nativeSource -Destination $nativeCompilePath -Force
  try {
    Add-Type -Path $nativeCompilePath -ErrorAction Stop
  } finally {
    if (Test-Path -LiteralPath $nativeCompilePath) { Remove-Item -LiteralPath $nativeCompilePath -Force -ErrorAction SilentlyContinue }
  }
} catch {
  Fail-Blocked 'native-compile' ('native backend failed to compile: ' + $_.Exception.Message)
}

if ($Mode -eq 'inspect') {
  try {
    $probe = [DshTestbed.Isolation.NativeL2]::Probe()
    [Console]::Error.WriteLine($statusPrefix + $probe)
    [Console]::Error.Flush()
    exit 0
  } catch {
    Fail-Blocked 'inspect' ('probe failed: ' + $_.Exception.Message)
  }
}

$authorization = Read-JsonFile -Path $AuthorizationPath -Label 'authorization'
Assert-Object $authorization 'authorization'
$request = $null

if ($authorization.schema_version -ne 'windows-l2-authorization/v1') {
  Fail-Blocked 'authorization' 'unsupported authorization schema_version'
}
$expiresAt = [DateTimeOffset]::MinValue
$expiresRaw = $authorization.expires_at
if ($expiresRaw -is [DateTimeOffset]) {
  $expiresAt = [DateTimeOffset]$expiresRaw
} elseif ($expiresRaw -is [datetime]) {
  $expiresAt = [DateTimeOffset]::new([datetime]$expiresRaw)
} elseif ($expiresRaw -is [string] -and [DateTimeOffset]::TryParse($expiresRaw, [ref]$expiresAt)) {
  # parsed above
} else {
  Fail-Blocked 'authorization' 'authorization.expires_at must be RFC 3339'
}
if ($expiresAt -le [DateTimeOffset]::UtcNow) {
  Fail-Blocked 'authorization' 'authorization is expired'
}
Assert-NonEmptyString $authorization.approved_by 'authorization.approved_by'
Assert-NonEmptyString $authorization.approval_ref 'authorization.approval_ref'
Assert-NonEmptyString $authorization.profile_name 'authorization.profile_name'

$defaultProfile = 'DshTestbedL2'
$profileName = $defaultProfile
if ($null -ne $request -and $request.PSObject.Properties.Name -contains 'profile_name' -and $request.profile_name) {
  $profileName = [string]$request.profile_name
}
if ($profileName -ne $defaultProfile -or $authorization.profile_name -ne $profileName) {
  Fail-Blocked 'authorization' 'authorization/profile_name must match the fixed testbed profile'
}
if ($profileName -notmatch '^[A-Za-z0-9._-]{1,64}$') {
  Fail-Blocked 'request' 'profile_name is invalid'
}

$scope = @()
if ($authorization.PSObject.Properties.Name -contains 'scope' -and $authorization.scope) {
  $scope = @($authorization.scope)
}
function Test-Scope([string]$Name) { return ($scope -contains $Name) }

if ($Mode -eq 'create-profile') {
  if (-not (Test-Scope 'create-appcontainer-profile')) {
    Fail-Blocked 'authorization' 'create-appcontainer-profile scope is not authorized'
  }
  exit ([DshTestbed.Isolation.NativeL2]::CreateProfile($profileName))
}

if ($Mode -eq 'delete-profile') {
  if (-not (Test-Scope 'delete-appcontainer-profile')) {
    Fail-Blocked 'authorization' 'delete-appcontainer-profile scope is not authorized'
  }
  exit ([DshTestbed.Isolation.NativeL2]::DeleteProfile($profileName))
}

# execute -------------------------------------------------------------------
$request = Read-JsonFile -Path $RequestPath -Label 'request'
Assert-Object $request 'request'
if ($request.PSObject.Properties.Name -contains 'profile_name' -and $request.profile_name -and [string]$request.profile_name -ne $profileName) {
  Fail-Blocked 'request' 'request/profile_name must match the authorized profile'
}
foreach ($requiredScope in @('create-appcontainer-profile', 'launch-appcontainer-process', 'assign-job-object', 'create-temp-root', 'delete-attempt-temp')) {
  if (-not (Test-Scope $requiredScope)) {
    Fail-Blocked 'authorization' ("scope not authorized: " + $requiredScope)
  }
}
if ($request.schema_version -ne 'windows-l2-launch-request/v1') {
  Fail-Blocked 'request' 'unsupported launch request schema_version'
}

Assert-NonEmptyString $request.temp_root 'request.temp_root'
Assert-NonEmptyString $request.application_path 'request.application_path'
Assert-NonEmptyString $request.working_directory 'request.working_directory'
if (-not (Test-Path -LiteralPath $request.application_path -PathType Leaf)) {
  Fail-Blocked 'request' 'application_path does not exist'
}
if ($request.working_directory -ne 'auto' -and -not (Test-Path -LiteralPath $request.working_directory -PathType Container)) {
  Fail-Blocked 'request' 'working_directory does not exist'
}

$limits = $request.limits
Assert-Object $limits 'request.limits'
foreach ($key in @('cpu_ms', 'memory_mb', 'processes')) {
  $value = $limits.$key
  if ($null -eq $value -or -not ($value -is [int] -or $value -is [long]) -or $value -le 0) {
    Fail-Blocked 'request' ("request.limits." + $key + " must be a positive integer")
  }
}
if ($limits.cpu_ms -gt 86400000 -or $limits.memory_mb -gt 65536 -or $limits.processes -gt 256) {
  Fail-Blocked 'request' 'request limits exceed the launcher ceiling'
}

# Environment allowlist: only non-secret OS/runtime keys. The worker never sees
# the parent environment.
$allowedEnvKeys = @('SystemRoot', 'SystemDrive', 'windir', 'TEMP', 'TMP', 'PATH', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'USERNAME')
$envLines = @()
if ($request.PSObject.Properties.Name -contains 'env' -and $null -ne $request.env) {
  $envObject = $request.env
  Assert-Object $envObject 'request.env'
  foreach ($property in $envObject.PSObject.Properties) {
    $key = [string]$property.Name
    $value = [string]$property.Value
    if (-not ($allowedEnvKeys -contains $key)) {
      Fail-Blocked 'request' ("env key not allowed: " + $key)
    }
    if (Test-SecretLike $key $value) {
      Fail-Blocked 'request' ("secret-like env is forbidden: " + $key)
    }
    $envLines += ($key + '=' + $value)
  }
}
foreach ($requiredKey in @('SystemRoot', 'SystemDrive', 'windir', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA')) {
  if (-not ($envLines | Where-Object { $_ -like ($requiredKey + '=*') })) {
    $value = [Environment]::GetEnvironmentVariable($requiredKey)
    if ([string]::IsNullOrWhiteSpace($value)) { Fail-Blocked 'request' ("missing environment value: " + $requiredKey) }
    $envLines += ($requiredKey + '=' + $value)
  }
}
$tempRoot = [string]$request.temp_root
$envLines += ('TEMP=' + $tempRoot)
$envLines += ('TMP=' + $tempRoot)
if (-not ($envLines | Where-Object { $_ -like 'PATH=*' })) {
  $envLines += 'PATH=C:\Windows\system32;C:\Windows'
}

$envFile = [IO.Path]::Combine([IO.Path]::GetTempPath(), ('dsh-l2-env-' + [guid]::NewGuid().ToString('N') + '.txt'))
try {
  Set-Content -LiteralPath $envFile -Value $envLines -Encoding utf8NoBOM -ErrorAction Stop
  $arguments = ''
  if ($request.PSObject.Properties.Name -contains 'arguments') { $arguments = [string]$request.arguments }
  $createProfile = $true
  if ($request.PSObject.Properties.Name -contains 'create_profile') { $createProfile = [bool]$request.create_profile }
  $deleteTemp = $true
  if ($request.PSObject.Properties.Name -contains 'delete_temp_on_exit') { $deleteTemp = [bool]$request.delete_temp_on_exit }
  $deleteProfile = $false
  if ($request.PSObject.Properties.Name -contains 'delete_profile_on_exit') { $deleteProfile = [bool]$request.delete_profile_on_exit }
  if ($deleteProfile -and -not (Test-Scope 'delete-appcontainer-profile')) {
    Fail-Blocked 'authorization' 'delete-appcontainer-profile scope is not authorized'
  }
  exit ([DshTestbed.Isolation.NativeL2]::Execute(
    $profileName,
    $tempRoot,
    [string]$request.application_path,
    $arguments,
    [string]$request.working_directory,
    $envFile,
    [long]$limits.cpu_ms,
    [long]$limits.memory_mb,
    [int]$limits.processes,
    $createProfile,
    $deleteTemp,
    $deleteProfile
  ))
} finally {
  if (-not $env:DSH_L2_KEEP_ENV -and (Test-Path -LiteralPath $envFile)) { Remove-Item -LiteralPath $envFile -Force -ErrorAction SilentlyContinue }
}
