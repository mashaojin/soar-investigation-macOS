# WSL OpenSSH owns cryptography/authentication. Windows opens only allowed TCP/22.
# No listener, firewall change, execution-policy change, or guest command here.
param(
    [Parameter(Mandatory=$true)][string]$ProfilePath,
    [Parameter(Mandatory=$true)][string]$Target,
    [ValidateRange(22,22)][int]$Port=22
)
$ErrorActionPreference='Stop'
$labProxyProfile=Get-Content -LiteralPath $ProfilePath -Raw | ConvertFrom-Json
if ($labProxyProfile.platform -ne 'windows-hyperv' -or $labProxyProfile.ssh.transport -ne 'windows-stdio') { throw 'Expected Windows lab profile' }
$labProxyAllowed=@($labProxyProfile.victim.ip,$labProxyProfile.trust_client.ip,$labProxyProfile.attacker.ip)
if ($Target -notin $labProxyAllowed) { throw 'Target is outside explicit lab role allowlist' }
$labProxyAddress=[System.Net.IPAddress]::Parse($Target)
if ($labProxyAddress.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) { throw 'IPv4 lab target required' }
$labProxyClient=[System.Net.Sockets.TcpClient]::new()
try {
    if (-not $labProxyClient.ConnectAsync($Target,$Port).Wait(4000)) { throw 'Lab SSH connect timed out' }
    $labProxyStream=$labProxyClient.GetStream()
    $labProxyInput=[Console]::OpenStandardInput()
    $labProxyOutput=[Console]::OpenStandardOutput()
    $labProxyUpload=$labProxyInput.CopyToAsync($labProxyStream)
    $labProxyDownload=$labProxyStream.CopyToAsync($labProxyOutput)
    $labProxyDownload.GetAwaiter().GetResult()
    $labProxyOutput.Flush()
} catch {
    [Console]::Error.WriteLine('Lab SSH bridge failed: '+$_.Exception.Message)
    exit 1
} finally { $labProxyClient.Dispose() }
