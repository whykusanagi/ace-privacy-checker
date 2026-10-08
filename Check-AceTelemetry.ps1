<#
.SYNOPSIS
  ACE / NIKKE telemetry check: what the game's crash reporter (Tencent CrashSight) and the ACE anti-cheat have stored on
  this PC and uploaded, which accounts those uploads were tagged with, and whether any verdict-like wording exists.

.DESCRIPTION
  Read-only and compact (a few MB). Copies only telemetry-relevant files: CrashSight records and database, CrashSight
  session logs, the game's Player.log, INTL SDK report queues, the launcher database, ACE version and registry facts,
  and filtered Windows event entries about ACE and NIKKE crashes. It decodes the CrashSight records on this PC and
  writes a plain-language SUMMARY.txt (plus summary.json) so the contents can be read before anything is shared.

  Not collected: passwords or login tokens, browser data, game assets, full event logs, serial numbers, network, DNS or
  process listings, installed programs, documents or any personal files. Nothing on the PC is changed.

  Output: <Destination>\<PC>-<timestamp>\ (left in place for inspection), <PC>-<timestamp>.zip next to it, and
  <PC>-<timestamp>-SUMMARY.txt. Destination defaults to ACE-Telemetry-Output next to this script (falls back to the
  Desktop, then TEMP, when that folder is not writable). The summary opens in Notepad when the run finishes.

.EXAMPLE
  powershell -NoProfile -ExecutionPolicy Bypass -File .\Check-AceTelemetry.ps1
#>
[CmdletBinding()]
param(
  [string]$Destination = (Join-Path $(if ($PSScriptRoot) { $PSScriptRoot } else { [Environment]::GetFolderPath('Desktop') }) 'ACE-Telemetry-Output'),
  [switch]$NoZip
)

$Version = '2.1 (2026-10-08)'
$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$case = "$env:COMPUTERNAME-$stamp"
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host ''
Write-Host "ACE / NIKKE telemetry check $Version  (read-only; nothing on this PC is changed)"
Write-Host 'Close NIKKE and its launcher first. This takes one to three minutes.'
Write-Host ''
if (Get-Process -Name 'nikke', 'nikke_launcher' -ErrorAction SilentlyContinue) {
  Write-Warning 'NIKKE or its launcher is still running. Close them now, otherwise the result will be incomplete.'
  $null = Read-Host '  Press Enter once they are closed (or to continue anyway)'
}

# output folder: next to the script, else Desktop, else TEMP (a probe file is written because New-Item -Force succeeds on read-only folders)
function TryDir([string]$d) { try { New-Item -ItemType Directory -Force -Path $d -ErrorAction Stop | Out-Null; $probe = Join-Path $d ".write-test-$PID"; 'ok' | Out-File -FilePath $probe -ErrorAction Stop; Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue; return $true } catch { return $false } }
if (-not (TryDir $Destination)) {
  foreach ($alt in @((Join-Path ([Environment]::GetFolderPath('Desktop')) 'ACE-Telemetry-Output'), (Join-Path $env:TEMP 'ACE-Telemetry-Output'))) {
    if (TryDir $alt) { Write-Warning "Cannot write to $Destination; using $alt instead"; $Destination = $alt; break }
  }
  if (-not (TryDir $Destination)) { Write-Error 'No writable output folder (tried the script folder, the Desktop and TEMP). Extract the zip somewhere you can write to, such as Documents, and run it again.'; exit 1 }
}
Write-Host "Output folder: $Destination"
Write-Host ''
$root = Join-Path $Destination $case
New-Item -ItemType Directory -Force -Path $root | Out-Null
$log = Join-Path $root 'collection.log'

# ---------- helpers ----------
function Log([string]$m) { $line = "{0} {1}" -f (Get-Date -Format 'HH:mm:ss'), $m; try { Add-Content -LiteralPath $log -Value $line -Encoding UTF8 } catch {}; Write-Host $line }
function Save([string]$name, $content) {
  try { $p = Join-Path $root $name; $dir = Split-Path $p -Parent; if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }; $content | Out-File -FilePath $p -Encoding UTF8 -Width 800; Log "  saved $name" } catch { Log "  ! $name : $($_.Exception.Message)" }
}
function CopyTree([string]$src, [string]$dstRel, [string[]]$excludeFiles = @(), [string[]]$excludeDirs = @()) {
  if (-not (Test-Path -LiteralPath $src)) { Log "  - missing: $src"; return }
  $dst = Join-Path $root $dstRel; New-Item -ItemType Directory -Force -Path $dst | Out-Null
  $args = @($src, $dst, '/E', '/R:1', '/W:1', '/XJ', '/NP', '/NFL', '/NDL', '/NJH', '/NJS', '/COPY:DAT', '/DCOPY:T')
  if ($excludeFiles.Count) { $args += '/XF'; $args += $excludeFiles }
  if ($excludeDirs.Count)  { $args += '/XD'; $args += $excludeDirs }
  $null = & robocopy @args 2>&1
  $n = (Get-ChildItem -LiteralPath $dst -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count
  Log ("  + {0} -> {1}  ({2} files)" -f $src, $dstRel, $n)
}
function CopyFiles([string]$src, [string]$filter, [string]$dstRel) {
  if (-not (Test-Path -LiteralPath $src)) { Log "  - missing: $src"; return }
  $dst = Join-Path $root $dstRel; New-Item -ItemType Directory -Force -Path $dst | Out-Null
  $files = @(Get-ChildItem -LiteralPath $src -Filter $filter -File -ErrorAction SilentlyContinue); $ok = 0
  foreach ($f in $files) { try { Copy-Item -LiteralPath $f.FullName -Destination $dst -Force -ErrorAction Stop; $ok++ } catch { Log "    ! $($f.Name): $($_.Exception.Message)" } }
  Log "  + $src\$filter -> $dstRel ($ok/$($files.Count) files)"
}
function Hash-File([string]$path) { try { return (Get-FileHash -LiteralPath $path -Algorithm SHA256 -ErrorAction Stop).Hash } catch { return '' } }
function FileFacts([string[]]$paths, [string]$filter = '*') {
  foreach ($p in $paths) {
    if (-not (Test-Path -LiteralPath $p)) { continue }
    Get-ChildItem -LiteralPath $p -File -Recurse -Filter $filter -ErrorAction SilentlyContinue | ForEach-Object {
      $sig = $null; try { $sig = Get-AuthenticodeSignature -FilePath $_.FullName -ErrorAction Stop } catch {}
      [pscustomobject]@{ Path = $_.FullName; Size = $_.Length; Created = $_.CreationTime; Modified = $_.LastWriteTime; SHA256 = (Hash-File $_.FullName); FileVersion = $_.VersionInfo.FileVersion; Product = $_.VersionInfo.ProductName; Company = $_.VersionInfo.CompanyName; SigStatus = $(if ($sig) { $sig.Status } else { '' }); Signer = $(if ($sig -and $sig.SignerCertificate) { $sig.SignerCertificate.Subject } else { '' }) }
    }
  }
}
function Ts2S($v) { try { $n = [int64]$v; if ($n -gt 100000000000) { $n = [int64]($n / 1000) }; return ([DateTimeOffset]::FromUnixTimeSeconds($n)).ToLocalTime().ToString('yyyy-MM-dd HH:mm:ss') } catch { return "$v" } }
function Trunc([string]$s, [int]$n) { if (-not $s) { return '' }; $s = $s -replace '\s+', ' '; if ($s.Length -gt $n) { return $s.Substring(0, $n) + '...' } else { return $s } }
function Gunzip([byte[]]$raw) {
  if ($raw.Length -gt 2 -and $raw[0] -eq 0x1f -and $raw[1] -eq 0x8b) {
    $ms = New-Object IO.MemoryStream(,$raw); $gz = New-Object IO.Compression.GZipStream($ms, [IO.Compression.CompressionMode]::Decompress); $o = New-Object IO.MemoryStream
    $gz.CopyTo($o); $gz.Dispose(); $ms.Dispose(); return $o.ToArray()
  }
  return $raw
}

# ---------- native helpers: protobuf walker (no .proto needed) and Windows' built-in SQLite ----------
$canDecode = $false; $canSql = $false
try {
Add-Type -TypeDefinition @'
using System; using System.Collections.Generic; using System.Text;
public class PbNode { public int Depth; public string Path; public string Kind; public string Value; }
public static class PbWalk {
  static readonly UTF8Encoding Strict = new UTF8Encoding(false, true);
  public static bool Varint(byte[] b, ref int i, int end, out ulong r) { r = 0; int s = 0; while (i < end) { byte x = b[i++]; r |= (ulong)(x & 0x7F) << s; s += 7; if ((x & 0x80) == 0) return true; if (s > 63) return false; } return false; }
  public static string LooksText(byte[] b, int off, int len) {
    string t; try { t = Strict.GetString(b, off, len); } catch (Exception) { return null; }
    if (t.Length == 0) return "";
    int bad = 0; foreach (char c in t) { if (c < 32 && c != '\r' && c != '\n' && c != '\t') bad++; }
    return bad <= t.Length * 0.02 ? t : null;
  }
  static bool TrySub(byte[] b, int off, int len) { return len > 1 && Walk(b, off, len, 99, null, "", 100); }
  public static bool Walk(byte[] b, int off, int len, int depth, List<PbNode> outList, string path, int maxdepth) {
    int i = off, end = off + len;
    try {
      while (i < end) {
        ulong tag; if (!Varint(b, ref i, end, out tag)) return false;
        ulong fn = tag >> 3; int wt = (int)(tag & 7);
        string p = path.Length == 0 ? fn.ToString() : path + "." + fn;
        if (wt == 0) { ulong v; if (!Varint(b, ref i, end, out v)) return false; if (outList != null) outList.Add(new PbNode { Depth = depth, Path = p, Kind = "int", Value = v.ToString() }); }
        else if (wt == 1) { if (i + 8 > end) return false; if (outList != null) outList.Add(new PbNode { Depth = depth, Path = p, Kind = "i64", Value = BitConverter.ToUInt64(b, i).ToString() }); i += 8; }
        else if (wt == 5) { if (i + 4 > end) return false; if (outList != null) outList.Add(new PbNode { Depth = depth, Path = p, Kind = "i32", Value = BitConverter.ToUInt32(b, i).ToString() }); i += 4; }
        else if (wt == 2) {
          ulong ln; if (!Varint(b, ref i, end, out ln)) return false; if ((ulong)(end - i) < ln) return false;
          int l = (int)ln; int s = i; i += l;
          string t = LooksText(b, s, l);
          bool firstIsTag = l > 0 && (b[s] == 0x08 || b[s] == 0x0a || b[s] == 0x12 || b[s] == 0x1a || b[s] == 0x22 || b[s] == 0x2a || b[s] == 0x32);
          if (t != null && (l == 0 || !(firstIsTag && depth < maxdepth && TrySub(b, s, l)))) { if (outList != null) outList.Add(new PbNode { Depth = depth, Path = p, Kind = "str", Value = t }); }
          else if (depth < maxdepth && TrySub(b, s, l)) { if (outList != null) { outList.Add(new PbNode { Depth = depth, Path = p, Kind = "msg", Value = l.ToString() }); Walk(b, s, l, depth + 1, outList, p, maxdepth); } }
          else { if (outList != null) outList.Add(new PbNode { Depth = depth, Path = p, Kind = "bytes", Value = l.ToString() }); }
        }
        else return false;
      }
    } catch (Exception) { return false; }
    return true;
  }
}
'@ -ErrorAction Stop
  $canDecode = $true
} catch { Write-Warning "protobuf decoder could not be compiled ($($_.Exception.Message)); raw records are still collected" }
try {
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using System.Collections.Generic; using System.Text;
public static class WinSqlite {
  [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_open_v2(byte[] filename, out IntPtr db, int flags, IntPtr vfs);
  [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_prepare_v2(IntPtr db, byte[] sql, int nByte, out IntPtr stmt, IntPtr tail);
  [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_step(IntPtr stmt);
  [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_column_count(IntPtr stmt);
  [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)] static extern IntPtr sqlite3_column_name(IntPtr stmt, int col);
  [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_column_type(IntPtr stmt, int col);
  [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)] static extern IntPtr sqlite3_column_text(IntPtr stmt, int col);
  [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_column_bytes(IntPtr stmt, int col);
  [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_finalize(IntPtr stmt);
  [DllImport("winsqlite3.dll", CallingConvention = CallingConvention.Cdecl)] static extern int sqlite3_close_v2(IntPtr db);
  static byte[] Z(string s) { return Encoding.UTF8.GetBytes(s + "\0"); }
  static string Utf8(IntPtr p, int len) { if (p == IntPtr.Zero || len <= 0) return ""; byte[] buf = new byte[len]; Marshal.Copy(p, buf, 0, len); return Encoding.UTF8.GetString(buf); }
  public static List<Dictionary<string, string>> Query(string file, string sql) {
    var rows = new List<Dictionary<string, string>>();
    IntPtr db; int rc = sqlite3_open_v2(Z(file), out db, 1, IntPtr.Zero);
    if (rc != 0) throw new Exception("sqlite open failed rc=" + rc);
    try {
      IntPtr stmt; rc = sqlite3_prepare_v2(db, Z(sql), -1, out stmt, IntPtr.Zero);
      if (rc != 0) throw new Exception("sqlite prepare failed rc=" + rc + " for " + sql);
      try {
        int n = sqlite3_column_count(stmt);
        while (sqlite3_step(stmt) == 100) {
          var row = new Dictionary<string, string>();
          for (int c = 0; c < n; c++) {
            string name = Marshal.PtrToStringAnsi(sqlite3_column_name(stmt, c));
            int type = sqlite3_column_type(stmt, c);
            string val;
            if (type == 5) val = ""; else if (type == 4) val = "<blob " + sqlite3_column_bytes(stmt, c) + " bytes>"; else { IntPtr tp = sqlite3_column_text(stmt, c); val = Utf8(tp, sqlite3_column_bytes(stmt, c)); }
            row[name] = val;
          }
          rows.Add(row);
        }
      } finally { sqlite3_finalize(stmt); }
    } finally { sqlite3_close_v2(db); }
    return rows;
  }
}
'@ -ErrorAction Stop
  $canSql = $true
} catch { Write-Warning "SQLite helper could not be compiled ($($_.Exception.Message)); upload status will be unknown" }
Add-Type -TypeDefinition @'
using System; using System.Runtime.InteropServices; using Microsoft.Win32;
public static class RegKeyTime {
  [DllImport("ntdll.dll")] static extern int NtQueryKey(IntPtr h, int c, IntPtr b, int l, out int r);
  public static DateTime Get(RegistryKey k) { IntPtr h = k.Handle.DangerousGetHandle(); int len; IntPtr buf = Marshal.AllocHGlobal(1024); int st = NtQueryKey(h, 0, buf, 1024, out len); long ft = Marshal.ReadInt64(buf); Marshal.FreeHGlobal(buf); return st == 0 ? DateTime.FromFileTime(ft) : DateTime.MinValue; }
}
'@ -ErrorAction SilentlyContinue

Log "=== ACE telemetry check $Version  case=$case  admin=$isAdmin  PS=$($PSVersionTable.PSVersion)  decoder=$canDecode sqlite=$canSql"

# ---------- 1. basic system facts (no serial numbers, no machine ids) ----------
Log "[1] system"
$os = Get-CimInstance Win32_OperatingSystem
$sys = [ordered]@{
  ComputerName = $env:COMPUTERNAME; Elevated = $isAdmin; CollectedAt = (Get-Date).ToString('o'); CollectorVersion = $Version; Kind = 'telemetry-check'
  OS = "$($os.Caption) $($os.Version) build $($os.BuildNumber)"; LastBoot = $os.LastBootUpTime.ToString('o'); TimeZone = (Get-TimeZone).Id
  CPU = ((Get-CimInstance Win32_Processor | ForEach-Object { $_.Name.Trim() }) -join '; ')
  GPU = ((Get-CimInstance Win32_VideoController | ForEach-Object { "$($_.Name) [$($_.DriverVersion)]" }) -join '; ')
  TotalRAM_GB = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
}
Save 'system\system-info.json' ($sys | ConvertTo-Json -Depth 3)

# ---------- 2. ACE facts (versions, hashes, registry; no binaries copied) ----------
Log "[2] ACE"
$aceDrivers = @(Get-CimInstance Win32_SystemDriver | Where-Object { $_.Name -match '^ACE-' })
Save 'ace\driver-state.txt' ($aceDrivers | Select-Object Name, State, StartMode, PathName | Format-Table -AutoSize | Out-String -Width 300)
$pfAce = Join-Path $env:ProgramFiles 'AntiCheatExpert'; $pdAce = Join-Path $env:ProgramData 'AntiCheatExpert'
$facts = @(FileFacts @($pfAce, $pdAce)) + @(Get-ChildItem "$env:SystemRoot\System32\drivers\ACE-*.sys" -ErrorAction SilentlyContinue | ForEach-Object { FileFacts @($_.FullName) })
$facts | Export-Csv -LiteralPath (Join-Path $root 'ace\file-facts.csv') -NoTypeInformation -Encoding UTF8
Save 'ace\ace-data-listing.txt' (Get-ChildItem -LiteralPath $pdAce -Recurse -File -ErrorAction SilentlyContinue | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize | Out-String -Width 300)
New-Item -ItemType Directory -Force -Path (Join-Path $root 'ace\registry') | Out-Null
$svcKeys = @(Get-ChildItem 'HKLM:\SYSTEM\CurrentControlSet\Services' -ErrorAction SilentlyContinue | Where-Object { $_.PSChildName -match '^ACE-|AntiCheatExpert' } | ForEach-Object { $_.PSChildName })
$times = @()
foreach ($k in $svcKeys) {
  $null = & reg.exe export "HKLM\SYSTEM\CurrentControlSet\Services\$k" (Join-Path $root "ace\registry\svc_$($k -replace '[^A-Za-z0-9_.-]','_').reg") /y 2>&1
  try { $rk = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\$k"); if ($rk) { $times += [pscustomobject]@{ Key = "Services\$k"; LastWrite = [RegKeyTime]::Get($rk) }; $rk.Close() } } catch { $times += [pscustomobject]@{ Key = "Services\$k"; LastWrite = 'access denied' } }
}
$fakeCount = 0; $classNames = @()
try {
  $cls = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey('SYSTEM\CurrentControlSet\Control\Class')
  $fake = @($cls.GetSubKeyNames() | Where-Object { $_ -match '-3202-12e0-ef96-251a2132e976\}$' }); $fakeCount = $fake.Count
  $classNames = @($cls.GetSubKeyNames() | ForEach-Object { try { $k = $cls.OpenSubKey($_); $c = [string]$k.GetValue('Class'); $k.Close(); if ($c -match 'ACE|AntiCheat|EasyAnti') { "$_ Class=$c" } } catch {} })
} catch {}
Save 'ace\registry\fake-device-classes.txt' (@("ACE-pattern device class keys: $fakeCount") + $fake + '' + 'Anti-cheat device classes:' + $classNames)
$times | Export-Csv -LiteralPath (Join-Path $root 'ace\registry\key-lastwrite-times.csv') -NoTypeInformation -Encoding UTF8
$aceBase = $facts | Where-Object { $_.Path -like '*\System32\drivers\ACE-BASE.sys' } | Select-Object -First 1
$aceAdvt = $facts | Where-Object { $_.Path -like '*\System32\drivers\ACE-ADVT.sys' } | Select-Object -First 1

# ---------- 3. the game: CrashSight records, session logs, attachments ----------
Log "[3] NIKKE"
$gameDir = $null
$unins = Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall' -ErrorAction SilentlyContinue | ForEach-Object { Get-ItemProperty $_.PSPath } | Where-Object { $_.DisplayName -match 'NIKKE|GODDESS OF VICTORY' -or $_.Publisher -match 'Level Infinite|Proxima|Shift Up' }
$candidates = @()
foreach ($u in $unins) { foreach ($v in @($u.InstallLocation, $u.UninstallString, $u.DisplayIcon)) { if ($v) { $m = [regex]::Match($v, '[A-Za-z]:\\[^"]+'); if ($m.Success) { $candidates += $m.Value } } } }
foreach ($d in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null })) {
  foreach ($sub in @('NIKKE', 'Games\NIKKE', 'Program Files\NIKKE', 'Level Infinite\NIKKE', 'GODDESS OF VICTORY NIKKE')) { $candidates += (Join-Path $d.Root $sub) }
  try { $candidates += Get-ChildItem -Path $d.Root -Directory -Depth 1 -ErrorAction SilentlyContinue | Where-Object { $_.Name -match 'nikke' } | ForEach-Object { $_.FullName } } catch {}
}
foreach ($c in ($candidates | Select-Object -Unique)) {
  if (-not $c) { continue }
  $probe = $c; for ($i = 0; $i -lt 4 -and $probe; $i++) {
    foreach ($rel in @('NIKKE\game\nikke.exe', 'game\nikke.exe', 'nikke.exe')) { $p = Join-Path $probe $rel; if (Test-Path -LiteralPath $p) { $gameDir = Split-Path $p -Parent; break } }
    if ($gameDir) { break }
    $probe = Split-Path $probe -Parent
  }
  if ($gameDir) { break }
}
if (-not $gameDir) {
  Log "  searching drives (depth 3) for nikke.exe"
  foreach ($d in (Get-PSDrive -PSProvider FileSystem | Where-Object { $_.Free -ne $null })) { try { $hit = Get-ChildItem -Path $d.Root -Filter 'nikke.exe' -File -Recurse -Depth 3 -ErrorAction SilentlyContinue | Select-Object -First 1; if ($hit) { $gameDir = $hit.DirectoryName; break } } catch {} }
}
$csLogCount = 0
if ($gameDir) {
  Log "  game dir: $gameDir"
  Save 'game\paths.txt' (@("GameDir=$gameDir", "InstallRoot=$(Split-Path (Split-Path $gameDir -Parent) -Parent)"))
  CopyTree (Join-Path $gameDir 'wesight') 'game\wesight'
  CopyTree (Join-Path $gameDir 'CrashSightLog') 'game\CrashSightLog'
  CopyTree (Join-Path $gameDir 'attachment') 'game\attachment'
  $csLogCount = (Get-ChildItem (Join-Path $root 'game\CrashSightLog') -Filter *.log -File -ErrorAction SilentlyContinue | Measure-Object).Count
  (FileFacts @((Join-Path $gameDir 'AntiCheatExpert'))) | Export-Csv -LiteralPath (Join-Path $root 'game\AntiCheatExpert-file-facts.csv') -NoTypeInformation -Encoding UTF8
  (FileFacts @((Join-Path $gameDir 'nikke.exe'), (Join-Path $gameDir 'GameAssembly.dll'))) | Export-Csv -LiteralPath (Join-Path $root 'game\game-binaries-facts.csv') -NoTypeInformation -Encoding UTF8
} else { Log "  ! NIKKE not found on this PC (no nikke.exe)" }

# ---------- 4. per-user: Player.log, INTL queues, launcher database, account cache names, EAC lines ----------
Log "[4] user data"
$profiles = @(Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin 'Public','Default','Default User','All Users' })
$profilesFound = @(); $aceLogins = 0; $aceLines = 0; $intlGameQueue = 0; $intlLauncherQueue = 0; $cacheAccounts = @(); $launcherAccounts = 0; $eacRefusals = 0; $eacProducts = @(); $eacDates = @()
$playerLogs = @()
foreach ($pr in $profiles) {
  $u = $pr.FullName; $tag = "users\$($pr.Name)"
  $has = $false; foreach ($p in @("$u\AppData\LocalLow\com.proximabeta", "$u\AppData\LocalLow\com_proximabeta", "$u\AppData\Roaming\nikke_launcher", "$u\AppData\Roaming\EasyAntiCheat")) { if (Test-Path -LiteralPath $p) { $has = $true } }
  if (-not $has) { continue }
  $profilesFound += $pr.Name; Log "  profile $($pr.Name)"
  # game log: ACE init and each login
  CopyFiles "$u\AppData\LocalLow\com.proximabeta\NIKKE" 'Player*.log' "$tag\LocalLow_com.proximabeta_NIKKE"
  $pl = @(Get-ChildItem "$u\AppData\LocalLow\com.proximabeta\NIKKE\Player*.log" -ErrorAction SilentlyContinue)
  if ($pl) {
    $playerLogs += $pl.FullName
    $lines = @($pl | Select-String -CaseSensitive -Pattern '(^|[^A-Za-z])ACE([^A-Za-z]|$)|AntiCheat|anti-cheat' -ErrorAction SilentlyContinue)
    $aceLines += $lines.Count; $aceLogins += @($lines | Where-Object { $_.Line -match 'ACE log in success' }).Count
    Save "$tag\player-ace-lines.txt" ($lines | ForEach-Object { "$($_.Filename):$($_.LineNumber): $($_.Line.Trim())" })
  }
  # per-account game cache: names only (which accounts were used here, and when); INTL SDK queue copied (small, encrypted)
  $ll = "$u\AppData\LocalLow\com_proximabeta\NIKKE"
  if (Test-Path -LiteralPath $ll) {
    $cache = @(Get-ChildItem -LiteralPath $ll -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.nkcache$|^NKPERSISTSD_|^NKSD_TRIGGER_' })
    $cache | Select-Object Name, Length, LastWriteTime | Export-Csv -LiteralPath (Join-Path (New-Item -ItemType Directory -Force -Path (Join-Path $root "$tag\LocalLow_com_proximabeta_NIKKE")).FullName 'account-cache-listing.csv') -NoTypeInformation -Encoding UTF8
    $cacheAccounts += @($cache | Where-Object { $_.Name -match '^(\d+_\d+)\.nkcache$' } | ForEach-Object { [pscustomobject]@{ Account = $_.BaseName; LastUsed = $_.LastWriteTime } })
    CopyFiles $ll '*.json' "$tag\LocalLow_com_proximabeta_NIKKE"
    foreach ($rep in (Get-ChildItem "$ll\INTL\*\NIKKE\report" -Directory -ErrorAction SilentlyContinue)) { CopyTree $rep.FullName "$tag\LocalLow_com_proximabeta_NIKKE\INTL_report"; $intlGameQueue += (Get-ChildItem $rep.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count }
    Save "$tag\LocalLow_com_proximabeta_NIKKE\INTL-listing.txt" (Get-ChildItem "$ll\INTL" -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.FullName -notmatch '\\(webview_cache|Cache|Code Cache|GPUCache)\\' } | Select-Object FullName, Length, LastWriteTime | Format-Table -AutoSize | Out-String -Width 300)
  }
  # launcher: database with one user_* table per account, INTL service queue and key-value store (tokens excluded)
  $nl = "$u\AppData\Roaming\nikke_launcher"
  if (Test-Path -LiteralPath $nl) {
    CopyFiles $nl 'production_gl_launcher.db*' "$tag\Roaming_nikke_launcher"
    CopyFiles $nl 'last_user.dat' "$tag\Roaming_nikke_launcher"
    foreach ($rep in (Get-ChildItem "$nl\*\intl_service\report" -Directory -ErrorAction SilentlyContinue)) { CopyTree $rep.FullName "$tag\Roaming_nikke_launcher\intl_service_report"; $intlLauncherQueue += (Get-ChildItem $rep.FullName -Recurse -File -ErrorAction SilentlyContinue | Measure-Object).Count }
    foreach ($mm in (Get-ChildItem "$nl\*\intl_service\mmkv" -Directory -ErrorAction SilentlyContinue)) { CopyTree $mm.FullName "$tag\Roaming_nikke_launcher\intl_service_mmkv" }
    if ($canSql) {
      $ldb = Join-Path $root "$tag\Roaming_nikke_launcher\production_gl_launcher.db"
      if (Test-Path -LiteralPath $ldb) { try { $t = [WinSqlite]::Query($ldb, "select name from sqlite_master where type='table' and name like 'user_%'"); $launcherAccounts += $t.Count; Save "$tag\Roaming_nikke_launcher\launcher-account-tables.txt" ($t | ForEach-Object { $_['name'] }) } catch { Log "  ! launcher db: $($_.Exception.Message)" } }
    }
  }
  # Easy Anti-Cheat: did other games refuse to start because ACE-BASE was loaded?
  $eac = "$u\AppData\Roaming\EasyAntiCheat"
  if (Test-Path -LiteralPath $eac) {
    $eacLogs = @(Get-ChildItem -LiteralPath $eac -Recurse -Filter *.log -File -ErrorAction SilentlyContinue)
    $eacProducts += @($eacLogs | ForEach-Object { $_.Directory.Parent.Name } | Select-Object -Unique)
    $hitsEac = @($eacLogs | Select-String -CaseSensitive -Pattern 'ACE-BASE|ACE-|AntiCheatExpert' -ErrorAction SilentlyContinue)
    $eacRefusals += @($hitsEac | Where-Object { $_.Line -match 'ACE-BASE' }).Count
    $eacDates += @($hitsEac | Where-Object { $_.Line -match 'ACE-BASE' } | ForEach-Object { (Get-Item $_.Path).LastWriteTime })
    Save "$tag\eac-ace-lines.txt" (@("EAC product folders: $((@($eacLogs | ForEach-Object { $_.Directory.Parent.Name } | Select-Object -Unique)).Count); log files: $($eacLogs.Count)") + ($hitsEac | ForEach-Object { "$($_.Path.Substring($eac.Length + 1)):$($_.LineNumber): $($_.Line.Trim())" }))
  }
}
$eacProducts = @($eacProducts | Select-Object -Unique)

# ---------- 5. Windows event entries about ACE and NIKKE (filtered, no full log export) ----------
Log "[5] Windows events (filtered)"
New-Item -ItemType Directory -Force -Path (Join-Path $root 'windows') | Out-Null
try {
  $sysEv = @()
  $sysEv += Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; Id=7045} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'ACE|EasyAnti|BEService|vgk' }
  $sysEv += Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-FilterManager'} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'ACE|EasyAnti' }
  $sysEv += Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Application Popup'} -ErrorAction SilentlyContinue | Where-Object { $_.Message -match 'ACE|AntiCheat|nikke' }
  $sysEv = $sysEv | Sort-Object TimeCreated
  $sysEv | Select-Object TimeCreated, Id, ProviderName, @{n='Message';e={($_.Message -replace '\s+',' ')}} | Export-Csv -LiteralPath (Join-Path $root 'windows\system-anticheat-events.csv') -NoTypeInformation -Encoding UTF8
  Log "  System events about anti-cheat: $($sysEv.Count)"
} catch { Log "  ! System log: $($_.Exception.Message)" }
try {
  $appEv = @(Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName=@('Application Error','Application Hang','Windows Error Reporting')} -ErrorAction Stop | Where-Object { $_.Message -match 'nikke|AntiCheat|ACE-|nikke_launcher|intl_service' })
  $appEv | Select-Object TimeCreated, Id, ProviderName, @{n='Message';e={($_.Message -replace '\s+',' ')}} | Export-Csv -LiteralPath (Join-Path $root 'windows\application-game-crash-events.csv') -NoTypeInformation -Encoding UTF8
  Log "  Application events about NIKKE: $($appEv.Count)"
} catch { Log "  ! Application log: $($_.Exception.Message)" }

# ---------- 6. decode the CrashSight records ----------
Log "[6] decoding CrashSight records"
New-Item -ItemType Directory -Force -Path (Join-Path $root 'crashsight') | Out-Null
$csDir = Join-Path $root 'game\wesight\crashsight_data'
$rows = @(); $kvSeen = @{}; $kv2Seen = @{}; $pathSeen = @{}; $recordText = @{}; $status = @{}; $strategy = @(); $lastUser = ''; $dbRead = $false
$known = @{ '6.2'='app id'; '6.4'='game version'; '6.6'='crash reporter sdk version'; '6.8.1.3'='exception type'; '6.8.1.4'='exception message'; '6.8.1.7'='stack trace'; '6.8.1.9'='record uuid'; '6.8.1.12'='user id'; '6.8.1.17.2'='attachment name'; '6.8.1.18.1'='engine/build info key'; '6.8.1.18.2'='engine/build info value'; '6.8.1.26'='process name'; '6.8.1.29.1'='game key'; '6.8.1.29.2'='game value'; '6.10'='operating system'; '6.11.1'='extra device info key'; '6.11.2'='extra device info value'; '6.12'='session id'; '6.15'='MAC address'; '6.21'='MAC address'; '6.33'='GPU'; '6.34'='screen resolution'; '6.35'='GPU driver'; '6.36'='GPU (renderer)'; '6.38'='CPU'; '6.40'='time zone' }
if (Test-Path -LiteralPath $csDir) {
  if ($canSql) {
    $db = Get-ChildItem -LiteralPath $csDir -Filter '*crashsight_data_db' -File -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($db) {
      try {
        foreach ($r in [WinSqlite]::Query($db.FullName, 'select STATUS, STATUS_TIME, PATH from T_CRASH_RECORD')) { $status[[IO.Path]::GetFileName($r['PATH'])] = @{ Status = $r['STATUS']; Time = $r['STATUS_TIME'] } }
        $lastUser = (@([WinSqlite]::Query($db.FullName, 'select * from T_LOCAL_RECORD')) | ForEach-Object { ($_.GetEnumerator() | ForEach-Object { if ($_.Key -match 'TIME' -and $_.Value -match '^\d{9,}$') { "$($_.Key)=$(Ts2S $_.Value)" } else { "$($_.Key)=$($_.Value)" } }) -join ' ' }) -join ' | '
        $strategy = @([WinSqlite]::Query($db.FullName, 'select KEY, VALUE from T_STRATEGY') | ForEach-Object { "$($_['KEY']) = $($_['VALUE'])" })
        Save 'crashsight\strategy.txt' (@("T_LOCAL_RECORD: $lastUser", '', 'T_STRATEGY (server-side reporting settings pushed to this client):') + $strategy)
        $dbRead = $true; Log "  database: $($status.Count) record rows, $($strategy.Count) strategy rows"
      } catch { Log "  ! database read failed: $($_.Exception.Message)" }
    }
  }
  if ($canDecode) {
    $files = @(Get-ChildItem -LiteralPath $csDir -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^(merged_)?error_data\.info_(\d+)_' } | Sort-Object Name)
    foreach ($fi in $files) {
      $m = [regex]::Match($fi.Name, '^(merged_)?error_data\.info_(\d+)_')
      try {
        $raw = [IO.File]::ReadAllBytes($fi.FullName); $b = Gunzip $raw
        $nodes = New-Object 'System.Collections.Generic.List[PbNode]'
        [void][PbWalk]::Walk($b, 0, $b.Length, 0, $nodes, '', 6)
      } catch { Log "  ! decode failed: $($fi.Name): $($_.Exception.Message)"; continue }
      $f = @{}; $kv = @{}; $last = $null; $last2 = $null; $texts = New-Object 'System.Collections.Generic.List[string]'
      foreach ($n in $nodes) {
        if ($n.Path -eq '6.8.1.29.1') { $last = $n.Value; continue }
        if ($n.Path -eq '6.8.1.29.2' -and $n.Kind -eq 'str' -and $last) {
          if (-not $kv.ContainsKey($last)) { $kv[$last] = $n.Value }
          if (-not $kvSeen.ContainsKey($last)) { $kvSeen[$last] = @{ Count = 0; Example = $n.Value } }; $kvSeen[$last].Count++
          $texts.Add("$last=$($n.Value)"); $last = $null; continue
        }
        if ($n.Path -eq '6.8.1.18.1') { $last2 = $n.Value; continue }
        if ($n.Path -eq '6.8.1.18.2' -and $n.Kind -eq 'str' -and $last2) {
          if (-not $kv2Seen.ContainsKey($last2)) { $kv2Seen[$last2] = @{ Count = 0; Example = $n.Value } }; $kv2Seen[$last2].Count++
          $texts.Add("$last2=$($n.Value)"); $last2 = $null; continue
        }
        if ($n.Kind -eq 'str') { if (-not $f.ContainsKey($n.Path)) { $f[$n.Path] = $n.Value }; if ($n.Value) { $texts.Add($n.Value) } }
        if ($n.Kind -ne 'msg' -and $n.Kind -ne 'bytes') { if (-not $pathSeen.ContainsKey($n.Path)) { $pathSeen[$n.Path] = @{ Kind = $n.Kind; Count = 0; Example = $n.Value } }; $pathSeen[$n.Path].Count++ }
      }
      $frames = @(); if ($f['6.8.1.7']) { $frames = @(($f['6.8.1.7'] -split "`n") | Where-Object { $_.Trim() }) }
      $top = ''; if ($frames.Count) { $top = ($frames[0].Trim() -replace '\s*\(.*$', '') }
      $st = $status[$fi.Name]
      $stText = if ($st) { if ("$($st.Status)" -eq '1') { 'uploaded' } else { 'pending' } } elseif ($dbRead) { 'not in db' } else { 'unknown (database not read)' }
      $rows += [pscustomobject]@{
        file = $fi.Name; type = $(if ($m.Groups[1].Success) { 'merged' } else { 'single' }); logged = (Ts2S $m.Groups[2].Value)
        status = $stText; status_time = $(if ($st -and $st.Time) { Ts2S $st.Time } else { '' })
        app_id = $f['6.2']; game_version = $f['6.4']; record_uuid = $f['6.8.1.9']; uid = $f['6.8.1.12']
        nickname = $kv['user.nickName']; usn = $kv['user.USN']; openid = $kv['openId']; world = $kv['worldId']; server = $kv['user.server']; level = $kv['user.LV']
        scene = $kv['on.activeSceneChanged']; view = (("$($kv['view'])" -split ',')[0])
        error_type = $f['6.8.1.3']; message = (Trunc $f['6.8.1.4'] 200); top_frame = (Trunc $top 160); frames = $frames.Count
        os = $f['6.10']; cpu = ("$($f['6.38'])".Trim()); gpu = $f['6.33']; gpu_driver = $f['6.35']; resolution = $f['6.34']; mac = $f['6.15']; timezone = $f['6.40']; session_guid = $f['6.12']
        decoded_bytes = $b.Length; file_bytes = $raw.Length
      }
      $recordText[$fi.Name] = ($texts -join "`n")
    }
    Log "  decoded $($rows.Count) of $($files.Count) records"
    if ($rows.Count) {
      $rows | Export-Csv -LiteralPath (Join-Path $root 'crashsight\decoded-records.csv') -NoTypeInformation -Encoding UTF8
      $fieldLines = @('Every field found in the crash reports on this PC (one line per field, tab-separated).', 'KV = key/value pairs the game attaches to each report; FIELD = protobuf field path with a name when known.', '', "kind`tname`tcount`texample")
      $fieldLines += $kvSeen.GetEnumerator() | Sort-Object { -$_.Value.Count }, Name | ForEach-Object { "KV`t$($_.Name)`t$($_.Value.Count)`t$(Trunc $_.Value.Example 120)" }
      $fieldLines += $kv2Seen.GetEnumerator() | Sort-Object { -$_.Value.Count }, Name | ForEach-Object { "KV-engine`t$($_.Name)`t$($_.Value.Count)`t$(Trunc $_.Value.Example 120)" }
      $fieldLines += $pathSeen.GetEnumerator() | Sort-Object Name | ForEach-Object { $nm = if ($known[$_.Name]) { "$($_.Name) ($($known[$_.Name]))" } else { $_.Name }; "FIELD`t$nm`t$($_.Value.Count)`t$($_.Value.Kind): $(Trunc $_.Value.Example 120)" }
      Save 'crashsight\fields-seen.txt' $fieldLines
    }
  } else { Log '  (decoder unavailable: raw records collected for offline decoding)' }
} else { Log '  - no crashsight_data folder collected' }

$uploaded = @($rows | Where-Object { $_.status -eq 'uploaded' })
$pending = @($rows | Where-Object { $_.status -eq 'pending' })
$accounts = @($uploaded | Group-Object uid | ForEach-Object {
  $g = $_.Group
  [pscustomobject]@{ uid = $(if ($_.Name) { $_.Name } else { '(no account: sent before login)' }); nickname = (@($g | Where-Object nickname | Select-Object -First 1).nickname); openid = (@($g | Where-Object openid | Select-Object -First 1).openid); world = (@($g | Where-Object world | Select-Object -First 1).world); server = (@($g | Where-Object server | Select-Object -First 1).server); levels = ((@($g | Where-Object level | ForEach-Object { $_.level }) | Sort-Object -Unique) -join ' '); uploaded_reports = $g.Count; first = (@($g | Sort-Object logged | Select-Object -First 1).logged); last = (@($g | Sort-Object logged | Select-Object -Last 1).logged) }
} | Sort-Object uploaded_reports -Descending)
if ($accounts.Count) { $accounts | Export-Csv -LiteralPath (Join-Path $root 'crashsight\accounts-uploaded.csv') -NoTypeInformation -Encoding UTF8 }
$macs = @($rows | Where-Object mac | ForEach-Object { $_.mac } | Select-Object -Unique)
$gameVersions = @($rows | Where-Object game_version | ForEach-Object { $_.game_version } | Select-Object -Unique)

# ---------- 7. verdict / cheat / ban wording scan ----------
Log "[7] scanning for verdict-like wording"
$verdictRx = '(?i)verdict|cheat|abnormal|punish|\bbanned?\b|\bkick|violat|suspect|macro|inject|\bhack|forbid|illegal|sanction|penalt|blacklist'
# the game's own code contains a class named NK.Common.Cheat.NKCommandHandler (a debug command handler); log lines naming it are not verdicts
$ignoreRx = '(?i)NK\.Common\.Cheat\.|referenced script .* is missing'
$hits = New-Object 'System.Collections.Generic.List[string]'; $scanned = 0; $hitCount = 0; $ignored = 0
function ScanLines([string]$label, $lines) {
  $n = 0
  foreach ($l in @($lines)) { if ($l -and ($l -match $verdictRx)) { if ($l -match $ignoreRx) { $script:ignored++; continue }; $n++; if ($n -le 25) { $script:hits.Add("$label : $(Trunc $l 240)") } } }
  if ($n -gt 25) { $script:hits.Add("$label : ... $($n - 25) more lines") }
  $script:scanned++; $script:hitCount += $n
}
foreach ($k in $recordText.Keys) { ScanLines "report $k" ($recordText[$k] -split "`n") }
foreach ($lf in (Get-ChildItem (Join-Path $root 'game\CrashSightLog') -Filter *.log -File -ErrorAction SilentlyContinue)) { ScanLines "session log $($lf.Name)" (Get-Content -LiteralPath $lf.FullName -ErrorAction SilentlyContinue) }
foreach ($pf in (Get-ChildItem (Join-Path $root 'users') -Recurse -Filter 'Player*.log' -File -ErrorAction SilentlyContinue)) { ScanLines "game log $($pf.Name)" (Get-Content -LiteralPath $pf.FullName -ErrorAction SilentlyContinue) }
foreach ($af in (Get-ChildItem (Join-Path $root 'game\attachment') -Recurse -Include *.txt,*.log -File -ErrorAction SilentlyContinue)) { ScanLines "attachment $($af.Name)" (Get-Content -LiteralPath $af.FullName -ErrorAction SilentlyContinue) }
if ($strategy.Count) { ScanLines 'crash reporter strategy (server settings)' $strategy }
if ($lastUser) { ScanLines 'crash reporter local record' @($lastUser) }
$recordHits = $hitCount
# ACE's own data/config files: wording here describes detection settings in general, not a finding about this PC
$cfgHits = New-Object 'System.Collections.Generic.List[string]'
$cfgPaths = @($pdAce, $pfAce); if ($gameDir) { $cfgPaths += (Join-Path $gameDir 'AntiCheatExpert') }
foreach ($cf in @(Get-ChildItem -Path $cfgPaths -Filter *.dat -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 20MB })) {
  try {
    $bytes = [IO.File]::ReadAllBytes($cf.FullName); $latin = [Text.Encoding]::GetEncoding(28591).GetString($bytes)
    $strs = @([regex]::Matches($latin, '[\x20-\x7e]{6,}') | ForEach-Object { $_.Value }) + @([regex]::Matches($latin, '(?:[\x20-\x7e]\x00){6,}') | ForEach-Object { $_.Value -replace "`0", '' })
    $n = 0; foreach ($s in $strs) { if ($s -match $verdictRx) { $n++; if ($n -le 15) { $cfgHits.Add("$($cf.Name) : $(Trunc $s 160)") } } }
    if ($n -gt 15) { $cfgHits.Add("$($cf.Name) : ... $($n - 15) more strings") }
  } catch {}
}
Save 'crashsight\verdict-scan.txt' (@("records/logs hits: $recordHits", "ace config hits: $($cfgHits.Count)", "files scanned: $scanned", "ignored game-internal lines: $ignored (the game's own code has a class named NK.Common.Cheat.NKCommandHandler; lines naming it are not verdicts)", "pattern: $verdictRx", '',
  'A) Reports, session logs, game logs and crash-reporter settings on this PC (wording that would describe a verdict about this player):') + $(if ($hits.Count) { $hits } else { @('  none found') }) +
  @('', 'B) Strings inside ACE''s own config/data files (generic detection settings shipped with the anti-cheat; NOT a finding about this PC):') + $(if ($cfgHits.Count) { $cfgHits } else { @('  none found') }))

# ---------- 8. manifest, zip, summary ----------
Log "[8] manifest and zip"
$all = @(Get-ChildItem -LiteralPath $root -Recurse -File -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'collection.log' })
$all | ForEach-Object { [pscustomobject]@{ RelativePath = $_.FullName.Substring($root.Length + 1); Size = $_.Length; Modified = $_.LastWriteTime; SHA256 = (Hash-File $_.FullName) } } | Export-Csv -LiteralPath (Join-Path $root 'manifest.csv') -NoTypeInformation -Encoding UTF8
$total = ($all | Measure-Object Length -Sum).Sum
$zip = $null; $zipSha = ''
if (-not $NoZip) {
  $zip = "$root.zip"; $zipped = $false
  try { Compress-Archive -Path (Join-Path $root '*') -DestinationPath $zip -CompressionLevel Optimal -Force -ErrorAction Stop; $zipped = $true }
  catch {
    Log "  ! Compress-Archive failed ($($_.Exception.Message.Split([char]10)[0])); trying tar.exe"
    if (Test-Path -LiteralPath $zip) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }
    $tar = Join-Path $env:SystemRoot 'System32\tar.exe'
    if (Test-Path -LiteralPath $tar) { $null = & $tar -a -c -f $zip -C $root . 2>&1; if ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $zip)) { $zipped = $true } }
  }
  if ($zipped) { $zipSha = Hash-File $zip; Log ("zip: {0} ({1:N1} MB) sha256 {2}" -f $zip, ((Get-Item -LiteralPath $zip).Length / 1MB), $zipSha) } else { Log '  ! zip not created; zip the case folder by hand'; $zip = $null }
}

$dr = if ($rows.Count) { "$((@($rows | Sort-Object logged | Select-Object -First 1).logged).Substring(0,10)) .. $((@($rows | Sort-Object logged | Select-Object -Last 1).logged).Substring(0,10))" } else { '' }
$eacRange = if ($eacDates.Count) { "$(($eacDates | Sort-Object | Select-Object -First 1).ToString('yyyy-MM-dd')) .. $(($eacDates | Sort-Object | Select-Object -Last 1).ToString('yyyy-MM-dd'))" } else { '' }
$cacheLast = if ($cacheAccounts.Count) { ($cacheAccounts | Sort-Object LastUsed | Select-Object -Last 1).LastUsed.ToString('yyyy-MM-dd') } else { '' }
$summary = @(
  "ACE / NIKKE TELEMETRY CHECK - SUMMARY                          collector $Version, read-only"
  "=================================================================================="
  "PC              : $env:COMPUTERNAME   |  $($sys.OS)   |  collected $((Get-Date).ToString('yyyy-MM-dd HH:mm'))  admin=$isAdmin"
  "NIKKE           : $(if ($gameDir) { $gameDir } else { 'not found on this PC' })   |  game version(s) in reports: $(if ($gameVersions) { $gameVersions -join ', ' } else { 'n/a' })"
  "ACE             : ACE-BASE.sys $(if ($aceBase) { "v$($aceBase.FileVersion) ($($aceBase.Modified.ToString('yyyy-MM-dd')))" } else { 'not installed' })  ACE-ADVT.sys $(if ($aceAdvt) { "v$($aceAdvt.FileVersion)" } else { 'absent' })  |  drivers now: $(if ($aceDrivers) { ($aceDrivers | ForEach-Object { "$($_.Name)=$($_.State)" }) -join ', ' } else { 'none registered' })  |  hidden device classes: $fakeCount"
  ""
  "1) CRASH REPORTS UPLOADED TO TENCENT (CrashSight, pc.crashsight.wetest.net)"
  "   reports still on disk: $($rows.Count) ($dr)   uploaded: $($uploaded.Count)   pending: $($pending.Count)   $(if (-not $dbRead) { '(upload status unknown: database not readable)' })"
  "   accounts tagged in the uploaded reports:"
) + $(if ($accounts.Count) { $accounts | ForEach-Object { "     $($_.uid)  $($_.nickname)  openId=$(if ($_.openid) { $_.openid } else { '-' })  world=$($_.world)  server=$($_.server)  LV=$($_.levels)  reports=$($_.uploaded_reports)  ($($_.first) .. $($_.last))" } } else { @('     none (no uploaded report carries an account)') }) + @(
  "   device details inside every report: OS, CPU, GPU and driver, display adapters, time zone, session id, MAC address $(if ($macs) { '(' + ($macs -join ', ') + ')' })"
  "   -> crashsight\decoded-records.csv (one row per report), crashsight\accounts-uploaded.csv, crashsight\fields-seen.txt (every field the game attaches: $($kvSeen.Count + $kv2Seen.Count) key/value keys, $($pathSeen.Count) fields)"
  ""
  "2) VERDICT / CHEAT / BAN WORDING"
  "   in reports, session logs and game logs about this PC: $(if ($recordHits) { "$recordHits line(s) found -> read crashsight\verdict-scan.txt (ordinary log text can contain these words too)" } else { "none found ($scanned files scanned)" })$(if ($ignored) { "  [$ignored line(s) naming the game's own NK.Common.Cheat code class ignored]" })"
  "   in ACE's own config files (generic detection settings, not about you): $($cfgHits.Count) string(s), listed in crashsight\verdict-scan.txt"
  ""
  "3) OTHER METADATA THAT LEFT THIS PC"
  "   Level Infinite (INTL SDK) analytics queues, encrypted: $intlGameQueue file(s) in the game queue, $intlLauncherQueue in the launcher queue (copied, cannot be read locally)"
  "   accounts used on this PC (game cache): $($cacheAccounts.Count)$(if ($cacheLast) { ", last used $cacheLast" })   |  launcher database knows $launcherAccounts account(s)"
  "   ACE logins in Player.log ('ACE log in success' = account bound to this device): $aceLogins   |  ACE mentions in Player.log: $aceLines"
  "   crash reporter session logs: $csLogCount   |  crash reporter local record: $(if ($lastUser) { $lastUser } else { 'n/a' })"
  ""
  "4) IMPACT ON OTHER GAMES (Easy Anti-Cheat logs)"
  "   games with EAC logs: $($eacProducts.Count)   refusals 'Please close ACE-BASE before starting the game': $eacRefusals $(if ($eacRange) { "($eacRange)" })"
  ""
  "Files: $($all.Count) ($([math]::Round($total / 1MB, 1)) MB) in $root"
  "Zip  : $(if ($zip) { "$zip ($([math]::Round((Get-Item -LiteralPath $zip).Length / 1MB, 1)) MB)" } else { 'not created' })"
  "SHA-256: $zipSha"
)
$summaryPath = "$root-SUMMARY.txt"
try { $summary | Out-File -FilePath $summaryPath -Encoding UTF8 } catch {}
try { $summary | Out-File -FilePath (Join-Path $root 'SUMMARY.txt') -Encoding UTF8 } catch {}
$sj = [ordered]@{
  computer = $env:COMPUTERNAME; collected = (Get-Date).ToString('o'); collector = $Version; windows = $sys.OS; cpu = $sys.CPU; gpu = $sys.GPU; elevated = $isAdmin
  game_dir = $gameDir; game_versions = $gameVersions; ace_base_version = $(if ($aceBase) { $aceBase.FileVersion } else { '' }); ace_base_date = $(if ($aceBase) { $aceBase.Modified.ToString('yyyy-MM-dd') } else { '' }); ace_base_sha256 = $(if ($aceBase) { $aceBase.SHA256 } else { '' })
  ace_advt_version = $(if ($aceAdvt) { $aceAdvt.FileVersion } else { '' }); ace_driver_state = $(if ($aceDrivers) { ($aceDrivers | ForEach-Object { "$($_.Name)=$($_.State)" }) -join ', ' } else { '' }); hidden_device_classes = $fakeCount
  records_total = $rows.Count; records_uploaded = $uploaded.Count; records_pending = $pending.Count; records_range = $dr; db_read = $dbRead
  accounts_uploaded = @($accounts | ForEach-Object { [ordered]@{ uid = $_.uid; nickname = $_.nickname; openid = $_.openid; world = $_.world; server = $_.server; levels = $_.levels; reports = $_.uploaded_reports; first = $_.first; last = $_.last } })
  macs = $macs; kv_keys = @($kvSeen.Keys | Sort-Object); field_count = $pathSeen.Count
  verdict_hits_records = $recordHits; verdict_hits_ace_config = $cfgHits.Count; verdict_ignored_game_internal = $ignored; files_scanned = $scanned; kv2_keys = @($kv2Seen.Keys | Sort-Object)
  intl_queue_game = $intlGameQueue; intl_queue_launcher = $intlLauncherQueue; cache_accounts = @($cacheAccounts | ForEach-Object { $_.Account }); cache_last_used = $cacheLast; launcher_accounts = $launcherAccounts
  ace_logins = $aceLogins; ace_lines = $aceLines; crashsight_session_logs = $csLogCount; last_user_record = $lastUser
  eac_products = $eacProducts.Count; eac_refusals = $eacRefusals; eac_refusal_range = $eacRange
  files = $all.Count; mb = [math]::Round($total / 1MB, 1); zip = $zip; zip_sha256 = $zipSha
}
try { $sj | ConvertTo-Json -Depth 4 | Out-File -FilePath (Join-Path $root 'summary.json') -Encoding UTF8 } catch {}
if ($zip) {
  # refresh the zip so SUMMARY.txt and summary.json are inside it too
  try { Compress-Archive -Path (Join-Path $root 'SUMMARY.txt'), (Join-Path $root 'summary.json') -DestinationPath $zip -Update -ErrorAction Stop; $zipSha = Hash-File $zip; $summary[-1] = "SHA-256: $zipSha"; $summary | Out-File -FilePath $summaryPath -Encoding UTF8 } catch { Log "  (could not add summary files to the zip: $($_.Exception.Message))" }
}
Log "done."
Write-Host ''
$summary | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host '=================================================================================='
Write-Host '  DONE. YOUR REPORT IS THIS FILE:' -ForegroundColor Green
Write-Host "    $summaryPath"
Write-Host "  The folder next to it holds everything that was collected$(if ($zip) { '; the .zip beside it is the file to share, if you choose to' })."
Write-Host '  Opening the report in Notepad and its folder in Explorer now.'
Write-Host '=================================================================================='
try { Start-Process notepad.exe -ArgumentList "`"$summaryPath`"" } catch {}
try { Start-Process explorer.exe -ArgumentList "/select,`"$summaryPath`"" } catch {}
