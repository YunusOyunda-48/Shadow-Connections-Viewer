$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$Script:CommonPorts = @(20, 21, 22, 25, 53, 80, 110, 123, 143, 443, 465, 587, 993, 995)
$Script:HistoryDir = Join-Path $PSScriptRoot ".shadow"
$Script:HistoryPath = Join-Path $Script:HistoryDir "last-scan.json"

function Get-IsPublicIp {
  param([string]$Address)

  if ([string]::IsNullOrWhiteSpace($Address)) { return $false }
  if ($Address -in @("0.0.0.0", "::", "127.0.0.1", "::1")) { return $false }
  if ($Address.StartsWith("10.") -or $Address.StartsWith("192.168.") -or $Address.StartsWith("169.254.")) { return $false }
  if ($Address -match '^172\.(1[6-9]|2\d|3[0-1])\.') { return $false }
  if ($Address.StartsWith("fe80:") -or $Address.StartsWith("fc") -or $Address.StartsWith("fd")) { return $false }
  return $true
}

function Parse-Endpoint {
  param([string]$Value)

  if ([string]::IsNullOrWhiteSpace($Value)) { return $null }

  if ($Value.StartsWith("[")) {
    if ($Value -match '^\[(.*)\]:(\d+|\*)$') {
      return [PSCustomObject]@{
        Address = $matches[1]
        Port = if ($matches[2] -eq "*") { 0 } else { [int]$matches[2] }
      }
    }

    return $null
  }

  $lastColon = $Value.LastIndexOf(":")
  if ($lastColon -lt 0) { return $null }

  $portValue = $Value.Substring($lastColon + 1)

  [PSCustomObject]@{
    Address = $Value.Substring(0, $lastColon)
    Port = if ($portValue -eq "*") { 0 } else { [int]$portValue }
  }
}

function Get-ProcessMap {
  $map = @{}
  $rows = tasklist /FO CSV /NH | ConvertFrom-Csv -Header "ImageName", "PID", "SessionName", "SessionNumber", "MemoryUsage"

  foreach ($row in $rows) {
    $pid = 0
    if ([int]::TryParse($row.PID, [ref]$pid)) {
      $map[$pid] = $row.ImageName
    }
  }

  return $map
}

function Get-RawConnections {
  $processMap = Get-ProcessMap
  $lines = netstat -ano -p tcp
  $rows = @()

  foreach ($rawLine in $lines) {
    $line = $rawLine.Trim()
    if (-not $line.StartsWith("TCP")) { continue }

    $parts = $line -split '\s+'
    if ($parts.Count -lt 5) { continue }

    $local = Parse-Endpoint $parts[1]
    $remote = Parse-Endpoint $parts[2]
    if (-not $local -or -not $remote) { continue }

    $pid = [int]$parts[4]

    $rows += [PSCustomObject]@{
      protocol = $parts[0]
      state = $parts[3]
      localAddress = $local.Address
      localPort = $local.Port
      remoteAddress = $remote.Address
      remotePort = $remote.Port
      pid = $pid
      processName = if ($processMap.ContainsKey($pid)) { $processMap[$pid] } else { "unknown" }
    }
  }

  return $rows
}

function Get-ReverseHostnames {
  param([string]$Address)

  if (-not (Get-IsPublicIp $Address)) { return @() }

  try {
    $entry = [System.Net.Dns]::GetHostEntry($Address)
    if ($entry.HostName) {
      return @($entry.HostName)
    }
  } catch {
  }

  return @()
}

function Get-Risk {
  param(
    $Entry,
    [int]$ProcessConnectionCount
  )

  if ($Entry.state -eq "TIME_WAIT" -or [int]$Entry.pid -eq 0) {
    return [PSCustomObject]@{
      score = 0
      level = "low"
      reasons = @()
    }
  }

  $score = 0
  $reasons = [System.Collections.Generic.List[string]]::new()
  $remotePort = [int]$Entry.remotePort
  $processName = [string]$Entry.processName
  $isExternal = Get-IsPublicIp $Entry.remoteAddress

  if ($Entry.state -ne "LISTENING" -and $isExternal -and ($Script:CommonPorts -notcontains $remotePort)) {
    $score += 30
    $reasons.Add("alışılmadık uzak port")
  }

  if ($ProcessConnectionCount -ge 12) {
    $score += 15
    $reasons.Add("uygulama çok fazla bağlantı açıyor")
  }

  if ($processName.ToLowerInvariant() -in @("svchost.exe", "runtimebroker.exe", "rundll32.exe", "regsvr32.exe", "wscript.exe", "cscript.exe")) {
    $score += 10
    $reasons.Add("sistem süreci gibi görünen bağlantı")
  }

  if (-not $isExternal -or $Entry.state -eq "LISTENING") {
    $score = [Math]::Max(0, $score - 15)
  }

  $level = if ($score -ge 45) { "high" } elseif ($score -ge 20) { "medium" } else { "low" }

  return [PSCustomObject]@{
    score = $score
    level = $level
    reasons = @($reasons)
  }
}

function Get-ConnectionKey {
  param($Entry)

  return "{0}|{1}|{2}|{3}|{4}|{5}" -f $Entry.protocol, $Entry.pid, $Entry.localAddress, $Entry.localPort, $Entry.remoteAddress, $Entry.remotePort
}

function Load-PreviousScan {
  if (-not (Test-Path $Script:HistoryPath)) {
    return @()
  }

  try {
    $data = Get-Content -Raw $Script:HistoryPath | ConvertFrom-Json
    return @($data)
  } catch {
    return @()
  }
}

function Save-CurrentScan {
  param($Connections)

  if (-not (Test-Path $Script:HistoryDir)) {
    New-Item -ItemType Directory -Path $Script:HistoryDir | Out-Null
  }

  $Connections | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $Script:HistoryPath
}

function Get-ScanReport {
  param(
    [string]$ProcessName,
    [Nullable[int]]$Port,
    [int]$Limit,
    [bool]$Resolve,
    [bool]$History,
    [bool]$AllRows
  )

  $rawConnections = @(Get-RawConnections)
  $counts = @{}

  foreach ($entry in $rawConnections) {
    $key = [string]$entry.pid
    if (-not $counts.ContainsKey($key)) { $counts[$key] = 0 }
    $counts[$key] += 1
  }

  $previous = if ($History) { @(Load-PreviousScan) } else { @() }
  $previousKeys = [System.Collections.Generic.HashSet[string]]::new()
  foreach ($entry in $previous) {
    [void]$previousKeys.Add((Get-ConnectionKey $entry))
  }

  $connections = foreach ($entry in $rawConnections) {
    $hostnames = if ($Resolve) { @(Get-ReverseHostnames $entry.remoteAddress) } else { @() }
    $risk = Get-Risk -Entry $entry -ProcessConnectionCount $counts[[string]$entry.pid]

    [PSCustomObject]@{
      protocol = $entry.protocol
      state = $entry.state
      localAddress = $entry.localAddress
      localPort = $entry.localPort
      remoteAddress = $entry.remoteAddress
      remotePort = $entry.remotePort
      pid = $entry.pid
      processName = $entry.processName
      hostnames = $hostnames
      hostLabel = if ($hostnames.Count -gt 0) { $hostnames[0] } else { "çözümlenmedi" }
      risk = $risk
      isNew = if ($History) { -not $previousKeys.Contains((Get-ConnectionKey $entry)) } else { $false }
    }
  }

  if ($ProcessName) {
    $connections = @($connections | Where-Object { $_.processName.ToLowerInvariant().Contains($ProcessName.ToLowerInvariant()) })
  }

  if ($Port) {
    $connections = @($connections | Where-Object { $_.localPort -eq $Port -or $_.remotePort -eq $Port })
  }

  $connections = @(
    $connections |
      Sort-Object `
        @{ Expression = { if ($_.isNew) { 0 } else { 1 } } }, `
        @{ Expression = { -1 * [int]$_.risk.score } }, `
        @{ Expression = { $_.processName } }
  )

  $visibleRows = if ($AllRows) { $connections.Count } else { [Math]::Min($connections.Count, $Limit) }
  $visibleConnections = @($connections | Select-Object -First $visibleRows)

  if ($History) {
    Save-CurrentScan -Connections $rawConnections
  }

  return [PSCustomObject]@{
    summary = [PSCustomObject]@{
      scannedAt = [DateTime]::UtcNow.ToString("o")
      totalConnections = $connections.Count
      visibleRows = $visibleConnections.Count
      newConnections = @($connections | Where-Object { $_.isNew }).Count
      highRisk = @($connections | Where-Object { $_.risk.level -eq "high" }).Count
      mediumRisk = @($connections | Where-Object { $_.risk.level -eq "medium" }).Count
      lowRisk = @($connections | Where-Object { $_.risk.level -eq "low" }).Count
    }
    connections = $visibleConnections
  }
}

$form = New-Object System.Windows.Forms.Form
$form.Text = "Shadow Connections Viewer"
$form.Size = New-Object System.Drawing.Size(1220, 760)
$form.StartPosition = "CenterScreen"
$form.BackColor = [System.Drawing.Color]::FromArgb(10, 18, 28)
$form.ForeColor = [System.Drawing.Color]::White

$title = New-Object System.Windows.Forms.Label
$title.Text = "Shadow Connections Viewer"
$title.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 20, [System.Drawing.FontStyle]::Bold)
$title.AutoSize = $true
$title.Location = New-Object System.Drawing.Point(18, 18)
$form.Controls.Add($title)

$subtitle = New-Object System.Windows.Forms.Label
$subtitle.Text = "Bilgisayarda hangi uygulama nereye bağlanıyor, bunu sade şekilde gösterir."
$subtitle.AutoSize = $true
$subtitle.ForeColor = [System.Drawing.Color]::FromArgb(150, 190, 220)
$subtitle.Location = New-Object System.Drawing.Point(21, 58)
$form.Controls.Add($subtitle)

$processLabel = New-Object System.Windows.Forms.Label
$processLabel.Text = "Uygulama adı"
$processLabel.AutoSize = $true
$processLabel.Location = New-Object System.Drawing.Point(20, 100)
$form.Controls.Add($processLabel)

$processBox = New-Object System.Windows.Forms.TextBox
$processBox.Location = New-Object System.Drawing.Point(20, 122)
$processBox.Size = New-Object System.Drawing.Size(220, 28)
$form.Controls.Add($processBox)

$portLabel = New-Object System.Windows.Forms.Label
$portLabel.Text = "Port"
$portLabel.AutoSize = $true
$portLabel.Location = New-Object System.Drawing.Point(260, 100)
$form.Controls.Add($portLabel)

$portBox = New-Object System.Windows.Forms.TextBox
$portBox.Location = New-Object System.Drawing.Point(260, 122)
$portBox.Size = New-Object System.Drawing.Size(90, 28)
$form.Controls.Add($portBox)

$limitLabel = New-Object System.Windows.Forms.Label
$limitLabel.Text = "Gösterilecek satır"
$limitLabel.AutoSize = $true
$limitLabel.Location = New-Object System.Drawing.Point(370, 100)
$form.Controls.Add($limitLabel)

$limitBox = New-Object System.Windows.Forms.NumericUpDown
$limitBox.Location = New-Object System.Drawing.Point(370, 122)
$limitBox.Size = New-Object System.Drawing.Size(90, 28)
$limitBox.Minimum = 1
$limitBox.Maximum = 500
$limitBox.Value = 50
$form.Controls.Add($limitBox)

$resolveCheck = New-Object System.Windows.Forms.CheckBox
$resolveCheck.Text = "IP adını bulmaya çalış"
$resolveCheck.AutoSize = $true
$resolveCheck.Location = New-Object System.Drawing.Point(490, 124)
$resolveCheck.ForeColor = [System.Drawing.Color]::White
$form.Controls.Add($resolveCheck)

$historyCheck = New-Object System.Windows.Forms.CheckBox
$historyCheck.Text = "Önceki taramayla karşılaştır"
$historyCheck.AutoSize = $true
$historyCheck.Checked = $true
$historyCheck.Location = New-Object System.Drawing.Point(650, 124)
$historyCheck.ForeColor = [System.Drawing.Color]::White
$form.Controls.Add($historyCheck)

$allCheck = New-Object System.Windows.Forms.CheckBox
$allCheck.Text = "Tüm satırları göster"
$allCheck.AutoSize = $true
$allCheck.Location = New-Object System.Drawing.Point(850, 124)
$allCheck.ForeColor = [System.Drawing.Color]::White
$form.Controls.Add($allCheck)

$scanButton = New-Object System.Windows.Forms.Button
$scanButton.Text = "Tara"
$scanButton.Location = New-Object System.Drawing.Point(1010, 118)
$scanButton.Size = New-Object System.Drawing.Size(160, 34)
$scanButton.BackColor = [System.Drawing.Color]::FromArgb(90, 235, 190)
$scanButton.ForeColor = [System.Drawing.Color]::FromArgb(5, 20, 25)
$scanButton.FlatStyle = "Flat"
$form.Controls.Add($scanButton)

$statusLabel = New-Object System.Windows.Forms.Label
$statusLabel.Text = "Hazır."
$statusLabel.AutoSize = $true
$statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(150, 190, 220)
$statusLabel.Location = New-Object System.Drawing.Point(20, 165)
$form.Controls.Add($statusLabel)

$summaryLabel = New-Object System.Windows.Forms.Label
$summaryLabel.Text = "Toplam: - | Yeni: - | Yüksek: - | Orta: - | Düşük: -"
$summaryLabel.AutoSize = $true
$summaryLabel.ForeColor = [System.Drawing.Color]::FromArgb(113, 247, 199)
$summaryLabel.Location = New-Object System.Drawing.Point(20, 188)
$form.Controls.Add($summaryLabel)

$grid = New-Object System.Windows.Forms.DataGridView
$grid.Location = New-Object System.Drawing.Point(20, 220)
$grid.Size = New-Object System.Drawing.Size(1150, 470)
$grid.BackgroundColor = [System.Drawing.Color]::FromArgb(12, 24, 36)
$grid.GridColor = [System.Drawing.Color]::FromArgb(35, 60, 85)
$grid.EnableHeadersVisualStyles = $false
$grid.ColumnHeadersDefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(16, 34, 52)
$grid.ColumnHeadersDefaultCellStyle.ForeColor = [System.Drawing.Color]::White
$grid.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(12, 24, 36)
$grid.DefaultCellStyle.ForeColor = [System.Drawing.Color]::White
$grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(28, 58, 82)
$grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
$grid.RowHeadersVisible = $false
$grid.AutoSizeColumnsMode = "AllCells"
$grid.AllowUserToAddRows = $false
$grid.AllowUserToDeleteRows = $false
$grid.ReadOnly = $true
$grid.SelectionMode = "FullRowSelect"
$grid.AutoGenerateColumns = $true
$form.Controls.Add($grid)

$exportButton = New-Object System.Windows.Forms.Button
$exportButton.Text = "JSON dışa aktar"
$exportButton.Location = New-Object System.Drawing.Point(1030, 700)
$exportButton.Size = New-Object System.Drawing.Size(140, 32)
$exportButton.FlatStyle = "Flat"
$exportButton.ForeColor = [System.Drawing.Color]::White
$exportButton.BackColor = [System.Drawing.Color]::FromArgb(27, 45, 68)
$form.Controls.Add($exportButton)

$saveDialog = New-Object System.Windows.Forms.SaveFileDialog
$saveDialog.Filter = "JSON files (*.json)|*.json"
$saveDialog.FileName = "shadow-connections.json"

$hintLabel = New-Object System.Windows.Forms.Label
$hintLabel.Text = "Tabloda uygulama adı, nereye bağlandığı ve neden dikkat çektiği görünür."
$hintLabel.AutoSize = $true
$hintLabel.ForeColor = [System.Drawing.Color]::FromArgb(150, 190, 220)
$hintLabel.Location = New-Object System.Drawing.Point(20, 700)
$form.Controls.Add($hintLabel)

$latestReport = $null

function Set-GridData {
  param($Connections)

  $table = New-Object System.Data.DataTable
  [void]$table.Columns.Add("Risk")
  [void]$table.Columns.Add("Yeni")
  [void]$table.Columns.Add("Uygulama")
  [void]$table.Columns.Add("PID")
  [void]$table.Columns.Add("Senin tarafın")
  [void]$table.Columns.Add("Bağlandığı yer")
  [void]$table.Columns.Add("Bağlantı durumu")
  [void]$table.Columns.Add("Host")
  [void]$table.Columns.Add("Neden dikkat çekti")

  foreach ($entry in @($Connections)) {
    $notes = if ($entry.risk.reasons.Count -gt 0) { ($entry.risk.reasons -join ", ") } else { "Normal görünüyor" }
    [void]$table.Rows.Add(
      "$($entry.risk.level.ToUpper()) $($entry.risk.score)",
      $(if ($entry.isNew) { "YENİ" } else { "" }),
      $entry.processName,
      [string]$entry.pid,
      "$($entry.localAddress):$($entry.localPort)",
      "$($entry.remoteAddress):$($entry.remotePort)",
      $entry.state,
      $entry.hostLabel,
      $notes
    )
  }

  $grid.DataSource = $table

  foreach ($column in $grid.Columns) {
    if ($column.Name -eq "Neden dikkat çekti") {
      $column.AutoSizeMode = [System.Windows.Forms.DataGridViewAutoSizeColumnMode]::Fill
    }
  }
}

$scanAction = {
  try {
    $scanButton.Enabled = $false
    $statusLabel.Text = "Taranıyor..."

    $portValue = $null
    if (-not [string]::IsNullOrWhiteSpace($portBox.Text)) {
      $parsedPort = 0
      if ([int]::TryParse($portBox.Text, [ref]$parsedPort)) {
        $portValue = $parsedPort
      }
    }

    $report = Get-ScanReport `
      -ProcessName $processBox.Text `
      -Port $portValue `
      -Limit ([int]$limitBox.Value `
      ) `
      -Resolve $resolveCheck.Checked `
      -History $historyCheck.Checked `
      -AllRows $allCheck.Checked

    $latestReport = $report
    $summaryLabel.Text = "Toplam: $($report.summary.totalConnections) | Yeni: $($report.summary.newConnections) | Yüksek: $($report.summary.highRisk) | Orta: $($report.summary.mediumRisk) | Düşük: $($report.summary.lowRisk)"
    $statusLabel.Text = "$($report.connections.Count) satır listelendi. Son tarama: $([DateTime]::Parse($report.summary.scannedAt).ToLocalTime())"
    Set-GridData -Connections @($report.connections)
  } catch {
    [System.Windows.Forms.MessageBox]::Show("Tarama başarısız: $($_.Exception.Message)", "Shadow Connections Viewer")
    $statusLabel.Text = "Tarama başarısız."
  } finally {
    $scanButton.Enabled = $true
  }
}

$scanButton.Add_Click($scanAction)

$exportButton.Add_Click({
  if (-not $latestReport) {
    [System.Windows.Forms.MessageBox]::Show("Önce tarama yap.", "Shadow Connections Viewer")
    return
  }

  if ($saveDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
    $latestReport | ConvertTo-Json -Depth 8 | Set-Content -Encoding UTF8 $saveDialog.FileName
  }
})

$form.Add_Shown($scanAction)
[void]$form.ShowDialog()
