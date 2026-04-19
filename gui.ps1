Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $scriptDir

function Invoke-ShadowScan {
  param(
    [string]$ProcessName,
    [string]$Port,
    [int]$Limit,
    [bool]$Resolve,
    [bool]$History,
    [bool]$AllRows
  )

  $args = @(".\src\index.js", "--json")

  if ($Resolve) { $args += "--resolve" }
  if (-not $History) { $args += "--no-history" }
  if ($AllRows) { $args += "--all" } else { $args += @("--limit", [string]$Limit) }
  if ($ProcessName) { $args += @("--process", $ProcessName) }
  if ($Port) { $args += @("--port", $Port) }

  $raw = & node @args
  if ($LASTEXITCODE -ne 0) {
    throw "Node scan failed."
  }

  return $raw | ConvertFrom-Json
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
  [void]$table.Columns.Add("Senin taraf")
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

    $report = Invoke-ShadowScan `
      -ProcessName $processBox.Text `
      -Port $portBox.Text `
      -Limit ([int]$limitBox.Value) `
      -Resolve $resolveCheck.Checked `
      -History $historyCheck.Checked `
      -AllRows $allCheck.Checked

    $latestReport = $report
    $summaryLabel.Text = "Toplam: $($report.summary.totalConnections) | Yeni: $($report.summary.newConnections) | Yüksek: $($report.summary.highRisk) | Orta: $($report.summary.mediumRisk) | Düşük: $($report.summary.lowRisk)"
    $statusLabel.Text = "$($report.connections.Count) satır listelendi. Son tarama: $([DateTime]::Parse($report.summary.scannedAt).ToLocalTime())"
    Set-GridData -Connections @($report.connections)
  } catch {
    [System.Windows.Forms.MessageBox]::Show("Scan failed: $($_.Exception.Message)", "Shadow Connections Viewer")
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
    $latestReport | ConvertTo-Json -Depth 6 | Set-Content -Encoding UTF8 $saveDialog.FileName
  }
})

$form.Add_Shown($scanAction)
[void]$form.ShowDialog()
