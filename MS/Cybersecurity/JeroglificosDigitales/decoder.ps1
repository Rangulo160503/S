@'
param([Parameter(Mandatory=$true)][string]$Path)

if (-not (Test-Path $Path)) { Write-Error "No existe el archivo: $Path"; exit 1 }

$bits = Get-Content $Path -Raw
$bits = ($bits -replace '[^01]','')

function BitsToText($bits, $chunk) {
  $len = [Math]::Floor($bits.Length / $chunk) * $chunk
  if ($len -le 0) { return "" }
  $bits = $bits.Substring(0,$len)
  $sb = New-Object System.Text.StringBuilder
  for ($i=0; $i -lt $len; $i+=$chunk) {
    $val = [Convert]::ToInt32($bits.Substring($i,$chunk),2)
    [void]$sb.Append([char]$val)
  }
  $sb.ToString()
}

function TryB64([string]$s){ try { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($s)) } catch { "" } }
function ROT13([string]$s){
  ($s.ToCharArray() | ForEach-Object {
    $c=[int][char]$_
    if( ($c -ge 65 -and $c -le 90) ){ [char](((($c-65+13)%26)+65)) }
    elseif( ($c -ge 97 -and $c -le 122) ){ [char](((($c-97+13)%26)+97)) }
    else { [char]$c }
  }) -join ''
}
function CaesarAll([string]$s){
  $res=@()
  for($k=1;$k -le 25;$k++){
    $out=""
    foreach($ch in $s.ToCharArray()){
      $c=[int][char]$ch
      if($c -ge 65 -and $c -le 90){ $out += [char](((($c-65+$k)%26)+65)) }
      elseif($c -ge 97 -and $c -le 122){ $out += [char](((($c-97+$k)%26)+97)) }
      else{ $out += $ch }
    }
    $res += ("[k={0:00}] {1}" -f $k,$out)
  }
  $res -join "`r`n"
}

$dir = Split-Path -Parent $Path
$out8 = BitsToText $bits 8
$out7 = BitsToText $bits 7

Set-Content -Path (Join-Path $dir 'decode_8bits.txt') -Value $out8
Set-Content -Path (Join-Path $dir 'decode_7bits.txt') -Value $out7

$b64_8 = TryB64 $out8.Trim()
$b64_7 = TryB64 $out7.Trim()
if($b64_8){ Set-Content (Join-Path $dir 'decode_8bits_base64.txt') $b64_8 }
if($b64_7){ Set-Content (Join-Path $dir 'decode_7bits_base64.txt') $b64_7 }

Set-Content -Path (Join-Path $dir 'decode_8bits_rot13.txt') -Value (ROT13 $out8)
Set-Content -Path (Join-Path $dir 'decode_7bits_rot13.txt') -Value (ROT13 $out7)

Set-Content -Path (Join-Path $dir 'decode_8bits_caesar.txt') -Value (CaesarAll $out8)
Set-Content -Path (Join-Path $dir 'decode_7bits_caesar.txt') -Value (CaesarAll $out7)

"Listo. Revisá los archivos decode_*.txt en: $dir"
'@ | Set-Content ..\decoder.ps1
