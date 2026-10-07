param([string]$BaseUrl = 'http://127.0.0.1:8080')
$ErrorActionPreference = 'Stop'

function Invoke-CurlJson([string]$Method, [string]$Path, [object]$Body, [string]$Token, [int]$Expected) {
    $inputPath = [System.IO.Path]::GetTempFileName()
    $outputPath = [System.IO.Path]::GetTempFileName()
    try {
        $curlArgs = @('--silent', '--show-error', '--output', $outputPath, '--write-out', '%{http_code}',
            '--request', $Method, '--header', 'Content-Type: application/json', "$BaseUrl$Path")
        if ($Token) { $curlArgs += @('--header', "Authorization: Bearer $Token") }
        if ($null -ne $Body) {
            [System.IO.File]::WriteAllText($inputPath, ($Body | ConvertTo-Json -Compress), [System.Text.UTF8Encoding]::new($false))
            $curlArgs += @('--data-binary', "@$inputPath")
        }
        $status = & curl.exe @curlArgs
        if ($LASTEXITCODE -ne 0) { throw 'curl failed' }
        if ([int]$status -ne $Expected) { throw "$Method $Path returned $status; expected $Expected" }
        Write-Host "PASS $Method $Path -> $status"
        return Get-Content -Raw -Encoding UTF8 -LiteralPath $outputPath | ConvertFrom-Json
    } finally {
        Remove-Item -LiteralPath $inputPath, $outputPath
    }
}

$null = Invoke-CurlJson GET '/api/data' $null '' 401
$null = Invoke-CurlJson POST '/auth/login' @{login="' OR '1'='1' --";password='incorrect'} '' 401
$suffix = [Guid]::NewGuid().ToString('N').Substring(0, 12)
$credentials = @{login="<script>$suffix</script>";password=[Guid]::NewGuid().ToString('N')}
$user = Invoke-CurlJson POST '/auth/register' $credentials '' 201
if ($user.login -ne "&lt;script&gt;$suffix&lt;/script&gt;") { throw 'XSS escaping failed' }
$null = Invoke-CurlJson POST '/auth/register' $credentials '' 409
$login = Invoke-CurlJson POST '/auth/login' $credentials '' 200
$data = Invoke-CurlJson GET '/api/data' $null $login.accessToken 200
if (@($data).Count -ne 0) { throw 'New user should have no notes' }
$null = Invoke-CurlJson GET '/api/data' $null 'invalid-token' 401
$null = Invoke-CurlJson POST '/auth/register' @{login='invalid';password='short'} '' 400
Write-Host 'All curl smoke checks passed. XSS payload returned as escaped text.'
