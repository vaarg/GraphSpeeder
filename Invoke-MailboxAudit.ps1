<#
.SYNOPSIS
    Mailbox access audit supplement for GraphRunner. Probes user and Microsoft 365 group
    inboxes for read access, then reads or searches messages from accessible mailboxes.

.DESCRIPTION
    Two functions:

    Test-MailboxAccess
        Probes user mailboxes (GET /users/{id}/mailFolders/Inbox/messages) and Microsoft 365
        group inboxes (GET /groups/{id}/conversations) to determine which are accessible to
        the current token. Produces AccessibleMailboxes.csv and per-type fallback _ids.txt
        files written incrementally so results survive a crash mid-run.

        Replaces Invoke-GraphOpenInboxFinder. Key improvements: explicit per-status error
        messages (the original sets $err from the catch block but never uses it, making all
        failures silent), token refresh on 401, Retry-After back-off on 429, resume via
        -SkipUsers/-StartFromUser and -SkipGroups/-StartFromGroup, and group inbox support.

        Accepts user input from GraphRunner-style users.txt (one UPN per line) and group
        input from Resume-GroupAudit.ps1 output files (updatable.csv, updatable_details.csv,
        or updatable_ids.txt). Non-Microsoft 365 groups (Security, Distribution) will return
        400 or 404 -- this is expected and is reported rather than silently swallowed.

    Get-MailboxMessages
        Reads messages from accessible mailboxes identified by Test-MailboxAccess.
        Without -SearchTerm: retrieves the top N most recent items per mailbox.
        With -SearchTerm: for user mailboxes uses OData $search (server-side, searches
        subject and body); for group mailboxes filters client-side on topic and preview
        (the Graph REST API does not expose full-text search for group conversations).
        Compatible with the default_detectors.json detector-loop pattern via -GraphRun.

.EXAMPLE
    . .\GraphRunner\GraphRunner.ps1
    . .\Invoke-MailboxAudit.ps1

    # Probe user mailboxes from GraphRunner users.txt and groups from GroupAudit
    Test-MailboxAccess -Tokens $tokens -UserList .\users.txt -InputCsv .\updatable_details.csv

    # Probe groups only, using the simple updatable CSV
    Test-MailboxAccess -Tokens $tokens -InputCsv .\updatable.csv -CheckGroupsOnly

    # Resume user probe from a specific address after a failure
    Test-MailboxAccess -Tokens $tokens -UserList .\users.txt -StartFromUser "jsmith@contoso.com"

    # Read top 10 messages from all accessible mailboxes
    Get-MailboxMessages -Tokens $tokens -MessageCount 10 -ReportOnly -OutFile .\messages.csv

    # Search for a term across all accessible mailboxes
    Get-MailboxMessages -Tokens $tokens -SearchTerm "password" -ReportOnly -OutFile .\hits.csv

    # Detector loop (mirrors the GraphRunner wiki and SharePointAudit patterns)
    $folderName = "MailboxSearch-" + (Get-Date -Format 'yyyyMMddHHmmss')
    New-Item -Path $folderName -ItemType Directory | Out-Null
    $outFile    = "$folderName\interesting-mail.csv"
    $detectors  = (Get-Content '.\default_detectors.json' | ConvertFrom-Json).Detectors
    foreach ($detect in $detectors) {
        Get-MailboxMessages -Tokens $tokens `
            -SearchTerm   $detect.SearchQuery `
            -DetectorName $detect.DetectorName `
            -PageResults -MessageCount 500 `
            -ReportOnly  -OutFile $outFile -GraphRun
    }

.NOTES
    Requires GraphRunner.ps1 to be dot-sourced first (for Invoke-RefreshGraphTokens).
    Encoding: ASCII. Save as ASCII or UTF-8 with BOM to avoid Windows-1252 parse errors in PS 5.1.

    Permissions required:
      - Mail.Read.Shared or Mail.ReadWrite.Shared to read other users' inboxes.
      - Group.Read.All or membership in the group to read group conversations.

    Group conversation search is client-side (topic + preview fields only). For complete
    results when searching groups, use -PageResults so all conversation pages are fetched
    before filtering. Without -PageResults only the first page is searched.

    User mailbox OData $search is server-side and searches subject and body, but does not
    support KQL managed properties (filetype:, path:, etc.) -- use plain keyword terms.
#>


function Get-MailboxJwtClaims {
    param([string]$Token)
    try {
        $seg = $Token.Split(".")[1]
        $seg = $seg.Replace('-', '+').Replace('_', '/')
        while ($seg.Length % 4) { $seg += "=" }
        return [System.Text.Encoding]::UTF8.GetString(
            [System.Convert]::FromBase64String($seg)) | ConvertFrom-Json
    } catch { return $null }
}


function Test-MailboxAccess {
    <#
    .SYNOPSIS
        Probes user mailboxes and Microsoft 365 group inboxes for read access.
        Replacement for Invoke-GraphOpenInboxFinder with group support, token refresh
        resilience, explicit error reporting, and position- or ID-based resume.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Tokens,

        # User inputs -- compatible with GraphRunner users.txt (one UPN per line)
        [string]$UserList = "",
        [string[]]$UserIds,

        # Group inputs -- compatible with Resume-GroupAudit output files
        [string]$InputCsv  = "",
        [string]$InputFile  = "",
        [string[]]$GroupIds,

        # Scope flags (mutually exclusive)
        [switch]$CheckUsersOnly,
        [switch]$CheckGroupsOnly,

        # Resume -- user list (use one or the other, not both)
        [int]$SkipUsers        = 0,
        [string]$StartFromUser = "",

        # Resume -- group list (use one or the other, not both)
        [int]$SkipGroups        = 0,
        [string]$StartFromGroup = "",

        # Output
        [string]$OutputFile = "AccessibleMailboxes.csv",

        # Token handling (mirrors Resume-GroupAudit defaults)
        [string]$tenantid = $global:tenantid,
        [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
        [string[]]$Client = "MSGraph",
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [string]$Resource = "https://graph.microsoft.com",
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [string]$Device = "Windows",
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [string]$Browser = "Edge",
        [int]$RefreshInterval = 300
    )

    if ($CheckUsersOnly -and $CheckGroupsOnly) {
        Write-Host -ForegroundColor Red "[!] -CheckUsersOnly and -CheckGroupsOnly cannot both be specified."
        return
    }

    if (-not $PSBoundParameters.ContainsKey('ClientID')) {
        $claims = Get-MailboxJwtClaims -Token $Tokens.access_token
        if ($claims -and $claims.appid) {
            $ClientID = $claims.appid
            Write-Host -ForegroundColor Yellow "[*] Auto-detected ClientID from token: $ClientID"
        }
    }

    $guidRx = '[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'

    # -----------------------------------------------------------------------
    # Resolve user list
    # -----------------------------------------------------------------------
    $userList_resolved = @()
    if (-not $CheckGroupsOnly) {
        if ($UserIds -and $UserIds.Count -gt 0) {
            $userList_resolved = @($UserIds | Where-Object { $_ } | ForEach-Object {
                [pscustomobject]@{ id = $_.Trim(); displayName = $_.Trim() }
            })
        } elseif ($UserList) {
            if (-not (Test-Path $UserList)) {
                Write-Host -ForegroundColor Red "[!] UserList file not found: $UserList"
                return
            }
            $userList_resolved = @(Get-Content $UserList | Where-Object { $_.Trim() } | ForEach-Object {
                $u = $_.Trim()
                [pscustomobject]@{ id = $u; displayName = $u }
            })
        } else {
            if ($CheckUsersOnly) {
                Write-Host -ForegroundColor Red "[!] -CheckUsersOnly specified but no user input provided (-UserList or -UserIds)."
                return
            }
            Write-Host -ForegroundColor Yellow "[*] No user input provided -- skipping user mailbox probe."
            Write-Host -ForegroundColor Yellow "    To enumerate users, run a GraphRunner user enum function (e.g. Get-GlobalAddressList)"
            Write-Host -ForegroundColor Yellow "    and pass the output file with -UserList."
        }
    }

    # -----------------------------------------------------------------------
    # Resolve group list
    # -----------------------------------------------------------------------
    $groupList_resolved = @()
    if (-not $CheckUsersOnly) {
        if ($GroupIds -and $GroupIds.Count -gt 0) {
            $groupList_resolved = @($GroupIds | Where-Object { $_ } | ForEach-Object {
                [pscustomobject]@{ id = $_.Trim(); displayName = $_.Trim(); mail = ""; groupType = "" }
            })
        } elseif ($InputCsv) {
            if (-not (Test-Path $InputCsv)) {
                Write-Host -ForegroundColor Red "[!] InputCsv not found: $InputCsv"
                return
            }
            $groupList_resolved = @(Import-Csv $InputCsv | Where-Object { $_.id } | ForEach-Object {
                [pscustomobject]@{
                    id          = $_.id.Trim()
                    displayName = if ($_.displayName) { $_.displayName } else { $_.id }
                    mail        = if ($_.mail)        { $_.mail }        else { "" }
                    groupType   = if ($_.groupType)   { $_.groupType }   else { "" }
                }
            })
        } elseif ($InputFile) {
            if (-not (Test-Path $InputFile)) {
                Write-Host -ForegroundColor Red "[!] InputFile not found: $InputFile"
                return
            }
            $groupList_resolved = @(Get-Content $InputFile | ForEach-Object {
                $line = $_.Trim()
                if     ($line -match "^(.+):($guidRx)$") { [pscustomobject]@{ id = $Matches[2]; displayName = $Matches[1]; mail = ""; groupType = "" } }
                elseif ($line -match "^($guidRx)$")      { [pscustomobject]@{ id = $Matches[1]; displayName = $Matches[1]; mail = ""; groupType = "" } }
            } | Where-Object { $_ })
        } else {
            if ($CheckGroupsOnly) {
                Write-Host -ForegroundColor Red "[!] -CheckGroupsOnly specified but no group input provided (-InputCsv, -InputFile, or -GroupIds)."
                return
            }
            Write-Host -ForegroundColor Yellow "[*] No group input provided -- skipping group inbox probe."
            Write-Host -ForegroundColor Yellow "    To enumerate updatable groups, run Resume-GroupAudit.ps1 and pass the output with"
            Write-Host -ForegroundColor Yellow "    -InputCsv (updatable_details.csv recommended, includes groupType) or -InputFile (updatable_ids.txt)."
        }
    }

    if ($userList_resolved.Count -eq 0 -and $groupList_resolved.Count -eq 0) {
        Write-Host -ForegroundColor Red "[!] No mailboxes to probe. Provide at least one of: -UserList, -UserIds, -InputCsv, -InputFile, -GroupIds."
        return
    }

    # -----------------------------------------------------------------------
    # Apply user resume controls
    # -----------------------------------------------------------------------
    if ($StartFromUser -and $userList_resolved.Count -gt 0) {
        $idx = -1
        for ($i = 0; $i -lt $userList_resolved.Count; $i++) {
            if ($userList_resolved[$i].id -ieq $StartFromUser) { $idx = $i; break }
        }
        if ($idx -lt 0) {
            Write-Host -ForegroundColor Red "[!] -StartFromUser '$StartFromUser' not found in the user list."
            return
        }
        $userList_resolved = @($userList_resolved[$idx..($userList_resolved.Count - 1)])
        Write-Host -ForegroundColor Yellow "[*] Users: resuming from '$StartFromUser' ($($userList_resolved.Count) remaining)."
    } elseif ($SkipUsers -gt 0 -and $userList_resolved.Count -gt 0) {
        if ($SkipUsers -ge $userList_resolved.Count) {
            Write-Host -ForegroundColor Red "[!] -SkipUsers $SkipUsers >= total user count ($($userList_resolved.Count))."
            return
        }
        $userList_resolved = @($userList_resolved[$SkipUsers..($userList_resolved.Count - 1)])
        Write-Host -ForegroundColor Yellow "[*] Users: skipping first $SkipUsers. $($userList_resolved.Count) remaining."
    }

    # -----------------------------------------------------------------------
    # Apply group resume controls
    # -----------------------------------------------------------------------
    if ($StartFromGroup -and $groupList_resolved.Count -gt 0) {
        $idx = -1
        for ($i = 0; $i -lt $groupList_resolved.Count; $i++) {
            if ($groupList_resolved[$i].id -ieq $StartFromGroup) { $idx = $i; break }
        }
        if ($idx -lt 0) {
            Write-Host -ForegroundColor Red "[!] -StartFromGroup '$StartFromGroup' not found in the group list."
            return
        }
        $groupList_resolved = @($groupList_resolved[$idx..($groupList_resolved.Count - 1)])
        Write-Host -ForegroundColor Yellow "[*] Groups: resuming from '$StartFromGroup' ($($groupList_resolved.Count) remaining)."
    } elseif ($SkipGroups -gt 0 -and $groupList_resolved.Count -gt 0) {
        if ($SkipGroups -ge $groupList_resolved.Count) {
            Write-Host -ForegroundColor Red "[!] -SkipGroups $SkipGroups >= total group count ($($groupList_resolved.Count))."
            return
        }
        $groupList_resolved = @($groupList_resolved[$SkipGroups..($groupList_resolved.Count - 1)])
        Write-Host -ForegroundColor Yellow "[*] Groups: skipping first $SkipGroups. $($groupList_resolved.Count) remaining."
    }

    # -----------------------------------------------------------------------
    # Token state
    # -----------------------------------------------------------------------
    $accessToken  = $Tokens.access_token
    $refreshToken = $Tokens.refresh_token
    $headers = @{
        Authorization = "Bearer $accessToken"
        Accept        = "application/json"
    }

    $startTime   = Get-Date
    $refreshSpan = [TimeSpan]::FromSeconds($RefreshInterval)
    $maxRetries  = 3

    $outputStem    = $OutputFile -replace '\.[^.]+$', ''
    $userFallback  = "${outputStem}_user_ids.txt"
    $groupFallback = "${outputStem}_group_ids.txt"

    $results     = [System.Collections.Generic.List[object]]::new()
    $accessibleU = 0
    $accessibleG = 0

    Write-Host -ForegroundColor Yellow "[*] Note: reading other users' mailboxes requires Mail.Read.Shared or Mail.ReadWrite.Shared."

    # -----------------------------------------------------------------------
    # Process users
    # -----------------------------------------------------------------------
    if ($userList_resolved.Count -gt 0) {
        Write-Host ""
        Write-Host -ForegroundColor Yellow "[*] Probing $($userList_resolved.Count) user mailbox(es)..."

        $checked = 0
        $total   = $userList_resolved.Count

        foreach ($user in $userList_resolved) {
            $checked++

            if ((Get-Date) - $startTime -ge $refreshSpan) {
                Write-Host ""
                Write-Host -ForegroundColor Yellow "[*] Proactive token refresh (users $checked/$total)..."
                Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                    -tenantid $tenantid -Resource $Resource -Client $Client `
                    -ClientID $ClientID -Browser $Browser -Device $Device
                if ($global:tokens) {
                    $accessToken  = $global:tokens.access_token
                    $refreshToken = $global:tokens.refresh_token
                    $headers["Authorization"] = "Bearer $accessToken"
                    $startTime = Get-Date
                }
            }

            $probeUri  = "https://graph.microsoft.com/v1.0/users/$($user.id)/mailFolders/Inbox/messages?`$top=1&`$select=id,subject,from,receivedDateTime"
            $attempt   = 0
            $done      = $false
            $resultObj = $null

            while (-not $done -and $attempt -lt $maxRetries) {
                try {
                    $resp = Invoke-RestMethod -Method Get -Uri $probeUri -Headers $headers -ErrorAction Stop
                    $done = $true

                    $latest     = if ($resp.value -and $resp.value.Count -gt 0) { $resp.value[0] } else { $null }
                    $latSubject = if ($latest -and $latest.subject)             { $latest.subject } else { "(empty inbox)" }
                    $latSender  = if ($latest -and $latest.from)               { $latest.from.emailAddress.address } else { "" }
                    $latDate    = if ($latest)                                  { $latest.receivedDateTime } else { "" }

                    $resultObj = [pscustomobject]@{
                        Type          = "User"
                        Id            = $user.id
                        DisplayName   = $user.displayName
                        MailAddress   = $user.id
                        Accessible    = $true
                        HttpStatus    = 200
                        Result        = "Accessible"
                        LatestSubject = $latSubject
                        LatestSender  = $latSender
                        LatestDate    = $latDate
                    }
                    $accessibleU++
                    "$($user.displayName):$($user.id)" | Out-File -Append -Encoding Ascii $userFallback
                    Write-Host ""
                    Write-Host -ForegroundColor Green "[+] $($user.id) -- inbox readable  |  $latSubject"

                } catch {
                    $sc = $null
                    try { $sc = [int]$_.Exception.Response.StatusCode       } catch {}
                    try { if (-not $sc) { $sc = [int]$_.Exception.Response.StatusCode.value__ } } catch {}

                    if ($sc -eq 401 -and $attempt -lt ($maxRetries - 1)) {
                        Write-Host ""
                        Write-Host -ForegroundColor Yellow "[*] 401 on '$($user.id)' -- refreshing token (attempt $($attempt + 1)/$maxRetries)..."
                        Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                            -tenantid $tenantid -Resource $Resource -Client $Client `
                            -ClientID $ClientID -Browser $Browser -Device $Device
                        if ($global:tokens) {
                            $accessToken  = $global:tokens.access_token
                            $refreshToken = $global:tokens.refresh_token
                            $headers["Authorization"] = "Bearer $accessToken"
                            $startTime = Get-Date
                        }
                        $attempt++
                    } elseif ($sc -eq 429) {
                        $retryAfter = 10
                        try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                        Write-Host ""
                        Write-Host -ForegroundColor DarkYellow "[*] Rate limited (429) -- sleeping ${retryAfter}s..."
                        Start-Sleep -Seconds $retryAfter
                        # 429 does not count against the retry budget
                    } else {
                        $result = switch ($sc) {
                            403     { "Access denied" }
                            404     { "Not found or no mailbox" }
                            401     { "Authentication failed" }
                            default { "Request failed (HTTP $sc)" }
                        }
                        $resultObj = [pscustomobject]@{
                            Type          = "User"
                            Id            = $user.id
                            DisplayName   = $user.displayName
                            MailAddress   = $user.id
                            Accessible    = $false
                            HttpStatus    = $sc
                            Result        = $result
                            LatestSubject = ""
                            LatestSender  = ""
                            LatestDate    = ""
                        }
                        $done = $true
                    }
                }
            }

            if (-not $done) {
                Write-Host ""
                Write-Host -ForegroundColor Red "[!] Giving up on '$($user.id)' after $maxRetries attempts."
                Write-Host -ForegroundColor Yellow "    Resume tip: -StartFromUser '$($user.id)'"
                $resultObj = [pscustomobject]@{
                    Type = "User"; Id = $user.id; DisplayName = $user.displayName
                    MailAddress = $user.id; Accessible = $false; HttpStatus = $null
                    Result = "Max retries exceeded"; LatestSubject = ""; LatestSender = ""; LatestDate = ""
                }
            }

            if ($resultObj) { $results.Add($resultObj) }

            $pct = [int](($checked / $total) * 100)
            Write-Host -NoNewline -ForegroundColor Cyan "`r[*] Users: $checked/$total ($pct%) -- $accessibleU accessible..."
            [System.Console]::Out.Flush()
        }
        Write-Host ""
    }

    # -----------------------------------------------------------------------
    # Process groups
    # -----------------------------------------------------------------------
    if ($groupList_resolved.Count -gt 0) {
        Write-Host ""
        Write-Host -ForegroundColor Yellow "[*] Probing $($groupList_resolved.Count) group inbox(es)..."
        Write-Host -ForegroundColor Yellow "[*] Non-Microsoft 365 groups (Security, Distribution) will return 400/404 -- expected, logged clearly."

        $checked = 0
        $total   = $groupList_resolved.Count

        foreach ($group in $groupList_resolved) {
            $checked++

            if ((Get-Date) - $startTime -ge $refreshSpan) {
                Write-Host ""
                Write-Host -ForegroundColor Yellow "[*] Proactive token refresh (groups $checked/$total)..."
                Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                    -tenantid $tenantid -Resource $Resource -Client $Client `
                    -ClientID $ClientID -Browser $Browser -Device $Device
                if ($global:tokens) {
                    $accessToken  = $global:tokens.access_token
                    $refreshToken = $global:tokens.refresh_token
                    $headers["Authorization"] = "Bearer $accessToken"
                    $startTime = Get-Date
                }
            }

            $probeUri  = "https://graph.microsoft.com/v1.0/groups/$($group.id)/conversations?`$top=1"
            $attempt   = 0
            $done      = $false
            $resultObj = $null

            while (-not $done -and $attempt -lt $maxRetries) {
                try {
                    $resp = Invoke-RestMethod -Method Get -Uri $probeUri -Headers $headers -ErrorAction Stop
                    $done = $true

                    $latest    = if ($resp.value -and $resp.value.Count -gt 0) { $resp.value[0] } else { $null }
                    $latTopic  = if ($latest -and $latest.topic)               { $latest.topic } else { "(no conversations)" }
                    $latSender = if ($latest -and $latest.uniqueSenders -and $latest.uniqueSenders.Count -gt 0) {
                                     $latest.uniqueSenders[0]
                                 } else { "" }
                    $latDate   = if ($latest)                                   { $latest.lastDeliveredDateTime } else { "" }

                    $resultObj = [pscustomobject]@{
                        Type          = "Group"
                        Id            = $group.id
                        DisplayName   = $group.displayName
                        MailAddress   = $group.mail
                        Accessible    = $true
                        HttpStatus    = 200
                        Result        = "Accessible"
                        LatestSubject = $latTopic
                        LatestSender  = $latSender
                        LatestDate    = $latDate
                    }
                    $accessibleG++
                    "$($group.displayName):$($group.id)" | Out-File -Append -Encoding Ascii $groupFallback
                    Write-Host ""
                    Write-Host -ForegroundColor Green "[+] $($group.displayName) -- conversations readable  |  $latTopic"

                } catch {
                    $sc = $null
                    try { $sc = [int]$_.Exception.Response.StatusCode       } catch {}
                    try { if (-not $sc) { $sc = [int]$_.Exception.Response.StatusCode.value__ } } catch {}

                    if ($sc -eq 401 -and $attempt -lt ($maxRetries - 1)) {
                        Write-Host ""
                        Write-Host -ForegroundColor Yellow "[*] 401 on '$($group.displayName)' -- refreshing token (attempt $($attempt + 1)/$maxRetries)..."
                        Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                            -tenantid $tenantid -Resource $Resource -Client $Client `
                            -ClientID $ClientID -Browser $Browser -Device $Device
                        if ($global:tokens) {
                            $accessToken  = $global:tokens.access_token
                            $refreshToken = $global:tokens.refresh_token
                            $headers["Authorization"] = "Bearer $accessToken"
                            $startTime = Get-Date
                        }
                        $attempt++
                    } elseif ($sc -eq 429) {
                        $retryAfter = 10
                        try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                        Write-Host ""
                        Write-Host -ForegroundColor DarkYellow "[*] Rate limited (429) -- sleeping ${retryAfter}s..."
                        Start-Sleep -Seconds $retryAfter
                    } else {
                        $result = switch ($sc) {
                            403     { "Access denied" }
                            404     { "Not found or no mailbox" }
                            400     { "Not a mail-enabled M365 group (Security or Distribution group)" }
                            401     { "Authentication failed" }
                            default { "Request failed (HTTP $sc)" }
                        }
                        $resultObj = [pscustomobject]@{
                            Type          = "Group"
                            Id            = $group.id
                            DisplayName   = $group.displayName
                            MailAddress   = $group.mail
                            Accessible    = $false
                            HttpStatus    = $sc
                            Result        = $result
                            LatestSubject = ""
                            LatestSender  = ""
                            LatestDate    = ""
                        }
                        $done = $true
                    }
                }
            }

            if (-not $done) {
                Write-Host ""
                Write-Host -ForegroundColor Red "[!] Giving up on '$($group.displayName)' ($($group.id)) after $maxRetries attempts."
                Write-Host -ForegroundColor Yellow "    Resume tip: -StartFromGroup '$($group.id)'"
                $resultObj = [pscustomobject]@{
                    Type = "Group"; Id = $group.id; DisplayName = $group.displayName
                    MailAddress = $group.mail; Accessible = $false; HttpStatus = $null
                    Result = "Max retries exceeded"; LatestSubject = ""; LatestSender = ""; LatestDate = ""
                }
            }

            if ($resultObj) { $results.Add($resultObj) }

            $pct = [int](($checked / $total) * 100)
            Write-Host -NoNewline -ForegroundColor Cyan "`r[*] Groups: $checked/$total ($pct%) -- $accessibleG accessible..."
            [System.Console]::Out.Flush()
        }
        Write-Host ""
    }

    # -----------------------------------------------------------------------
    # Summary and export
    # -----------------------------------------------------------------------
    Write-Host ""
    Write-Host "Accessible user mailboxes : $accessibleU"
    Write-Host "Accessible group inboxes  : $accessibleG"
    Write-Host ""

    if ($results.Count -gt 0) {
        $results | Export-Csv -Path $OutputFile -NoTypeInformation -Encoding UTF8
        Write-Host -ForegroundColor Green "[*] Full results saved to $OutputFile"
        if ($accessibleU -gt 0) { Write-Host -ForegroundColor Green "[*] Accessible user IDs  : $userFallback" }
        if ($accessibleG -gt 0) { Write-Host -ForegroundColor Green "[*] Accessible group IDs : $groupFallback" }
    }

    $accessibleAll = @($results | Where-Object { $_.Accessible -eq $true })
    if ($accessibleAll.Count -gt 0) {
        Write-Host ""
        $accessibleAll | Select-Object Type, DisplayName, MailAddress, LatestSubject, LatestDate | Format-Table -AutoSize
    }

    Write-Host -ForegroundColor Yellow "[*] Pass -InputCsv '$OutputFile' to Get-MailboxMessages to read or search accessible mailboxes."
}


function Remove-MailboxHtmlTags {
    param([string]$Html)
    if (-not $Html) { return "" }
    ($Html -replace '<[^>]+>', ' ' -replace '&nbsp;', ' ' -replace '&amp;', '&' -replace '&lt;', '<' -replace '&gt;', '>' -replace '\s+', ' ').Trim()
}


function Get-MailboxSafeFileName {
    param([string]$Name, [int]$MaxLength = 80)
    if (-not $Name) { return "unnamed" }
    $safe = $Name -replace '[\\/:*?"<>|]', '_' -replace '\s+', ' '
    if ($safe.Length -gt $MaxLength) { $safe = $safe.Substring(0, $MaxLength) }
    return $safe.Trim('_').Trim()
}


function Expand-MbxSearchTerms {
    param([string]$Query)
    # KQL detector queries wrap meaningful keywords in double quotes, e.g.:
    #   (filetype:txt OR ...) AND ("AWS_ACCESS_KEY_ID" OR "AWS_SECRET_ACCESS_KEY")
    # Extract those quoted phrases -- they are the real search signals for email bodies.
    $quoted = [regex]::Matches($Query, '"([^"]+)"') |
              ForEach-Object { $_.Groups[1].Value } |
              Where-Object   { $_.Trim() -ne '' }
    if ($quoted.Count -gt 0) { return @($quoted) }
    # No quoted phrases: strip KQL-specific syntax and return remaining tokens as plain keywords.
    $clean = $Query -replace '(?i)filetype:[^\s)]+', '' `
                    -replace '(?i)filename:[^\s)]+',  '' `
                    -replace '(?i)NEAR\(n=\d+\)',      '' `
                    -replace '\b(AND|OR|NOT)\b',       '' `
                    -replace '[()"]',                  '' `
                    -replace '\s+',                    ' '
    return @($clean.Trim().Split(' ', [System.StringSplitOptions]::RemoveEmptyEntries) |
             Where-Object { $_.Length -ge 3 })
}


function Format-MbxSize {
    param([long]$Bytes)
    if ($Bytes -ge 1GB) { return "{0:N1} GB" -f ($Bytes / 1GB) }
    if ($Bytes -ge 1MB) { return "{0:N1} MB" -f ($Bytes / 1MB) }
    if ($Bytes -ge 1KB) { return "{0:N1} KB" -f ($Bytes / 1KB) }
    return "$Bytes B"
}


function Get-MailboxMessages {
    <#
    .SYNOPSIS
        Reads or searches messages from accessible mailboxes found by Test-MailboxAccess.
        Without -SearchTerm: retrieves the top N most recent items per mailbox.
        With -SearchTerm: server-side OData $search for user mailboxes; client-side topic
        and preview filtering for group mailboxes. Supports detector-loop pattern via -GraphRun.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object]$Tokens,

        # Input: accessible mailboxes CSV from Test-MailboxAccess
        [string]$InputCsv = "AccessibleMailboxes.csv",

        # Direct targeting: bypass CSV with explicit mailbox ID(s)
        [string[]]$MailboxId = @(),
        [ValidateSet("User", "Group")]
        [string]$MailboxType = "User",

        # Filter to a specific mailbox type (CSV path only; ignored when -MailboxId is used)
        [ValidateSet("User", "Group", "Both")]
        [string]$Type = "Both",

        # Message retrieval
        [int]$MessageCount   = 25,
        [string]$SearchTerm  = "",

        # Deep fetch and save
        [switch]$DeepGroupSearch,
        [string]$SaveTo        = "",
        [switch]$SaveAttachments,
        [switch]$Force,
        [int]$ConversationThreshold = 100,

        # Output / mode
        [string]$DetectorName = "Custom",
        [string]$OutFile      = "",
        [switch]$ReportOnly,
        [switch]$PageResults,
        [switch]$GraphRun,

        # Token handling
        [string]$tenantid = $global:tenantid,
        [ValidateSet("Yammer","Outlook","MSTeams","Graph","AzureCoreManagement","AzureManagement","MSGraph","DODMSGraph","Custom","Substrate")]
        [string[]]$Client = "MSGraph",
        [string]$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c",
        [string]$Resource = "https://graph.microsoft.com",
        [ValidateSet('Mac','Windows','AndroidMobile','iPhone')]
        [string]$Device = "Windows",
        [ValidateSet('Android','IE','Chrome','Firefox','Edge','Safari')]
        [string]$Browser = "Edge",
        [int]$RefreshInterval = 300
    )

    if (-not $PSBoundParameters.ContainsKey('ClientID')) {
        $claims = Get-MailboxJwtClaims -Token $Tokens.access_token
        if ($claims -and $claims.appid) { $ClientID = $claims.appid }
    }

    if ($SaveAttachments -and -not $SaveTo) {
        Write-Host -ForegroundColor Red "[!] -SaveAttachments requires -SaveTo to specify an output folder."
        return
    }

    if ($MailboxId.Count -gt 0) {
        $mailboxes = @($MailboxId | ForEach-Object {
            [pscustomobject]@{
                Type        = $MailboxType
                Id          = $_
                DisplayName = $_
                MailAddress = $_
            }
        })
    } else {
        if (-not (Test-Path $InputCsv)) {
            Write-Host -ForegroundColor Red "[!] Input CSV not found: $InputCsv"
            Write-Host -ForegroundColor Red "[!] Run Test-MailboxAccess first, or use -MailboxId for direct targeting."
            return
        }

        $allRows = @(Import-Csv -Path $InputCsv -ErrorAction Stop | Where-Object { $_.Accessible -eq "True" })

        $mailboxes = @(switch ($Type) {
            "User"  { $allRows | Where-Object { $_.Type -eq "User"  } }
            "Group" { $allRows | Where-Object { $_.Type -eq "Group" } }
            "Both"  { $allRows }
        })

        if ($mailboxes.Count -eq 0) {
            Write-Host -ForegroundColor Red "[!] No accessible mailboxes of type '$Type' found in $InputCsv"
            return
        }
    }

    $isSearch       = -not [string]::IsNullOrWhiteSpace($SearchTerm)
    $searchTerms    = if ($isSearch) { @(Expand-MbxSearchTerms -Query $SearchTerm) } else { @() }
    $groupMailboxes = @($mailboxes | Where-Object { $_.Type -eq "Group" })
    $needsDeepFetch = $DeepGroupSearch -or ($SaveTo -and $groupMailboxes.Count -gt 0)

    if ($needsDeepFetch -and $groupMailboxes.Count -gt 0 -and -not $Force) {
        Write-Host -ForegroundColor Yellow "[!] Deep group fetch drills into threads and posts for each conversation across $($groupMailboxes.Count) group(s)."
        Write-Host -ForegroundColor Yellow "    This makes up to 3 API calls per conversation thread. For active groups this could"
        Write-Host -ForegroundColor Yellow "    mean hundreds to thousands of requests. Use -Force to skip this prompt."
        $confirm = Read-Host "    Proceed? [Y/N]"
        if ($confirm -notmatch '^[Yy]') {
            Write-Host -ForegroundColor Red "[!] Aborted."
            return
        }
    }

    if ($SaveTo -and -not (Test-Path $SaveTo)) {
        New-Item -Path $SaveTo -ItemType Directory | Out-Null
        Write-Host -ForegroundColor Yellow "[*] Created output folder: $SaveTo"
    }

    if (-not $GraphRun) {
        if ($isSearch) {
            Write-Host -ForegroundColor Yellow "[*] Searching $($mailboxes.Count) mailbox(es) for: $SearchTerm"
        } else {
            Write-Host -ForegroundColor Yellow "[*] Reading messages from $($mailboxes.Count) accessible mailbox(es) (top $MessageCount per mailbox)..."
        }
        if ($groupMailboxes.Count -gt 0) {
            if ($needsDeepFetch) {
                Write-Host -ForegroundColor Yellow "[*] Group fetch: drilling into post bodies and attachment names (-DeepGroupSearch)."
            } elseif ($isSearch -and -not $PageResults) {
                Write-Host -ForegroundColor Yellow "[*] Group search is client-side (topic + preview only). Use -DeepGroupSearch to search full post bodies and attachment names."
            }
        }
    }

    $accessToken  = $Tokens.access_token
    $refreshToken = $Tokens.refresh_token
    $headers = @{
        Authorization  = "Bearer $accessToken"
        Accept         = "application/json"
    }

    $startTime     = Get-Date
    $refreshSpan   = [TimeSpan]::FromSeconds($RefreshInterval)
    $maxRetries    = 3
    $totalHits     = 0
    $mbxNum        = 0
    $csvHeaders    = $false
    $totalBytes    = [long]0
    $autoForceDeep = $false

    foreach ($mbx in $mailboxes) {
        $mbxNum++

        if ((Get-Date) - $startTime -ge $refreshSpan) {
            if (-not $GraphRun) { Write-Host -ForegroundColor Yellow "`n[*] Proactive token refresh (mailbox $mbxNum/$($mailboxes.Count))..." }
            Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                -tenantid $tenantid -Resource $Resource -Client $Client `
                -ClientID $ClientID -Browser $Browser -Device $Device
            if ($global:tokens) {
                $accessToken  = $global:tokens.access_token
                $refreshToken = $global:tokens.refresh_token
                $headers["Authorization"] = "Bearer $accessToken"
                $startTime = Get-Date
            }
        }

        $mbxHits      = [System.Collections.Generic.List[object]]::new()
        $mbxLabel     = "$($mbx.Type): $($mbx.DisplayName)"

        # -------------------------------------------------------------------
        # User mailbox
        # -------------------------------------------------------------------
        if ($mbx.Type -eq "User") {
            $userSelect   = "id,subject,from,toRecipients,receivedDateTime,hasAttachments,bodyPreview,size"
            if ($SaveTo)  { $userSelect += ",body" }
            $expandClause = "&`$expand=attachments(`$select=name,contentType,size)"

            if ($isSearch) {
                $searchValue   = ($searchTerms | ForEach-Object { "`"$_`"" }) -join " OR "
                $escapedSearch = [uri]::EscapeDataString($searchValue)
                $baseUri = "https://graph.microsoft.com/v1.0/users/$($mbx.Id)/messages?`$search=$escapedSearch&`$top=$MessageCount&`$select=$userSelect$expandClause"
            } else {
                $baseUri = "https://graph.microsoft.com/v1.0/users/$($mbx.Id)/mailFolders/Inbox/messages?`$top=$MessageCount&`$select=$userSelect$expandClause"
            }

            $nextUri = $baseUri
            do {
                $attempt  = 0
                $done     = $false
                $response = $null

                while (-not $done -and $attempt -lt $maxRetries) {
                    try {
                        $response = Invoke-RestMethod -Method Get -Uri $nextUri -Headers $headers -ErrorAction Stop
                        $done = $true
                    } catch {
                        $sc = $null
                        try { $sc = [int]$_.Exception.Response.StatusCode       } catch {}
                        try { if (-not $sc) { $sc = [int]$_.Exception.Response.StatusCode.value__ } } catch {}

                        if ($sc -eq 401 -and $attempt -lt ($maxRetries - 1)) {
                            Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                                -tenantid $tenantid -Resource $Resource -Client $Client `
                                -ClientID $ClientID -Browser $Browser -Device $Device
                            if ($global:tokens) {
                                $accessToken  = $global:tokens.access_token
                                $refreshToken = $global:tokens.refresh_token
                                $headers["Authorization"] = "Bearer $accessToken"
                                $startTime = Get-Date
                            }
                            $attempt++
                        } elseif ($sc -eq 429) {
                            $retryAfter = 10
                            try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                            if (-not $GraphRun) { Write-Host -ForegroundColor DarkYellow "`n[*] Rate limited (429) -- sleeping ${retryAfter}s..." }
                            Start-Sleep -Seconds $retryAfter
                        } else {
                            if (-not $GraphRun) {
                                Write-Host -ForegroundColor Red "`n[!] Failed to retrieve messages from $mbxLabel (HTTP $sc): $($_.Exception.Message -replace 'HTTP \d+ - ','')"
                            }
                            $done = $true
                        }
                    }
                }

                if ($null -eq $response) { break }

                foreach ($msg in @($response.value)) {
                    $subject   = if ($msg.subject)          { $msg.subject } else { "(No Subject)" }
                    $msgSender = if ($msg.from)             { $msg.from.emailAddress.address } else { "(Unknown)" }
                    $receivers = @($msg.toRecipients | ForEach-Object { $_.emailAddress.address }) -join ", "
                    $date      = if ($msg.receivedDateTime) { $msg.receivedDateTime } else { "" }
                    $preview   = if ($msg.bodyPreview)      { $msg.bodyPreview } else { "(No Preview)" }

                    $attachNames = ""
                    if ($msg.attachments -and $msg.attachments.Count -gt 0) {
                        $attachNames = @($msg.attachments | ForEach-Object { $_.name }) -join ", "
                    }

                    $bodyFile = ""
                    if ($SaveTo -and $msg.body -and $msg.body.content) {
                        $ext         = if ($msg.body.contentType -eq "html") { "html" } else { "txt" }
                        $safeMailbox = Get-MailboxSafeFileName -Name $mbx.DisplayName
                        $safeDate    = ($date -replace 'T.*', '')
                        $safeSubject = Get-MailboxSafeFileName -Name $subject -MaxLength 60
                        $mbxFolder   = Join-Path $SaveTo "User_$safeMailbox"
                        if (-not (Test-Path $mbxFolder)) { New-Item -Path $mbxFolder -ItemType Directory | Out-Null }
                        $bodyFile    = Join-Path $mbxFolder "${safeDate}_${safeSubject}.$ext"
                        $msg.body.content | Out-File -FilePath $bodyFile -Encoding UTF8
                    }

                    if ($SaveAttachments -and $msg.hasAttachments -and $msg.id) {
                        try {
                            $attUri  = "https://graph.microsoft.com/v1.0/users/$($mbx.Id)/messages/$($msg.id)/attachments"
                            $attResp = Invoke-RestMethod -Method Get -Uri $attUri -Headers $headers -ErrorAction Stop
                            $safeMailbox = Get-MailboxSafeFileName -Name $mbx.DisplayName
                            $attFolder   = Join-Path (Join-Path $SaveTo "User_$safeMailbox") "attachments"
                            if (-not (Test-Path $attFolder)) { New-Item -Path $attFolder -ItemType Directory | Out-Null }
                            foreach ($att in @($attResp.value)) {
                                if ($att.'@odata.type' -eq '#microsoft.graph.fileAttachment' -and $att.contentBytes) {
                                    $attBytes = [System.Convert]::FromBase64String($att.contentBytes)
                                    [System.IO.File]::WriteAllBytes((Join-Path $attFolder $att.name), $attBytes)
                                }
                            }
                        } catch {
                            if (-not $GraphRun) { Write-Host -ForegroundColor DarkYellow "`n[*] Could not retrieve attachments for '$subject'" }
                        }
                    }

                    $totalBytes += [long]$msg.size
                    $mbxHits.Add([pscustomobject]@{
                        "Detector Name"   = $DetectorName
                        "Mailbox Type"    = "User"
                        "Mailbox ID"      = $mbx.Id
                        "Mailbox Display" = $mbx.DisplayName
                        "Mailbox Address" = $mbx.MailAddress
                        "Subject"         = $subject
                        "Sender"          = $msgSender
                        "Receivers"       = $receivers
                        "Date"            = $date
                        "Preview"         = $preview
                        "HasAttachments"  = [bool]$msg.hasAttachments
                        "AttachmentNames" = $attachNames
                        "BodyFile"        = $bodyFile
                    })

                    if (-not $ReportOnly) {
                        Write-Host "Subject: $subject | Sender: $msgSender | Date: $date"
                        if ($attachNames) { Write-Host "Attachments: $attachNames" }
                        Write-Host "Preview: $preview"
                        Write-Host ("=" * 80)
                    }
                }

                $nextUri = if ($PageResults -and $response.'@odata.nextLink') { $response.'@odata.nextLink' } else { $null }

            } while ($nextUri)
        }

        # -------------------------------------------------------------------
        # Group mailbox
        # -------------------------------------------------------------------
        elseif ($mbx.Type -eq "Group") {

            if ($needsDeepFetch) {
                # Deep path: conversations -> threads -> posts
                # -----------------------------------------------
                $convUri  = "https://graph.microsoft.com/v1.0/groups/$($mbx.Id)/conversations?`$top=50&`$select=id,topic,hasAttachments,lastDeliveredDateTime,uniqueSenders"
                $allConvs = [System.Collections.Generic.List[object]]::new()

                do {
                    $attempt = 0; $done = $false; $response = $null
                    while (-not $done -and $attempt -lt $maxRetries) {
                        try {
                            $response = Invoke-RestMethod -Method Get -Uri $convUri -Headers $headers -ErrorAction Stop
                            $done = $true
                        } catch {
                            $sc = $null
                            try { $sc = [int]$_.Exception.Response.StatusCode       } catch {}
                            try { if (-not $sc) { $sc = [int]$_.Exception.Response.StatusCode.value__ } } catch {}
                            if ($sc -eq 401 -and $attempt -lt ($maxRetries - 1)) {
                                Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                                    -tenantid $tenantid -Resource $Resource -Client $Client `
                                    -ClientID $ClientID -Browser $Browser -Device $Device
                                if ($global:tokens) { $accessToken = $global:tokens.access_token; $refreshToken = $global:tokens.refresh_token; $headers["Authorization"] = "Bearer $accessToken"; $startTime = Get-Date }
                                $attempt++
                            } elseif ($sc -eq 429) {
                                $ra = 10; try { $ra = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                                if (-not $GraphRun) { Write-Host -ForegroundColor DarkYellow "`n[*] 429 -- sleeping ${ra}s..." }
                                Start-Sleep -Seconds $ra
                            } else {
                                if (-not $GraphRun) { Write-Host -ForegroundColor Red "`n[!] Failed to list conversations for $mbxLabel (HTTP $sc)" }
                                $done = $true
                            }
                        }
                    }
                    if ($null -eq $response) { break }
                    $allConvs.AddRange([object[]]@($response.value))
                    $convUri = if ($response.'@odata.nextLink') { $response.'@odata.nextLink' } else { $null }
                } while ($convUri)

                if ($allConvs.Count -gt $ConversationThreshold -and -not $Force -and -not $autoForceDeep) {
                    Write-Host -ForegroundColor Yellow "`n[!] $mbxLabel has $($allConvs.Count) conversations (threshold: $ConversationThreshold)."
                    Write-Host -ForegroundColor Yellow "    Deep fetch will drill into threads and posts for each one."
                    $choice = Read-Host "    Proceed? [Y]es / [N]o / [A]ll (skip this prompt for remaining groups)"
                    if ($choice -match '^[Nn]') { continue }
                    if ($choice -match '^[Aa]') { $autoForceDeep = $true }
                }

                foreach ($conv in $allConvs) {
                    $topic = if ($conv.topic) { $conv.topic } else { "(No Subject)" }

                    # Get threads for this conversation
                    $tResp = $null
                    try {
                        $tResp = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/groups/$($mbx.Id)/conversations/$($conv.id)/threads?`$select=id" -Headers $headers -ErrorAction Stop
                    } catch {
                        $sc = $null; try { $sc = [int]$_.Exception.Response.StatusCode } catch {}
                        if ($sc -eq 429) {
                            $ra = 10; try { $ra = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                            Start-Sleep -Seconds $ra
                            try { $tResp = Invoke-RestMethod -Method Get -Uri "https://graph.microsoft.com/v1.0/groups/$($mbx.Id)/conversations/$($conv.id)/threads?`$select=id" -Headers $headers -ErrorAction Stop } catch {}
                        } elseif (-not $GraphRun) { Write-Host -ForegroundColor Red "`n[!] Failed to list threads for '$topic' (HTTP $sc)" }
                    }
                    if (-not $tResp) { continue }

                    foreach ($thread in @($tResp.value)) {
                        # Get posts with full bodies and attachment names
                        $pNextUri = "https://graph.microsoft.com/v1.0/groups/$($mbx.Id)/threads/$($thread.id)/posts?`$select=id,body,from,receivedDateTime,hasAttachments&`$expand=attachments(`$select=name,contentType,size)"
                        $allPosts = [System.Collections.Generic.List[object]]::new()

                        do {
                            $pResp = $null
                            try {
                                $pResp = Invoke-RestMethod -Method Get -Uri $pNextUri -Headers $headers -ErrorAction Stop
                            } catch {
                                $sc = $null; try { $sc = [int]$_.Exception.Response.StatusCode } catch {}
                                if ($sc -eq 429) {
                                    $ra = 10; try { $ra = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                                    Start-Sleep -Seconds $ra
                                    try { $pResp = Invoke-RestMethod -Method Get -Uri $pNextUri -Headers $headers -ErrorAction Stop } catch {}
                                } elseif (-not $GraphRun) { Write-Host -ForegroundColor Red "`n[!] Failed to list posts for '$topic' (HTTP $sc)" }
                            }
                            if ($pResp) {
                                $allPosts.AddRange([object[]]@($pResp.value))
                                $pNextUri = if ($pResp.'@odata.nextLink') { $pResp.'@odata.nextLink' } else { $null }
                            } else { $pNextUri = $null }
                        } while ($pNextUri)

                        foreach ($post in $allPosts) {
                            $bodyContent = if ($post.body -and $post.body.content) { $post.body.content } else { "" }
                            $bodyText    = Remove-MailboxHtmlTags -Html $bodyContent
                            $postSender  = if ($post.from) { $post.from.emailAddress.address } else { "(Unknown)" }
                            $postDate    = if ($post.receivedDateTime) { $post.receivedDateTime } else { "" }

                            $attachNames = ""
                            if ($post.attachments -and $post.attachments.Count -gt 0) {
                                $attachNames = @($post.attachments | ForEach-Object { $_.name }) -join ", "
                            }

                            $totalBytes += [long]$bodyContent.Length
                            foreach ($att in @($post.attachments)) { $totalBytes += [long]$att.size }

                            if ($isSearch) {
                                $isMatch = $false
                                foreach ($t in $searchTerms) {
                                    if (($topic -like "*$t*") -or ($bodyText -like "*$t*") -or ($attachNames -like "*$t*")) {
                                        $isMatch = $true; break
                                    }
                                }
                                if (-not $isMatch) { continue }
                            }

                            $preview  = if ($bodyText) { $bodyText.Substring(0, [Math]::Min(500, $bodyText.Length)) } else { "(No Preview)" }
                            $bodyFile = ""

                            if ($SaveTo -and $bodyContent) {
                                $ext         = if ($post.body.contentType -eq "html") { "html" } else { "txt" }
                                $safeMailbox = Get-MailboxSafeFileName -Name $mbx.DisplayName
                                $safeDate    = ($postDate -replace 'T.*', '')
                                $safeTopic   = Get-MailboxSafeFileName -Name $topic -MaxLength 60
                                $mbxFolder   = Join-Path $SaveTo "Group_$safeMailbox"
                                if (-not (Test-Path $mbxFolder)) { New-Item -Path $mbxFolder -ItemType Directory | Out-Null }
                                $bodyFile    = Join-Path $mbxFolder "${safeDate}_${safeTopic}.$ext"
                                $bodyContent | Out-File -FilePath $bodyFile -Encoding UTF8
                            }

                            if ($SaveAttachments -and $post.hasAttachments) {
                                try {
                                    $attUri  = "https://graph.microsoft.com/v1.0/groups/$($mbx.Id)/threads/$($thread.id)/posts/$($post.id)/attachments"
                                    $attResp = Invoke-RestMethod -Method Get -Uri $attUri -Headers $headers -ErrorAction Stop
                                    $safeMailbox = Get-MailboxSafeFileName -Name $mbx.DisplayName
                                    $attFolder   = Join-Path (Join-Path $SaveTo "Group_$safeMailbox") "attachments"
                                    if (-not (Test-Path $attFolder)) { New-Item -Path $attFolder -ItemType Directory | Out-Null }
                                    foreach ($att in @($attResp.value)) {
                                        if ($att.'@odata.type' -eq '#microsoft.graph.fileAttachment' -and $att.contentBytes) {
                                            $attBytes = [System.Convert]::FromBase64String($att.contentBytes)
                                            [System.IO.File]::WriteAllBytes((Join-Path $attFolder $att.name), $attBytes)
                                        }
                                    }
                                } catch {
                                    if (-not $GraphRun) { Write-Host -ForegroundColor DarkYellow "`n[*] Could not retrieve attachments for post in '$topic'" }
                                }
                            }

                            $mbxHits.Add([pscustomobject]@{
                                "Detector Name"   = $DetectorName
                                "Mailbox Type"    = "Group"
                                "Mailbox ID"      = $mbx.Id
                                "Mailbox Display" = $mbx.DisplayName
                                "Mailbox Address" = $mbx.MailAddress
                                "Subject"         = $topic
                                "Sender"          = $postSender
                                "Receivers"       = ""
                                "Date"            = $postDate
                                "Preview"         = $preview
                                "HasAttachments"  = [bool]$post.hasAttachments
                                "AttachmentNames" = $attachNames
                                "BodyFile"        = $bodyFile
                            })

                            if (-not $ReportOnly) {
                                Write-Host "Subject: $topic | Sender: $postSender | Date: $postDate"
                                if ($attachNames) { Write-Host "Attachments: $attachNames" }
                                Write-Host "Preview: $($preview.Substring(0, [Math]::Min(200, $preview.Length)))"
                                Write-Host ("=" * 80)
                            }
                        }
                    }
                }

            } else {
                # Shallow path: conversations only (topic + preview)
                # -----------------------------------------------
                $nextUri   = "https://graph.microsoft.com/v1.0/groups/$($mbx.Id)/conversations?`$top=$MessageCount"
                $collected = [System.Collections.Generic.List[object]]::new()

                do {
                    $attempt = 0; $done = $false; $response = $null
                    while (-not $done -and $attempt -lt $maxRetries) {
                        try {
                            $response = Invoke-RestMethod -Method Get -Uri $nextUri -Headers $headers -ErrorAction Stop
                            $done = $true
                        } catch {
                            $sc = $null
                            try { $sc = [int]$_.Exception.Response.StatusCode       } catch {}
                            try { if (-not $sc) { $sc = [int]$_.Exception.Response.StatusCode.value__ } } catch {}
                            if ($sc -eq 401 -and $attempt -lt ($maxRetries - 1)) {
                                Invoke-RefreshGraphTokens -RefreshToken $refreshToken -AutoRefresh `
                                    -tenantid $tenantid -Resource $Resource -Client $Client `
                                    -ClientID $ClientID -Browser $Browser -Device $Device
                                if ($global:tokens) { $accessToken = $global:tokens.access_token; $refreshToken = $global:tokens.refresh_token; $headers["Authorization"] = "Bearer $accessToken"; $startTime = Get-Date }
                                $attempt++
                            } elseif ($sc -eq 429) {
                                $retryAfter = 10
                                try { $retryAfter = [int]$_.Exception.Response.Headers["Retry-After"] } catch {}
                                if (-not $GraphRun) { Write-Host -ForegroundColor DarkYellow "`n[*] Rate limited (429) -- sleeping ${retryAfter}s..." }
                                Start-Sleep -Seconds $retryAfter
                            } else {
                                if (-not $GraphRun) { Write-Host -ForegroundColor Red "`n[!] Failed to retrieve conversations from $mbxLabel (HTTP $sc): $($_.Exception.Message -replace 'HTTP \d+ - ','')" }
                                $done = $true
                            }
                        }
                    }
                    if ($null -eq $response) { break }
                    $collected.AddRange([object[]]@($response.value))
                    $nextUri = if (($PageResults -or $isSearch) -and $response.'@odata.nextLink') { $response.'@odata.nextLink' } else { $null }
                } while ($nextUri)

                $toOutput = if ($isSearch) {
                    @($collected | Where-Object {
                        $conv = $_
                        $matchFound = $false
                        foreach ($t in $searchTerms) {
                            if (($conv.topic -and $conv.topic -like "*$t*") -or ($conv.preview -and $conv.preview -like "*$t*")) {
                                $matchFound = $true; break
                            }
                        }
                        $matchFound
                    })
                } else { @($collected) }

                foreach ($conv in $toOutput) {
                    $topic   = if ($conv.topic)          { $conv.topic } else { "(No Subject)" }
                    $senders = if ($conv.uniqueSenders -and $conv.uniqueSenders.Count -gt 0) { $conv.uniqueSenders -join ", " } else { "(Unknown)" }
                    $date    = if ($conv.lastDeliveredDateTime) { $conv.lastDeliveredDateTime } else { "" }
                    $preview = if ($conv.preview)        { $conv.preview } else { "(No Preview)" }

                    $mbxHits.Add([pscustomobject]@{
                        "Detector Name"   = $DetectorName
                        "Mailbox Type"    = "Group"
                        "Mailbox ID"      = $mbx.Id
                        "Mailbox Display" = $mbx.DisplayName
                        "Mailbox Address" = $mbx.MailAddress
                        "Subject"         = $topic
                        "Sender"          = $senders
                        "Receivers"       = ""
                        "Date"            = $date
                        "Preview"         = $preview
                        "HasAttachments"  = [bool]$conv.hasAttachments
                        "AttachmentNames" = ""
                        "BodyFile"        = ""
                    })

                    if (-not $ReportOnly) {
                        Write-Host "Subject: $topic | Sender(s): $senders | Date: $date"
                        Write-Host "Preview: $preview"
                        Write-Host ("=" * 80)
                    }
                }
            }
        }

        # Write hits for this mailbox to CSV
        if ($OutFile -and $mbxHits.Count -gt 0) {
            if (-not $GraphRun) {
                Write-Host -ForegroundColor Yellow "`n[*] Writing $($mbxHits.Count) result(s) from $mbxLabel to $OutFile"
            }
            if ($csvHeaders) {
                $mbxHits | Export-Csv -Path $OutFile -NoTypeInformation -Append
            } else {
                $mbxHits | Export-Csv -Path $OutFile -NoTypeInformation
                $csvHeaders = $true
            }
        }

        $totalHits += $mbxHits.Count

        if (-not $GraphRun) {
            $pct = [int](($mbxNum / $mailboxes.Count) * 100)
            Write-Host -NoNewline -ForegroundColor Cyan "`r[*] $mbxNum/$($mailboxes.Count) ($pct%) -- $totalHits item(s) | $(Format-MbxSize $totalBytes) retrieved..."
            [System.Console]::Out.Flush()
        }
    }

    if (-not $GraphRun) { Write-Host "" }

    if ($isSearch) {
        if (-not $GraphRun) {
            Write-Host -ForegroundColor Yellow "[*] Found $totalHits match(es) for: $SearchTerm"
        } elseif ($totalHits -gt 0) {
            Write-Host -ForegroundColor Yellow "[*] Found $totalHits match(es) for detector: $DetectorName"
        }
    } else {
        if (-not $GraphRun) {
            Write-Host -ForegroundColor Yellow "[*] Retrieved $totalHits message(s) from $($mailboxes.Count) mailbox(es)."
        }
    }
}


function Search-MailboxCache {
    <#
    .SYNOPSIS
        Searches locally saved email bodies from a previous Get-MailboxMessages -SaveTo run.
    .DESCRIPTION
        Searches cached email files without making any API calls. Two modes:

        CSV mode (-InputCsv): Uses the CSV written by Get-MailboxMessages -OutFile as an index.
        Searches Subject, full body content (via BodyFile path), and AttachmentNames. All
        original metadata (Sender, Receivers, Date, etc.) is preserved in output.

        Folder-walk mode (-CachePath only): Walks the SaveTo folder structure directly. Searches
        filename-derived subject and body content. Sender/Receivers/AttachmentNames are not
        available without a CSV index.

        When both are supplied, CSV mode takes precedence.
    .PARAMETER InputCsv
        Path to the CSV produced by Get-MailboxMessages -OutFile. Used as the search index.
    .PARAMETER CachePath
        Path to the folder produced by Get-MailboxMessages -SaveTo. Used for folder-walk mode
        when no CSV is available.
    .PARAMETER SearchTerm
        String to search for. Checked against Subject, body content, and attachment names.
    .PARAMETER OutFile
        Path to write matching results as CSV.
    .PARAMETER DetectorName
        Label written to the "Detector Name" column in output. Default: "Custom".
    .PARAMETER ReportOnly
        Suppress per-hit console output.
    .PARAMETER GraphRun
        Suppress all non-error console output (for use in detector loops).
    #>
    [CmdletBinding()]
    param(
        [string]$InputCsv     = "",
        [string]$CachePath    = "",
        [string]$SearchTerm   = "",
        [string]$OutFile      = "",
        [string]$DetectorName = "Custom",
        [switch]$ReportOnly,
        [switch]$GraphRun
    )

    if (-not $InputCsv -and -not $CachePath) {
        Write-Host -ForegroundColor Red "[!] Provide -InputCsv, -CachePath, or both."
        return
    }
    if ([string]::IsNullOrWhiteSpace($SearchTerm)) {
        Write-Host -ForegroundColor Red "[!] -SearchTerm is required."
        return
    }
    if ($InputCsv -and -not (Test-Path $InputCsv)) {
        Write-Host -ForegroundColor Red "[!] CSV not found: $InputCsv"
        return
    }
    if ($CachePath -and -not (Test-Path $CachePath)) {
        Write-Host -ForegroundColor Red "[!] Cache path not found: $CachePath"
        return
    }

    $hits        = [System.Collections.Generic.List[object]]::new()
    $searchTerms = @(Expand-MbxSearchTerms -Query $SearchTerm)

    # -----------------------------------------------------------------------
    # CSV mode
    # -----------------------------------------------------------------------
    if ($InputCsv) {
        $rows = @(Import-Csv -Path $InputCsv -ErrorAction Stop)

        if (-not $GraphRun) {
            Write-Host -ForegroundColor Yellow "[*] Searching $($rows.Count) cached message(s) for: $SearchTerm"
        }

        foreach ($row in $rows) {
            $bodyText = ""
            if ($row.BodyFile -and (Test-Path $row.BodyFile)) {
                $raw      = Get-Content -Path $row.BodyFile -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
                $bodyText = Remove-MailboxHtmlTags -Html $raw
            }

            $isMatch = $false
            foreach ($t in $searchTerms) {
                if (($row.Subject -like "*$t*") -or ($bodyText -like "*$t*") -or ($row.AttachmentNames -like "*$t*")) {
                    $isMatch = $true; break
                }
            }

            if (-not $isMatch) { continue }

            $preview = if ($bodyText) { $bodyText.Substring(0, [Math]::Min(500, $bodyText.Length)) } else { $row.Preview }

            $hits.Add([pscustomobject]@{
                "Detector Name"   = $DetectorName
                "Mailbox Type"    = $row.'Mailbox Type'
                "Mailbox ID"      = $row.'Mailbox ID'
                "Mailbox Display" = $row.'Mailbox Display'
                "Mailbox Address" = $row.'Mailbox Address'
                "Subject"         = $row.Subject
                "Sender"          = $row.Sender
                "Receivers"       = $row.Receivers
                "Date"            = $row.Date
                "Preview"         = $preview
                "HasAttachments"  = $row.HasAttachments
                "AttachmentNames" = $row.AttachmentNames
                "BodyFile"        = $row.BodyFile
            })

            if (-not $ReportOnly) {
                Write-Host "Subject: $($row.Subject) | Sender: $($row.Sender) | Date: $($row.Date)"
                if ($row.AttachmentNames) { Write-Host "Attachments: $($row.AttachmentNames)" }
                Write-Host "Preview: $($preview.Substring(0, [Math]::Min(200, $preview.Length)))"
                Write-Host ("=" * 80)
            }
        }

    # -----------------------------------------------------------------------
    # Folder-walk mode
    # -----------------------------------------------------------------------
    } else {
        $bodyFiles = @(Get-ChildItem -Path $CachePath -Recurse -File -Include "*.html","*.txt" |
                       Where-Object { $_.DirectoryName -notmatch '[/\\]attachments$' })

        if (-not $GraphRun) {
            Write-Host -ForegroundColor Yellow "[*] Scanning $($bodyFiles.Count) cached file(s) for: $SearchTerm"
            Write-Host -ForegroundColor Yellow "[*] (Folder-walk mode -- Sender/Receivers/AttachmentNames not available without -InputCsv)"
        }

        foreach ($file in $bodyFiles) {
            $raw      = Get-Content -Path $file.FullName -Raw -Encoding UTF8 -ErrorAction SilentlyContinue
            $bodyText = Remove-MailboxHtmlTags -Html $raw

            $folderLeaf = Split-Path $file.DirectoryName -Leaf
            $mbxType    = if ($folderLeaf -match '^User_')  { "User"  }
                          elseif ($folderLeaf -match '^Group_') { "Group" }
                          else { "Unknown" }
            $mbxDisplay = $folderLeaf -replace '^(User_|Group_)', ''
            $fileBase   = [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
            $datePart   = if ($fileBase -match '^(\d{4}-\d{2}-\d{2})_') { $Matches[1] } else { "" }
            $subjPart   = $fileBase -replace '^\d{4}-\d{2}-\d{2}_', ''

            $isMatch = $false
            foreach ($t in $searchTerms) {
                if (($subjPart -like "*$t*") -or ($bodyText -like "*$t*")) {
                    $isMatch = $true; break
                }
            }

            if (-not $isMatch) { continue }

            $preview = if ($bodyText) { $bodyText.Substring(0, [Math]::Min(500, $bodyText.Length)) } else { "" }

            $hits.Add([pscustomobject]@{
                "Detector Name"   = $DetectorName
                "Mailbox Type"    = $mbxType
                "Mailbox ID"      = ""
                "Mailbox Display" = $mbxDisplay
                "Mailbox Address" = ""
                "Subject"         = $subjPart
                "Sender"          = ""
                "Receivers"       = ""
                "Date"            = $datePart
                "Preview"         = $preview
                "HasAttachments"  = ""
                "AttachmentNames" = ""
                "BodyFile"        = $file.FullName
            })

            if (-not $ReportOnly) {
                Write-Host "Subject: $subjPart | Mailbox: $mbxDisplay ($mbxType) | Date: $datePart"
                Write-Host "Preview: $($preview.Substring(0, [Math]::Min(200, $preview.Length)))"
                Write-Host ("=" * 80)
            }
        }
    }

    # -----------------------------------------------------------------------
    # Output
    # -----------------------------------------------------------------------
    if ($OutFile -and $hits.Count -gt 0) {
        $hits | Export-Csv -Path $OutFile -NoTypeInformation
        if (-not $GraphRun) {
            Write-Host -ForegroundColor Yellow "[*] Wrote $($hits.Count) match(es) to $OutFile"
        }
    }

    if (-not $GraphRun) {
        Write-Host -ForegroundColor Yellow "[*] Found $($hits.Count) match(es) for: $SearchTerm"
    } elseif ($hits.Count -gt 0) {
        Write-Host -ForegroundColor Yellow "[*] Found $($hits.Count) match(es) for detector: $DetectorName"
    }
}
