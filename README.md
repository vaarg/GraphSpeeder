# GraphSpeeder

PowerShell scripts for Microsoft Entra ID and Microsoft 365 pentesting. Some scripts are supplements to [GraphRunner](https://github.com/dafthack/GraphRunner) — extending or hardening its existing functions — while others are standalone modules that provide capabilities GraphRunner does not cover at all. Not all scripts require GraphRunner to be loaded.

## Scripts

### [Resume-GroupAudit.ps1](Resume-GroupAudit.ps1)
*GraphRunner supplement*

Three-phase replacement for `Get-UpdatableGroups`. Splits group enumeration, access checking, and detail enrichment into independent resumable phases. Handles token expiry reactively instead of silently swallowing 401s.

> Full documentation: [wiki/GroupAudit](https://github.com/vaarg/GraphSpeeder/wiki/GroupAudit)

### [Resume-SharePointAudit.ps1](Resume-SharePointAudit.ps1)
*GraphRunner supplement*

Multi-phase SharePoint and OneDrive audit. Enumerates site collections via the SPO SDK (admin), tests per-site Graph API access as a standard user, then searches accessible sites using KQL `path:` scoping — bypassing the site-discovery step that fails in restricted tenants. Includes a per-drive fallback search for environments where the Graph Search API is blocked.

> Full documentation: [wiki/SharePointAudit](https://github.com/vaarg/GraphSpeeder/wiki/SharePointAudit)

### [Invoke-AccessCheck.ps1](Invoke-AccessCheck.ps1)
*Standalone*

Identity and access auditing module. Given a token, enumerates the target user's or service principal's group memberships, directory roles (active and PIM-eligible), registered MFA methods, Conditional Access Policy coverage, app role assignments, OAuth2 permission grants, and identity risk state. Optionally probes common Azure/M365 resource URIs via refresh token exchange to determine what services the token can reach. Produces a severity-tagged findings summary (Critical / High / Medium / Info). Integrates with GraphRunner for token refresh resilience but does not depend on it for its core function.

> Full documentation: [wiki/AccessCheck](https://github.com/vaarg/GraphSpeeder/wiki/AccessCheck)

### [Invoke-MailboxAudit.ps1](Invoke-MailboxAudit.ps1)
*GraphRunner supplement*

Three-function mailbox audit. Probes user mailboxes and Microsoft 365 group inboxes for read access, producing a unified accessible-mailboxes CSV. Reads or searches messages from those that are accessible, with optional full body and attachment download. Searches previously saved bodies offline with zero API calls for opsec-safe repeated keyword searches. Designed to chain with `Resume-GroupAudit.ps1` output for group inbox discovery. Replaces `Invoke-GraphOpenInboxFinder`, which sets the HTTP status code in a variable that is never subsequently referenced, making every 401, 403, 404, and 429 response completely silent.

> Full documentation: [wiki/MailboxAudit](https://github.com/vaarg/GraphSpeeder/wiki/MailboxAudit)

---

## Requirements

Requirements vary by script:

| Script | GraphRunner required? | Notes |
|---|---|---|
| `Resume-GroupAudit.ps1` | Yes | Calls `Invoke-RefreshGraphTokens` |
| `Resume-SharePointAudit.ps1` | Yes | Calls `Invoke-RefreshGraphTokens`, `Invoke-ForgeUserAgent`, `Invoke-DriveFileDownload` |
| `Invoke-AccessCheck.ps1` | Optional | Uses `Invoke-RefreshGraphTokens` for token refresh resilience only; runs without it if the token does not expire |
| `Invoke-MailboxAudit.ps1` | Yes | Calls `Invoke-RefreshGraphTokens` |

All scripts require:
- Windows PowerShell 5.1 or PowerShell 7+
- A valid access token for the target tenant

## Setup

```powershell
# Load GraphRunner first if using the supplement scripts or want token refresh in Invoke-AccessCheck
. .\GraphRunner\GraphRunner.ps1

# Load whichever scripts you need
. .\Resume-GroupAudit.ps1
. .\Resume-SharePointAudit.ps1
. .\Invoke-AccessCheck.ps1
. .\Invoke-MailboxAudit.ps1
```

## Credits

GraphRunner is authored by Beau Bullock ([@dafthack](https://github.com/dafthack)) and licensed under MIT.
