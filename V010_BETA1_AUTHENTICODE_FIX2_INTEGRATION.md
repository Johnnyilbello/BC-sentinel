# v0.10 Beta1 Authenticode FIX2 integration note

The current full tree uses native Windows WinVerifyTrust as the authoritative signature-validity decision path. PowerShell certificate metadata is advisory enrichment only. This supersedes the earlier PowerShell-only parsing path that produced UnknownError on the Windows host. The filename remains data-only and no execution-policy relaxation is used by the scanner.
