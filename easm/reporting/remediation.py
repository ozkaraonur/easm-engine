REMEDIATION: dict[str, str] = {
    "git-head": (
        "Remove the .git directory from the web root and block access to dotfiles at the web "
        "server. Assume source code and embedded credentials are compromised: rotate them."
    ),
    "env-file": (
        "Remove the .env file from the web root and deny access to dotfiles. Rotate every "
        "secret it contained (database, API and application keys)."
    ),
    "backup-zip": (
        "Delete the archive from the web root and store backups outside publicly served "
        "paths. Review its contents for secrets and rotate any that were exposed."
    ),
    "web-config": (
        "Deny direct access to web.config (IIS request filtering) and review it for "
        "connection strings and machine keys."
    ),
    "robots-txt": (
        "Informational. Make sure Disallow entries do not advertise sensitive paths; "
        "robots.txt is not an access control."
    ),
    "security-txt": "Informational. Keep the published contact and expiry date up to date.",
}
DEFAULT_REMEDIATION = "Review the exposed resource and restrict access if it is not intended."


def remediation_for(check: str) -> str:
    return REMEDIATION.get(check, DEFAULT_REMEDIATION)
