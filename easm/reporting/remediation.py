from easm.core.ports import port_remediation

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
    "git-config": (
        "Remove the .git directory from the web root and block dotfiles. "
        "Rotate any credentials stored in remotes."
    ),
    "ssh-private-key": (
        "Remove the key from the web root and treat it as compromised: revoke and regenerate it."
    ),
    "aws-credentials": (
        "Remove the credentials file from the web root and rotate the AWS access keys at once."
    ),
    "wp-config-backup": (
        "Delete the backup from the web root and rotate the database password and WordPress salts."
    ),
    "sql-dump": (
        "Delete the dump from the web root, keep backups outside served paths and review it "
        "for personal data."
    ),
    "database-sql": (
        "Delete the dump from the web root, keep backups outside served paths and review it "
        "for personal data."
    ),
    "backup-sql": (
        "Delete the dump from the web root, keep backups outside served paths and review it "
        "for personal data."
    ),
    "backup-targz": (
        "Delete the archive from the web root and store backups outside publicly served paths."
    ),
    "htpasswd": (
        "Deny access to .htpasswd and move it outside the web root; reset the affected passwords."
    ),
    "sqlite-database": (
        "Move the database outside the web root and deny direct access to database files."
    ),
    "svn-database": "Remove .svn directories from deployments and block access to dotfiles.",
    "actuator-env": (
        "Restrict Spring Boot actuator endpoints to internal networks and require authentication."
    ),
    "npmrc": "Remove .npmrc from the web root and revoke the exposed npm token.",
    "phpinfo": "Delete phpinfo pages from production; they disclose paths, modules and environment.",
    "phpinfo-info": (
        "Delete phpinfo pages from production; they disclose paths, modules and environment."
    ),
    "server-status": "Restrict mod_status to localhost or trusted addresses.",
    "dir-listing": "Disable directory indexing (Options -Indexes) and review the exposed files.",
    "dir-listing-uploads": (
        "Disable directory indexing (Options -Indexes) and review the exposed files."
    ),
    "phpmyadmin": (
        "Restrict phpMyAdmin to a VPN or allow-listed addresses, or remove it from production."
    ),
    "ds-store": "Delete .DS_Store files from deployments; they list file and folder names.",
    "swagger": "Confirm the API definition is meant to be public; otherwise require authentication.",
    "robots-txt": (
        "Informational. Make sure Disallow entries do not advertise sensitive paths; "
        "robots.txt is not an access control."
    ),
    "security-txt": "Informational. Keep the published contact and expiry date up to date.",
}
DEFAULT_REMEDIATION = "Review the exposed resource and restrict access if it is not intended."


def remediation_for(check: str) -> str:
    return REMEDIATION.get(check) or port_remediation(check) or DEFAULT_REMEDIATION
