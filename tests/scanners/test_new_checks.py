import pytest

from easm.scanners.exposures import CHECKS, Probe

BY_ID = {c.id: c for c in CHECKS}
HTML = "<!doctype html><html><title>Not found</title></html>"

CASES: list[tuple[str, bytes]] = [
    ("git-config", b"[core]\n\trepositoryformatversion = 0\n"),
    ("ssh-private-key", b"-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n"),
    ("aws-credentials", b"[default]\naws_access_key_id = AKIAxxxx\n"),
    ("wp-config-backup", b"<?php define('DB_PASSWORD', 'hunter2');"),
    ("sql-dump", b"DROP TABLE IF EXISTS users;\nCREATE TABLE users (id int);"),
    ("database-sql", b"INSERT INTO users VALUES (1);"),
    ("backup-sql", b"CREATE TABLE t (a int);"),
    ("backup-targz", b"\x1f\x8b\x08\x00rest"),
    ("htpasswd", b"admin:$apr1$abc$hashhashhash\n"),
    ("sqlite-database", b"SQLite format 3\x00rest"),
    ("svn-database", b"SQLite format 3\x00rest"),
    ("actuator-env", b'{"activeProfiles":[],"propertySources":[]}'),
    ("npmrc", b"//registry.npmjs.org/:_authToken=abc123\n"),
    ("phpinfo", b"<html><head><title>phpinfo()</title></head></html>"),
    ("phpinfo-info", b"<h1>PHP Version </h1>"),
    ("server-status", b"<html><h1>Apache Server Status for host</h1></html>"),
    ("dir-listing", b"<html><head><title>Index of /backup</title></head></html>"),
    ("dir-listing-uploads", b"<html><head><title>Index of /uploads</title></head></html>"),
    ("phpmyadmin", b"<html><head><title>phpMyAdmin</title></head></html>"),
    ("ds-store", b"\x00\x00\x00\x01Bud1\x00\x00"),
    ("swagger", b'{"swagger": "2.0", "info": {}}'),
]

# Checks whose signature legitimately lives inside an HTML page.
HTML_BASED = {
    "phpinfo",
    "phpinfo-info",
    "server-status",
    "dir-listing",
    "dir-listing-uploads",
    "phpmyadmin",
    "web-config",
}


def _probe(body: bytes) -> Probe:
    return Probe(200, body, "text/plain")


def test_check_ids_are_unique_and_cover_cases() -> None:
    ids = [c.id for c in CHECKS]
    assert len(ids) == len(set(ids)) >= 25
    assert {case_id for case_id, _ in CASES} <= set(ids)


@pytest.mark.parametrize(("check_id", "body"), CASES)
def test_validator_accepts_real_content(check_id: str, body: bytes) -> None:
    evidence = BY_ID[check_id].validate(_probe(body))
    assert evidence
    for secret in ("hunter2", "abc123", "AKIAxxxx", "hashhashhash"):
        assert secret not in evidence  # evidence never echoes secret values


@pytest.mark.parametrize("check_id", [c.id for c in CHECKS])
def test_validator_rejects_generic_soft_404_page(check_id: str) -> None:
    assert BY_ID[check_id].validate(_probe(HTML.encode())) is None


@pytest.mark.parametrize("check_id", sorted(set(BY_ID) - HTML_BASED - {"robots-txt"}))
def test_validator_rejects_html_mentioning_signature(check_id: str) -> None:
    body = "<html><body>[core] DB_PASSWORD CREATE TABLE _authToken= ref: refs/heads/x</body></html>"
    assert BY_ID[check_id].validate(_probe(body.encode())) is None


@pytest.mark.parametrize("check_id", ["git-head", "env-file", "backup-zip", "ds-store"])
def test_validator_rejects_empty_body(check_id: str) -> None:
    assert BY_ID[check_id].validate(_probe(b"")) is None
