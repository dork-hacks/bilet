import pytest

from tool.engine.parser import RawHost, RawPort
from tool.engine.rules import host_hits, is_outdated, outdated_hits


@pytest.mark.parametrize(
    ("product", "version", "outdated"),
    [
        # vsftpd 2.3.4 exactly
        ("vsftpd", "2.3.4", True),
        ("vsftpd", "2.3.5", False),
        ("vsftpd", "3.0.3", False),
        ("vsftpd", "2.3", False),  # not enough to tell
        # OpenSSH below 7.4
        ("OpenSSH", "7.2p2 Ubuntu 4ubuntu2.8", True),
        ("OpenSSH", "6.6.1p1", True),
        ("OpenSSH", "7.3", True),
        ("OpenSSH", "7.4p1 Debian 10", False),
        ("OpenSSH", "8.9p1", False),
        ("OpenSSH", "7", False),  # not enough to tell
        # Apache httpd 2.2.x or older
        ("Apache httpd", "2.2.22", True),
        ("Apache httpd", "2.2.x", True),
        ("Apache httpd", "2.0.64", True),
        ("Apache httpd", "1.3.42", True),
        ("Apache httpd", "2.4.62", False),
        ("Apache Tomcat", "2.2.1", False),  # a different product
        # Microsoft IIS 7.5 or older
        ("Microsoft IIS httpd", "7.5", True),
        ("Microsoft IIS httpd", "6.0", True),
        ("Microsoft IIS httpd", "8.0", False),
        ("Microsoft IIS httpd", "10.0", False),
        # Samba 3.x or older
        ("Samba smbd", "3.0.20-Debian", True),
        ("Samba smbd", "3.X", True),
        ("Samba smbd", "2.2.8a", True),
        ("Samba smbd", "4.15", False),
        ("Samba smbd", "3.X - 4.X", False),  # #8 item 1: upper bound 4 is not old
        ("Samba smbd", "1.X - 3.X", True),  # upper bound 3 is old
        # nothing to judge
        ("Samba smbd", None, False),
        ("Samba smbd", "", False),
        (None, "2.3.4", False),
        ("nginx", "1.0.0", False),
    ],
)
def test_outdated_list(product, version, outdated):
    assert is_outdated(product, version) is outdated


def make_port(port, name, product=None, version=None, tunnel=None, title=None):
    return RawPort(port, "tcp", name, product, version, tunnel, "probed", title)


def summary(hits):
    return sorted((h.port.port if h.port else -1, h.entry.code) for h in hits)


def make_host(*ports):
    return RawHost("192.168.1.60", None, "Acme", ("box",), ports)


def test_v4_vsftpd_gives_two_rows():
    host = make_host(make_port(21, "ftp", "vsftpd", "2.3.4"))
    assert summary(host_hits(host)) == [(21, "FTP_CLEARTEXT"), (21, "OUTDATED_SERVICE")]


def test_outdated_without_its_own_finding_still_counts():
    # Apache 2.2 on plain http with no admin title, and on https: no own finding either way.
    host = make_host(
        make_port(80, "http", "Apache httpd", "2.2.22", title="It works!"),
        make_port(443, "http", "Apache httpd", "2.2.22", tunnel="ssl", title="Admin"),
    )
    assert summary(host_hits(host)) == [(80, "OUTDATED_SERVICE"), (443, "OUTDATED_SERVICE")]


def test_outdated_samba_is_one_per_device_on_the_smb_port():
    host = make_host(
        make_port(139, "netbios-ssn", "Samba smbd", "3.0.20-Debian"),
        make_port(445, "microsoft-ds", "Samba smbd", "3.0.20-Debian"),
    )
    assert summary(host_hits(host)) == [(445, "OUTDATED_SERVICE"), (445, "SMB_EXPOSED")]


def test_outdated_samba_only_on_139():
    host = make_host(make_port(139, "netbios-ssn", "Samba smbd", "3.6.25"))
    assert summary(outdated_hits(host)) == [(139, "OUTDATED_SERVICE")]


def test_up_to_date_host_has_no_outdated_hits():
    host = make_host(
        make_port(22, "ssh", "OpenSSH", "8.9p1"), make_port(21, "ftp", "vsftpd", "3.0.5")
    )
    assert outdated_hits(host) == []
