import re
import stat
from pathlib import Path

import pytest

from tool.engine import analyze_file
from tool.engine.device import load_salt
from tool.history import History, HistoryError, diff_results, pair_devices

VALIDATION = Path(__file__).parent / "fixtures" / "validation"
SALT = b"test-salt"


def scan(name: str) -> dict:
    return analyze_file(VALIDATION / name, salt=SALT).to_dict()


@pytest.fixture
def history(tmp_path):
    return History(tmp_path / "data")


# --- the brief's before/after pair ----------------------------------------------------


def test_v6a_to_v6b_shows_three_resolved_findings(history):
    before = history.add(scan("V6a_before.xml"))
    after = history.add(scan("V6b_after.xml"))
    d = history.diff(before, after)
    assert (d.score_before, d.score_after, d.score_change) == (60, 100, 40)
    assert sorted((f["code"], f["ip"], f["port"]) for f in d.resolved_findings) == [
        ("HTTP_ADMIN_CLEARTEXT", "192.168.1.1", 80),
        ("TELNET_OPEN", "192.168.1.30", 23),
        ("UPNP_EXPOSED", "192.168.1.1", 1900),
    ]
    assert d.new_findings == []
    # Same home, though every device's MAC changed between the two files (only the vendor
    # half stayed): no false "new device" or "removed device".
    assert d.new_devices == [] and d.removed_devices == []
    assert [(p.ip, p.protocol, p.port) for p in d.opened_ports] == [("192.168.1.1", "tcp", 443)]
    assert sorted((p.ip, p.port) for p in d.closed_ports) == [
        ("192.168.1.1", 80),
        ("192.168.1.1", 1900),
        ("192.168.1.30", 23),
    ]


def test_latest_diff_compares_the_two_newest_readable_scans(history):
    history.add(scan("V6b_after.xml"))  # added first, but its scan_start is later
    history.add(scan("V7_broken.xml"))  # unreadable scans are kept but never compared
    history.add(scan("V6a_before.xml"))
    d = history.latest_diff()
    assert (d.old.file, d.new.file) == ("V6a_before.xml", "V6b_after.xml")


def test_reverse_diff_shows_findings_coming_back(history):
    before = history.add(scan("V6a_before.xml"))
    after = history.add(scan("V6b_after.xml"))
    d = history.diff(after, before)
    assert len(d.new_findings) == 3 and d.resolved_findings == [] and d.score_change == -40


# --- pairing devices ------------------------------------------------------------------


def device(key, ip, mac="50:C7:BF:xx:xx:xx", hostname="box"):
    return {"device_key": key, "ip": ip, "mac_masked": mac, "hostname": hostname}


def test_pairing_rounds():
    old = [
        device("d_a", "192.168.1.1"),  # round 1: same key
        device("d_b", "192.168.1.2", hostname="cam"),  # round 2: MAC randomised, same IP
        device("d_c", "192.168.1.3", hostname="nas"),  # round 3: same name, new IP
        device("d_d", "192.168.1.4", mac="AA:BB:CC:xx:xx:xx"),  # gone
    ]
    new = [
        device("d_a", "192.168.1.1"),
        device("d_b2", "192.168.1.2", hostname="cam"),
        device("d_c2", "192.168.1.33", hostname="nas"),
        device("d_e", "192.168.1.4", mac="11:22:33:xx:xx:xx"),  # other vendor: a new device
    ]
    assert pair_devices(old, new) == {"d_a": "d_a", "d_b2": "d_b", "d_c2": "d_c"}


def test_same_ip_with_a_different_hostname_is_not_the_same_device():
    old = [device("d_1", "192.168.1.5", hostname="tv")]
    new = [device("d_2", "192.168.1.5", hostname="laptop")]
    assert pair_devices(old, new) == {}


def test_ambiguous_matches_stay_unpaired():
    old = [
        device("d_1", "192.168.1.5", hostname="plug"),
        device("d_2", "192.168.1.6", hostname="plug"),
    ]
    new = [device("d_3", "192.168.1.9", hostname="plug")]  # which plug moved? don't guess
    assert pair_devices(old, new) == {}


def test_devices_without_a_mac_pair_only_by_key():
    old = [device("d_1", "192.168.1.99", mac=None, hostname=None)]
    new = [device("d_2", "192.168.1.99", mac=None, hostname=None)]
    assert pair_devices(old, new) == {}


def test_unreadable_scans_cannot_be_compared():
    with pytest.raises(HistoryError):
        diff_results(scan("V6a_before.xml"), scan("V7_broken.xml"))


# --- storage --------------------------------------------------------------------------


def test_scans_are_ordered_by_scan_start_then_file(history):
    for name in ("V3_small_office.xml", "V1_home_basic.xml", "V7_broken.xml", "V2_smart_home.xml"):
        history.add(scan(name))
    order = [s.file for s in history.scans()]
    starts = [s.scan_start for s in history.scans()]
    with_start = [s for s in starts if s is not None]
    assert with_start == sorted(with_start)
    assert order[-1] == "V7_broken.xml"  # no start time: last


def test_adding_the_same_result_twice_keeps_one_row(history):
    first = history.add(scan("V1_home_basic.xml"))
    assert history.add(scan("V1_home_basic.xml")) == first
    assert len(history.scans()) == 1


def test_results_round_trip(history):
    data = scan("V2_smart_home.xml")
    assert history.result(history.add(data)) == data
    with pytest.raises(HistoryError):
        history.result(999)


def test_score_trend(history):
    for name in ("V6a_before.xml", "V6b_after.xml", "V7_broken.xml"):
        history.add(scan(name))
    assert [score for _, score in history.score_trend()] == [60, 100]


def test_empty_history(tmp_path):
    h = History(tmp_path / "nothing")
    assert h.scans() == [] and h.latest_diff() is None
    assert not (tmp_path / "nothing").exists()  # reading never creates the database


def test_no_raw_mac_is_stored(history):
    history.add(scan("V6a_before.xml"))
    stored = history.path.read_bytes().upper()
    xml = (VALIDATION / "V6a_before.xml").read_bytes()
    raw = [m.upper() for m in re.findall(rb'addr="([0-9A-Fa-f:]{17})" addrtype="mac"', xml)]
    assert raw and not any(mac in stored for mac in raw)


def test_database_is_private(history):
    history.add(scan("V1_home_basic.xml"))
    assert stat.S_IMODE(history.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(history.folder.stat().st_mode) == 0o700


# --- delete my history ----------------------------------------------------------------


def test_delete_my_history_leaves_nothing(tmp_path):
    folder = tmp_path / "data"
    h = History(folder)
    h.add(scan("V1_home_basic.xml"))
    load_salt(folder)
    (folder / "ai_cache").mkdir()
    (folder / "ai_cache" / "x.json").write_text("{}")
    (folder / "ai_rejections.jsonl").write_text("{}\n")
    h.delete_all()
    assert list(folder.iterdir()) == []
    assert h.scans() == []
    h.delete_all()  # twice is fine
