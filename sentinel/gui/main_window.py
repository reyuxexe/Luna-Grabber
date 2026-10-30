from __future__ import annotations

import logging
import os
from collections import Counter

from PySide6.QtCore import QObject, QThread, Signal, Qt
from PySide6.QtGui import QColor, QAction
from PySide6.QtWidgets import (QApplication, QFileDialog, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
                               QProgressBar, QPushButton, QSystemTrayIcon, QTableWidget,
                               QTableWidgetItem, QTabWidget, QTextEdit, QVBoxLayout, QWidget,
                               QAbstractItemView, QHeaderView, QCheckBox)

from sentinel import __version__
from sentinel.core.models import Finding, Severity, Verdict, findings_to_json, findings_to_text
from sentinel.core.quarantine import Quarantine, QuarantineError
from sentinel.core.signatures import IOCDatabase
from sentinel.gui.theme import QSS, SEVERITY_COLORS
from sentinel.scanners import engine
from sentinel.scanners.realtime import RealtimeMonitor

log = logging.getLogger("sentinel.gui")


class ScanWorker(QThread):
    stage = Signal(str, int)
    status = Signal(str)
    done = Signal(list, int)

    def __init__(self, ioc, roots):
        super().__init__()
        self.ioc, self.roots, self._cancel = ioc, roots, False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            f, n = engine.run_full_scan(self.ioc, self.roots, self.stage.emit, self.status.emit, lambda: self._cancel)
        except Exception:
            log.exception("scan crashed")
            f, n = [], 0
        self.done.emit(f, n)


class Bridge(QObject):
    finding = Signal(object)


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Sentinel Security Auditor {__version__}")
        self.resize(1150, 740)
        self.ioc = IOCDatabase()
        self.quarantine = Quarantine()
        self.findings: list[Finding] = []
        self.worker: ScanWorker | None = None
        self.monitor: RealtimeMonitor | None = None
        self.bridge = Bridge()
        self.bridge.finding.connect(self._on_rt_finding)
        self.tray = QSystemTrayIcon(self)
        self.tray.setIcon(self.style().standardIcon(self.style().StandardPixmap.SP_MessageBoxWarning))
        self.roots = engine.default_file_roots()

        tabs = QTabWidget()
        tabs.addTab(self._dashboard(), "Dashboard")
        tabs.addTab(self._results(), "Findings")
        tabs.addTab(self._realtime(), "Real-time")
        tabs.addTab(self._settings(), "Settings")
        self.setCentralWidget(tabs)
        self._refresh()

    # ---- tabs
    def _card(self, title):
        w = QWidget(); w.setObjectName("card")
        l = QVBoxLayout(w)
        v = QLabel("0"); v.setStyleSheet("font-size:30px;font-weight:bold;")
        l.addWidget(QLabel(title)); l.addWidget(v)
        w.value = v
        return w

    def _dashboard(self):
        w = QWidget(); lay = QVBoxLayout(w)
        row = QHBoxLayout()
        self.cards = {k: self._card(k) for k in ("Confirmed", "Suspicious", "Unknown", "Files scanned")}
        for c in self.cards.values():
            row.addWidget(c)
        lay.addLayout(row)
        self.sev_label = QLabel(); lay.addWidget(self.sev_label)
        self.stage_label = QLabel("Idle"); self.bar = QProgressBar()
        self.status = QLabel(""); self.status.setStyleSheet("color:#8b93a1")
        lay.addWidget(self.stage_label); lay.addWidget(self.bar); lay.addWidget(self.status)
        btns = QHBoxLayout()
        self.scan_btn = QPushButton("Run full scan"); self.scan_btn.clicked.connect(self.start_scan)
        self.cancel_btn = QPushButton("Cancel"); self.cancel_btn.clicked.connect(self._cancel); self.cancel_btn.setEnabled(False)
        btns.addWidget(self.scan_btn); btns.addWidget(self.cancel_btn); btns.addStretch()
        lay.addLayout(btns)
        note = QLabel("Verdicts: Confirmed = exact SHA-256 match with your IOC list. Suspicious = heuristic "
                      "indicators, may be benign. Unknown = could not be assessed.")
        note.setWordWrap(True); note.setStyleSheet("color:#8b93a1")
        lay.addWidget(note); lay.addStretch()
        return w

    def _results(self):
        w = QWidget(); lay = QVBoxLayout(w)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Severity", "Verdict", "Category", "Title", "Target"])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self._show_detail)
        self.detail = QTextEdit(); self.detail.setReadOnly(True)
        lay.addWidget(self.table, 3); lay.addWidget(self.detail, 2)
        row = QHBoxLayout()
        q = QPushButton("Quarantine selected file..."); q.clicked.connect(self._quarantine)
        r = QPushButton("Export report..."); r.clicked.connect(self._export)
        row.addWidget(q); row.addWidget(r); row.addStretch()
        lay.addLayout(row)
        return w

    def _realtime(self):
        w = QWidget(); lay = QVBoxLayout(w)
        self.rt_toggle = QCheckBox("Enable real-time process monitoring (polls every 3 s)")
        self.rt_toggle.toggled.connect(self._toggle_rt)
        self.rt_log = QTextEdit(); self.rt_log.setReadOnly(True)
        lay.addWidget(self.rt_toggle); lay.addWidget(self.rt_log)
        return w

    def _settings(self):
        w = QWidget(); lay = QVBoxLayout(w)
        self.ioc_label = QLabel("IOC database: empty (no Confirmed detections are possible until you load SHA-256 hashes)")
        b = QPushButton("Load IOC hash list..."); b.clicked.connect(self._load_ioc)
        self.roots_label = QLabel(); 
        b2 = QPushButton("Choose scan folder..."); b2.clicked.connect(self._choose_root)
        self._roots_text()
        for x in (self.ioc_label, b, self.roots_label, b2):
            lay.addWidget(x)
        lay.addStretch()
        return w

    # ---- actions
    def _roots_text(self):
        self.roots_label.setText("File scan folders:\n" + "\n".join(self.roots))

    def _choose_root(self):
        d = QFileDialog.getExistingDirectory(self, "Folder to scan")
        if d:
            self.roots = [d]; self._roots_text()

    def _load_ioc(self):
        p, _ = QFileDialog.getOpenFileName(self, "IOC list (one SHA-256 per line)", "", "Text (*.txt *.csv);;All (*)")
        if p:
            try:
                n = self.ioc.load_file(p)
                self.ioc_label.setText(f"IOC database: {len(self.ioc.hashes)} hashes loaded ({n} from last file)")
            except OSError as e:
                QMessageBox.warning(self, "Error", str(e))

    def start_scan(self):
        self.findings = []; self._refresh()
        self.worker = ScanWorker(self.ioc, self.roots)
        self.worker.stage.connect(lambda s, p: (self.stage_label.setText(f"Scanning: {s}"), self.bar.setValue(p)))
        self.worker.status.connect(lambda s: self.status.setText(s[:140]))
        self.worker.done.connect(self._scan_done)
        self.scan_btn.setEnabled(False); self.cancel_btn.setEnabled(True)
        self.worker.start()

    def _cancel(self):
        if self.worker:
            self.worker.cancel()

    def _scan_done(self, findings, nfiles):
        self.findings = findings; self.files_scanned = nfiles
        self.scan_btn.setEnabled(True); self.cancel_btn.setEnabled(False)
        self.stage_label.setText("Scan finished"); self.bar.setValue(100)
        self._refresh()

    def _refresh(self):
        c = Counter(f.verdict for f in self.findings)
        self.cards["Confirmed"].value.setText(str(c[Verdict.CONFIRMED]))
        self.cards["Suspicious"].value.setText(str(c[Verdict.SUSPICIOUS]))
        self.cards["Unknown"].value.setText(str(c[Verdict.UNKNOWN]))
        self.cards["Files scanned"].value.setText(str(getattr(self, "files_scanned", 0)))
        sc = Counter(f.severity for f in self.findings)
        self.sev_label.setText("  ".join(f'<span style="color:{SEVERITY_COLORS[s]}">■ {s.name}: {sc[s]}</span>'
                                       for s in sorted(Severity, reverse=True)))
        self.table.setRowCount(0)
        for f in sorted(self.findings, key=lambda x: -x.severity):
            self._add_row(f)

    def _add_row(self, f):
        r = self.table.rowCount(); self.table.insertRow(r)
        for i, t in enumerate([f.severity.name, f.verdict.value, f.category, f.title, f.target]):
            it = QTableWidgetItem(t)
            if i == 0:
                it.setForeground(QColor(SEVERITY_COLORS[f.severity]))
            it.setData(Qt.UserRole, f)
            self.table.setItem(r, i, it)

    def _selected(self) -> Finding | None:
        rows = self.table.selectionModel().selectedRows()
        return self.table.item(rows[0].row(), 0).data(Qt.UserRole) if rows else None

    def _show_detail(self):
        f = self._selected()
        if f:
            self.detail.setPlainText(findings_to_text([f]))

    def _quarantine(self):
        f = self._selected()
        if not f or not os.path.isfile(f.target):
            QMessageBox.information(self, "Quarantine", "Select a finding whose target is a file.")
            return
        warn = "" if f.verdict == Verdict.CONFIRMED else "\n\nThis is only a SUSPICIOUS (heuristic) result and may be a false positive."
        if QMessageBox.question(self, "Confirm quarantine", f"Move to quarantine?\n{f.target}{warn}") != QMessageBox.Yes:
            return
        try:
            dest = self.quarantine.quarantine(f.target, confirmed_by_user=True)
            QMessageBox.information(self, "Quarantine", f"Moved to {dest}")
        except QuarantineError as e:
            QMessageBox.warning(self, "Quarantine failed", str(e))

    def _export(self):
        p, sel = QFileDialog.getSaveFileName(self, "Save report", "sentinel_report.json", "JSON (*.json);;Text (*.txt)")
        if p:
            try:
                with open(p, "w", encoding="utf-8") as fh:
                    fh.write(findings_to_json(self.findings) if p.endswith(".json") else findings_to_text(self.findings))
            except OSError as e:
                QMessageBox.warning(self, "Error", str(e))

    def _toggle_rt(self, on):
        if on:
            self.monitor = RealtimeMonitor(self.ioc, self.bridge.finding.emit)
            self.monitor.start()
            self.rt_log.append("Monitoring started.")
        elif self.monitor:
            self.monitor.stop(); self.rt_log.append("Monitoring stopped.")

    def _on_rt_finding(self, f: Finding):
        self.findings.append(f); self._refresh()
        self.rt_log.append(f"[{f.severity.name}/{f.verdict.value}] {f.title}\n  {f.target}\n")
        self.tray.show()
        self.tray.showMessage(f"{f.verdict.value}: {f.title}", "; ".join(f.indicators)[:200])

    def closeEvent(self, e):
        if self.monitor:
            self.monitor.stop()
        if self.worker and self.worker.isRunning():
            self.worker.cancel(); self.worker.wait(3000)
        super().closeEvent(e)
