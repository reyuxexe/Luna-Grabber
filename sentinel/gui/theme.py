from sentinel.core.models import Severity

SEVERITY_COLORS = {Severity.CRITICAL: "#ff3b4e", Severity.HIGH: "#ff8a3d", Severity.MEDIUM: "#f5c542",
                   Severity.LOW: "#4aa3ff", Severity.INFO: "#8b93a1"}

QSS = """
QWidget { background:#14161b; color:#e3e6ec; font-family:'Segoe UI'; font-size:13px; }
QTabWidget::pane { border:1px solid #262a33; }
QTabBar::tab { background:#1b1e25; padding:8px 18px; border:1px solid #262a33; }
QTabBar::tab:selected { background:#2a3040; color:#fff; }
QPushButton { background:#2d6cdf; border:none; border-radius:5px; padding:8px 16px; color:white; }
QPushButton:hover { background:#3d7cef; } QPushButton:disabled { background:#2a2e38; color:#777; }
QTableWidget, QTextEdit, QLineEdit { background:#1b1e25; border:1px solid #262a33; gridline-color:#262a33; }
QHeaderView::section { background:#222632; padding:5px; border:none; }
QProgressBar { border:1px solid #262a33; border-radius:4px; text-align:center; background:#1b1e25; }
QProgressBar::chunk { background:#2d6cdf; }
#card { background:#1b1e25; border:1px solid #262a33; border-radius:8px; }
"""
