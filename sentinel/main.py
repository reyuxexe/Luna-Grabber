import sys

from sentinel.core.logging_setup import setup_logging


def main() -> int:
    log = setup_logging()
    try:
        from PySide6.QtWidgets import QApplication
        from sentinel.gui.main_window import MainWindow
        from sentinel.gui.theme import QSS
    except ImportError as exc:
        log.error("Missing dependency: %s", exc)
        return 1
    app = QApplication(sys.argv)
    app.setStyleSheet(QSS)
    w = MainWindow()
    w.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
