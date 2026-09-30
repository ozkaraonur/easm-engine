from pathlib import Path

from pytest import MonkeyPatch
from streamlit.testing.v1 import AppTest

from easm.core.config import Settings
from easm.core.models import ScanResult
from easm.web import logic
from tests.web.test_logic import _finding, _result

APP = str(Path(__file__).parents[2] / "easm" / "web" / "app.py")


def test_demo_button_and_scan(monkeypatch: MonkeyPatch) -> None:
    async def fake(
        domain: str, options: logic.ScanOptions, settings: Settings, progress: object = None
    ) -> ScanResult:
        return _result(_finding())

    monkeypatch.setattr(logic, "run_scan", fake)
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.button[0].click().run()  # Demo Hedef Yükle
    assert at.text_input[0].value == logic.DEMO_DOMAIN
    at.button[1].click().run()  # Taramayı Başlat
    assert not at.exception
    assert [m.label for m in at.metric] == ["Assets", "Active", "Open ports", "Risk score"]
    assert at.error[0].value == "Sensitive file exposure detected!"


def test_invalid_domain_shows_error() -> None:
    at = AppTest.from_file(APP, default_timeout=30).run()
    at.text_input[0].set_value("not a domain").run()
    at.button[1].click().run()
    assert at.error and "Invalid domain" in at.error[0].value
