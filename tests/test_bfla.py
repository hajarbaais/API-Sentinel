"""
Test cible du detecteur BFLA (api_sentinel.detectors.bfla) - regression
corrigee suite a une revue de code : evidence_store.record() retourne
un Evidence avec un test_id genere, mais sa valeur etait ignoree et
"" etait code en dur sur le Finding, rendant la preuve introuvable
depuis le rapport (SARIF/HTML/JSON) malgre son enregistrement correct
dans evidence_store.jsonl.
"""

from types import SimpleNamespace

from api_sentinel.detectors.bfla import BFLADetector


class _FakeEvidenceStore:
    def __init__(self, test_id: str):
        self._test_id = test_id

    def record(self, **kwargs):
        return SimpleNamespace(test_id=self._test_id)


def test_confirmed_finding_carries_the_real_evidence_test_id(monkeypatch):
    detector = BFLADetector.__new__(BFLADetector)
    detector.evidence_store = _FakeEvidenceStore("bfla-00042")
    detector.findings = []
    detector.request_timeout = 5

    fake_account = SimpleNamespace(base_url="http://localhost:8888", auth_headers=lambda: {})
    detector.session_manager = SimpleNamespace(get_account=lambda role: fake_account)
    detector._send_request = lambda path, method, role: (200, {"ok": True})

    detector._test_attacker("/admin/users", "GET", "attacker_lower_level", "admin")

    assert len(detector.findings) == 1
    assert detector.findings[0].evidence_test_id == "bfla-00042"
