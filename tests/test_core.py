import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

import tripflare as core  # noqa: E402


class _FakeHTTPResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode("utf-8")

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


class TripFlareCoreTests(unittest.TestCase):
    def test_random_name_and_scoring_filters(self):
        self.assertIsNone(core.RANDOM_RE.match("中文应用日志导出_v2"))
        self.assertIsNone(core.RANDOM_RE.match("WindowsTerminalUpdate"))
        self.assertIsNotNone(core.RANDOM_RE.match("X7K9Q2ZM"))

        temp_dir = os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp")
        dl_dir = os.path.join(os.path.expanduser("~"), "Downloads")
        guid = "96B14529-00A1-4CEB-A7EE-FB900BEF9820"
        ms_signer = "CN=Microsoft Windows, O=Microsoft Corporation, L=Redmond, S=Washington, C=US"

        dism_dll = os.path.join(temp_dir, guid, "DismProv.dll")
        lolbin_fake = os.path.join(dl_dir, "Invoice_2026.exe")
        sig_map = {
            dism_dll: ("Valid", ms_signer, "DismProv.dll.mui"),
            lolbin_fake: ("Valid", ms_signer, "CertUtil.exe.mui"),
        }

        cfg = dict(core.DEFAULT_CONFIG)
        cfg["system_noise_filter"] = True

        with mock.patch.object(core, "batch_sign", side_effect=lambda paths, timeout=300: {
            p: sig_map[p] for p in paths if p in sig_map
        }):
            with mock.patch("os.path.exists", side_effect=lambda p: p in sig_map):
                suppressed = [{"type": "file_new", "path": dism_dll, "persistence": False, "needs_sig": True, "hidden": False}]
                core.finalize_scores(suppressed, cfg)
                self.assertEqual(suppressed, [])

                masquerade = [{"type": "file_new", "path": lolbin_fake, "persistence": False, "needs_sig": True, "hidden": False}]
                core.finalize_scores(masquerade, cfg)
                self.assertEqual(len(masquerade), 1)
                self.assertGreaterEqual(masquerade[0]["score"], 7)

    def test_lolbin_masquerade_detection(self):
        self.assertEqual(core.check_original_filename(r"C:\Windows\System32\certutil.exe", "CertUtil.exe.mui"), "match")
        self.assertEqual(core.check_original_filename(r"C:\Users\Alex\Downloads\Invoice_2026.exe", "CertUtil.exe.mui"), "mismatch")
        self.assertEqual(core.check_original_filename(r"C:\Users\Alex\AppData\Local\Temp\evil.dll", "vcruntime140.dll"), "mismatch")

    def test_allowlist_matching_and_verdict_regex(self):
        cfg = {
            "allowlist": {
                "paths": [r"c:\trusted\tool.exe", r"c:\approved_tools", "safe_cli.exe"],
                "signers": ["Trusted Corp"],
            }
        }
        self.assertTrue(core.alert_matches_allowlist({"path": r"C:\Trusted\Tool.exe"}, cfg))
        self.assertTrue(core.alert_matches_allowlist({"path": r"C:\Approved_Tools\helper.exe"}, cfg))
        self.assertTrue(core.alert_matches_allowlist({"path": r"D:\Random\safe_cli.exe"}, cfg))
        self.assertTrue(
            core.alert_matches_allowlist(
                {"path": r"C:\Temp\app.exe", "sig_status": "Valid", "signer": "CN=Trusted Corp, O=Example"},
                cfg,
            )
        )
        self.assertFalse(core.alert_matches_allowlist({"path": r"C:\Temp\evil.exe"}, cfg))

        self.assertIsNotNone(core.HIGH_VERDICT_RE.search("**Verdict**: HIGH"))
        self.assertIsNotNone(core.HIGH_VERDICT_RE.search("裁决：高危"))
        self.assertIsNone(core.HIGH_VERDICT_RE.search("裁决：安全，无需处置，并非高危"))

    def test_language_resolution_and_prompt_override(self):
        self.assertEqual(core.resolve_language({"language": "en"}), "en")
        self.assertEqual(core.resolve_language({"language": "zh"}), "zh")
        self.assertIn(core.resolve_language({"language": "auto"}), ("zh", "en"))

        prompt_en = core.build_review_prompt(
            [{"ts": "2026-11-18T00:00:00Z", "type": "file_new", "level": "HIGH", "score": 9, "path": r"C:\Temp\a.exe"}],
            cfg={"language": "en"},
            lang="en",
        )
        self.assertIn("English", prompt_en)

    def test_ai_provider_precedence_and_mocked_http(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("TRIPFLARE_API_KEY", None)
            os.environ.pop("OPENAI_API_KEY", None)
            with mock.patch.object(core, "detect_backend", return_value=None):
                with mock.patch.object(core, "probe_ollama", return_value=["qwen2.5:7b"]):
                    self.assertEqual(core.resolve_ai_provider({"ai": {"provider": "auto"}}), "ollama")
                    self.assertEqual(
                        core.resolve_ai_provider({"ai": {"provider": "auto", "api_key": "sk-test"}}),
                        "openai",
                    )

            with mock.patch.object(core, "detect_backend", return_value=r"C:\Tools\kimi.exe"):
                with mock.patch.object(core, "probe_ollama", return_value=["qwen2.5:7b"]):
                    self.assertEqual(core.resolve_ai_provider({"ai": {"provider": "auto"}}), "cli")

        seen_requests = []

        def fake_urlopen(req, timeout=0):
            seen_requests.append(req)
            url = req.full_url
            if "/api/chat" in url:
                return _FakeHTTPResponse({"message": {"content": "VERDICT: BENIGN\nEVIDENCE: Test"}})
            if "/chat/completions" in url:
                return _FakeHTTPResponse({"choices": [{"message": {"content": "VERDICT: SUSPICIOUS"}}]})
            raise AssertionError(f"Unexpected URL: {url}")

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            with mock.patch.object(core, "probe_ollama", return_value=["llama3.1:8b"]):
                text, err = core.call_ai({"ai": {"provider": "ollama"}}, "analyze this")
                self.assertIsNone(err)
                self.assertIn("BENIGN", text)

            text2, err2 = core.call_ai(
                {
                    "ai": {
                        "provider": "openai",
                        "api_base": "https://api.example.invalid/v1",
                        "api_key": "sk-mock-secret",
                        "model": "gpt-4o-mini",
                    }
                },
                "analyze this",
            )
            self.assertIsNone(err2)
            self.assertIn("SUSPICIOUS", text2)
            auth_headers = [r.get_header("Authorization") for r in seen_requests if "/chat/completions" in r.full_url]
            self.assertEqual(auth_headers, ["Bearer sk-mock-secret"])

    def test_realtime_directory_watcher_detects_new_executable(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            real_tmp = os.path.realpath(tmpdir)
            watcher = core.RealtimeDirectoryWatcher(
                [(real_tmp, 2, True)],
                exclusions=[],
                use_filter=False,
            )
            watcher.start()
            try:
                time.sleep(0.25)
                sample = os.path.join(real_tmp, "dropper_test.exe")
                with open(sample, "wb") as fh:
                    fh.write(b"MZ" + b"\x00" * 64)
                deadline = time.monotonic() + 3.0
                captured = []
                while time.monotonic() < deadline:
                    if watcher.has_pending():
                        captured.extend(watcher.pop_pending())
                        if any(os.path.normcase(os.path.realpath(p)) == os.path.normcase(sample) for p in captured):
                            break
                    time.sleep(0.08)
                self.assertTrue(
                    any(os.path.normcase(os.path.realpath(p)) == os.path.normcase(sample) for p in captured),
                    f"Expected {sample} in realtime events, got {captured}",
                )
            finally:
                watcher.stop()


if __name__ == "__main__":
    unittest.main()
