from pathlib import Path
import importlib.util


def load_module():
    module_path = Path(__file__).resolve().parents[1] / "app.py"
    spec = importlib.util.spec_from_file_location("module_b_app", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    templates_path = module_path.parent / "templates"
    module.app.template_folder = str(templates_path)
    module.app.jinja_loader.searchpath = [str(templates_path)]
    return module


class DummyResponse:
    def __init__(self, status_code=200, text="", headers=None):
        self.status_code = status_code
        self.text = text
        self.headers = headers or {}


def test_is_allowed_target_and_normalize_url():
    module_b = load_module()
    assert module_b.is_allowed_target("http://localhost:5000")
    assert not module_b.is_allowed_target("http://example.com")
    assert module_b.normalize_url("localhost:5000") == "http://localhost:5000/"


def test_index_page_renders_form():
    module_b = load_module()
    module_b.app.config["TESTING"] = True
    client = module_b.app.test_client()
    response = client.get("/")
    body = response.get_data(as_text=True)
    assert "Start Scan" in body
    assert "name=\"target_url\"" in body


def test_scan_rejects_non_lab_target():
    module_b = load_module()
    module_b.app.config["TESTING"] = True
    client = module_b.app.test_client()
    response = client.post("/scan", data={"target_url": "https://example.com"}, follow_redirects=True)
    assert "Only localhost or lab-like targets are allowed for ethical testing." in response.get_data(
        as_text=True
    )


def test_scan_handles_unreachable_allowed_target(monkeypatch):
    module_b = load_module()
    module_b.app.config["TESTING"] = True
    monkeypatch.setattr(module_b, "fetch_url", lambda _: None)
    client = module_b.app.test_client()
    response = client.post("/scan", data={"target_url": "http://localhost:5001"}, follow_redirects=True)
    assert "Target could not be reached." in response.get_data(as_text=True)


def test_scan_success_renders_results_and_report(monkeypatch):
    module_b = load_module()
    module_b.app.config["TESTING"] = True

    def fake_fetch_url(url):
        if "scanner-test-trigger-404" in url:
            return DummyResponse(status_code=404, text="Not Found")
        return DummyResponse(status_code=200, text="safe body", headers={"X-Frame-Options": "DENY"})

    monkeypatch.setattr(module_b, "fetch_url", fake_fetch_url)
    monkeypatch.setattr(
        module_b,
        "check_directory_listing",
        lambda _: {"name": "Directory Listing", "secure": True, "status": "✓ Secure", "details": ["ok"]},
    )
    monkeypatch.setattr(
        module_b,
        "check_sensitive_files",
        lambda _: {
            "name": "Sensitive File Exposure",
            "secure": False,
            "status": "✗ Vulnerable",
            "details": ["demo finding"],
        },
    )
    monkeypatch.setattr(
        module_b,
        "check_security_headers",
        lambda _: {"name": "HTTP Security Headers", "secure": True, "status": "✓ Secure", "details": ["ok"]},
    )
    monkeypatch.setattr(
        module_b,
        "check_debug_exposure",
        lambda *_: {"name": "Debug/Error Information Leakage", "secure": True, "status": "✓ Secure", "details": ["ok"]},
    )
    monkeypatch.setattr(module_b, "build_report_summary", lambda *_: "summary text")

    client = module_b.app.test_client()
    response = client.post("/scan", data={"target_url": "http://localhost:5001"}, follow_redirects=True)
    body = response.get_data(as_text=True)
    assert "Security Scan Report" in body
    assert "Sensitive File Exposure" in body
    assert "summary text" in body
