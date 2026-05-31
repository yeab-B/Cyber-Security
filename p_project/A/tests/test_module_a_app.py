from pathlib import Path
import importlib.util
import sqlite3

import pytest


def load_module():
    module_path = Path(__file__).resolve().parents[1] / "app.py"
    spec = importlib.util.spec_from_file_location("module_a_app", module_path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    templates_path = module_path.parent / "templates"
    module.app.template_folder = str(templates_path)
    module.app.jinja_loader.searchpath = [str(templates_path)]
    return module


@pytest.fixture()
def module_a(tmp_path, monkeypatch):
    module = load_module()
    db_path = tmp_path / "test_a.db"
    monkeypatch.setattr(module, "DB_PATH", str(db_path))
    module.app.config["TESTING"] = True
    module.init_db()
    return module


def test_register_login_attacker_flow(module_a):
    client = module_a.app.test_client()

    response = client.post(
        "/register",
        data={"username": "alice", "password": "Password123!", "method": "plain"},
        follow_redirects=True,
    )
    text = response.get_data(as_text=True)
    assert "registered using" in text
    assert "plain" in text

    response = client.post(
        "/login",
        data={"username": "alice", "password": "Password123!"},
        follow_redirects=True,
    )
    assert "Login successful for alice" in response.get_data(as_text=True)

    response = client.get("/attacker")
    assert "Readable immediately: Password123!" in response.get_data(as_text=True)


def test_register_rejects_invalid_storage_method(module_a):
    client = module_a.app.test_client()
    response = client.post(
        "/register",
        data={"username": "bob", "password": "secret", "method": "invalid"},
        follow_redirects=True,
    )
    assert "Invalid storage method selected." in response.get_data(as_text=True)


def test_login_fails_for_wrong_password_with_hashed_storage(module_a):
    client = module_a.app.test_client()
    client.post(
        "/register",
        data={"username": "charlie", "password": "safe-pass", "method": "hashed"},
        follow_redirects=True,
    )
    response = client.post(
        "/login",
        data={"username": "charlie", "password": "wrong-pass"},
        follow_redirects=True,
    )
    assert "Login failed: incorrect password." in response.get_data(as_text=True)


def test_encrypted_password_invalid_token_is_handled(module_a):
    client = module_a.app.test_client()
    client.post(
        "/register",
        data={"username": "dina", "password": "enc-pass", "method": "encrypted"},
        follow_redirects=True,
    )

    with sqlite3.connect(module_a.DB_PATH) as conn:
        conn.execute(
            "UPDATE users SET password_value = ? WHERE username = ?",
            ("broken-token", "dina"),
        )
        conn.commit()

    response = client.post(
        "/login",
        data={"username": "dina", "password": "enc-pass"},
        follow_redirects=True,
    )
    assert "Login failed: incorrect password." in response.get_data(as_text=True)
