import unittest
import os
import sys
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Add app folder to sys path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

TEST_DB_FILE = "test_temp.db"
TEST_DB_URL = f"sqlite:///./{TEST_DB_FILE}"

# Set test environment to use file-based test database
os.environ["DATABASE_URL"] = TEST_DB_URL

from app.config import settings
settings.DATABASE_URL = TEST_DB_URL

import app.database
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Create test engine and sessionmaker
test_engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

# Overrides get_db dependency in FastAPI app
from app.database import get_db, Base
from app.main import app

def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

class TestSecurityPlatform(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Clean existing test database if present
        if os.path.exists(TEST_DB_FILE):
            os.remove(TEST_DB_FILE)

        # Create all tables on the test database
        Base.metadata.create_all(bind=test_engine)
        cls.client = TestClient(app)
        cls.username = "testoperator"
        cls.password = "SecOpsPass123!"
        cls.email = "operator@secops.com"  # Valid domain TLD
        cls.token = ""

    @classmethod
    def tearDownClass(cls):
        # Clean up database file after testing
        if os.path.exists(TEST_DB_FILE):
            try:
                os.remove(TEST_DB_FILE)
            except Exception:
                pass

    def test_01_health(self):
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "healthy")

    def test_02_register(self):
        payload = {
            "email": self.email,
            "username": self.username,
            "password": self.password,
            "full_name": "SOC Lead Engineer"
        }
        response = self.client.post("/api/auth/register", json=payload)
        self.assertEqual(response.status_code, 201)
        data = response.json()
        self.assertIn("access_token", data)
        self.assertIn("user", data)
        self.__class__.token = data["access_token"]

    def test_03_login(self):
        response = self.client.post("/api/auth/login", json={
            "username": self.username,
            "password": self.password
        })
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("access_token", data)

    def test_04_profile(self):
        headers = {"Authorization": f"Bearer {self.token}"}
        response = self.client.get("/api/auth/me", headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["username"], self.username)

    @patch("requests.Session.get")
    def test_05_web_scan(self, mock_get):
        # Setup mock response parameters
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.headers = {
            "Server": "nginx/1.18.0",
            "X-Powered-By": "PHP/7.4.3",
            "Content-Type": "text/html"
        }
        mock_response.text = "<html><head></head><body><h1>Hello Test</h1></body></html>"
        mock_response.cookies = []
        mock_get.return_value = mock_response

        # Perform mock scan request
        headers = {"Authorization": f"Bearer {self.token}"}
        response = self.client.post("/api/scans/web", json={
            "url": "http://localhost:8000",
            "scan_depth": "quick"
        }, headers=headers)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["scan_type"], "web")
        self.assertEqual(data["status"], "completed")
        self.assertIn("security_score", data)

if __name__ == "__main__":
    unittest.main()
