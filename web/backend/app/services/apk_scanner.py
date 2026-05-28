"""APK vulnerability scanner service.

Performs static analysis on Android APK files including:
- Manifest analysis
- Permission analysis
- Exported component detection
- Hardcoded secrets detection
- Debuggable mode check
- Network security config analysis
- Certificate information extraction
"""
import os
import re
import zipfile
import logging
import time
import xml.etree.ElementTree as ET
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Dangerous Android permissions
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_CONTACTS": ("medium", "Access to user contacts"),
    "android.permission.WRITE_CONTACTS": ("medium", "Can modify user contacts"),
    "android.permission.READ_CALL_LOG": ("high", "Access to call history"),
    "android.permission.READ_SMS": ("high", "Can read SMS messages"),
    "android.permission.SEND_SMS": ("critical", "Can send SMS messages without user knowledge"),
    "android.permission.RECEIVE_SMS": ("high", "Can intercept SMS messages"),
    "android.permission.CAMERA": ("medium", "Camera access"),
    "android.permission.RECORD_AUDIO": ("high", "Microphone access for recording"),
    "android.permission.ACCESS_FINE_LOCATION": ("high", "Precise GPS location tracking"),
    "android.permission.ACCESS_COARSE_LOCATION": ("medium", "Approximate location tracking"),
    "android.permission.READ_EXTERNAL_STORAGE": ("medium", "Access to files on device"),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("medium", "Can modify files on device"),
    "android.permission.INTERNET": ("low", "Network access"),
    "android.permission.ACCESS_NETWORK_STATE": ("low", "Network state information"),
    "android.permission.INSTALL_PACKAGES": ("critical", "Can install other apps silently"),
    "android.permission.SYSTEM_ALERT_WINDOW": ("high", "Can display overlays on other apps"),
    "android.permission.READ_PHONE_STATE": ("medium", "Access to device identifiers"),
    "android.permission.WRITE_SETTINGS": ("high", "Can modify system settings"),
    "android.permission.RECEIVE_BOOT_COMPLETED": ("medium", "Starts automatically on boot"),
    "android.permission.WAKE_LOCK": ("low", "Can prevent device from sleeping"),
}

# Patterns for hardcoded secrets
SECRET_PATTERNS = {
    "AWS Access Key": r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key": r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key[\s]*[=:]\s*["\']?([A-Za-z0-9/+=]{40})',
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
    "Generic API Key": r'(?i)(api[_\-]?key|apikey|api_secret)[\s]*[=:]\s*["\']?([A-Za-z0-9_\-]{20,})',
    "Private Key": r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----',
    "Generic Secret": r'(?i)(secret|password|passwd|pwd|token)[\s]*[=:]\s*["\']([^"\']{8,})["\']',
    "Hardcoded URL with Credentials": r'https?://[^:]+:[^@]+@[^\s]+',
    "Base64 Encoded Secret": r'(?i)(secret|key|password|token)[\s]*[=:]\s*["\']?(?:[A-Za-z0-9+/]{40,}={0,2})',
}


class APKScanner:
    """Performs static analysis on Android APK files."""

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.findings: List[Dict[str, Any]] = []
        self.manifest_xml: str = ""
        self.permissions: List[str] = []
        self.apk_files: List[str] = []
        self.dex_strings: List[str] = []

    def scan(self) -> Dict[str, Any]:
        """Execute all APK analysis modules and return findings."""
        start_time = time.time()

        if not os.path.exists(self.apk_path):
            return {
                "target": os.path.basename(self.apk_path),
                "error": "APK file not found",
                "vulnerabilities": [],
                "scan_duration": time.time() - start_time,
            }

        try:
            self._extract_apk_info()
            self._analyze_manifest()
            self._analyze_permissions()
            self._check_debuggable()
            self._check_backup_flag()
            self._check_exported_components()
            self._check_network_security()
            self._detect_hardcoded_secrets()
            self._check_certificate()
            self._check_min_sdk()
            self._check_third_party_libs()
        except Exception as e:
            logger.error(f"APK scan error: {e}")
            self._add_finding(
                name="Scan Error",
                severity="info",
                description=f"Some analysis modules could not complete: {str(e)}",
                impact="Partial scan results",
                remediation="Ensure the APK file is valid and not corrupted",
                category="Scanner",
            )

        duration = time.time() - start_time
        return {
            "target": os.path.basename(self.apk_path),
            "vulnerabilities": self.findings,
            "scan_duration": round(duration, 2),
            "permissions": self.permissions,
            "file_count": len(self.apk_files),
        }

    def _add_finding(self, name: str, severity: str, description: str,
                     impact: str, remediation: str, category: str = "APK Analysis",
                     evidence: str = "", cve_id: str = None):
        """Add a vulnerability finding."""
        self.findings.append({
            "name": name,
            "severity": severity,
            "category": category,
            "description": description,
            "impact": impact,
            "remediation": remediation,
            "evidence": evidence,
            "cve_id": cve_id,
        })

    def _extract_apk_info(self):
        """Extract basic APK structure information."""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk:
                self.apk_files = apk.namelist()

                # Extract AndroidManifest.xml (binary XML, attempt text read)
                if "AndroidManifest.xml" in self.apk_files:
                    try:
                        manifest_data = apk.read("AndroidManifest.xml")
                        # Try to decode as text (works for decompiled APKs)
                        self.manifest_xml = manifest_data.decode("utf-8", errors="replace")
                    except Exception:
                        self.manifest_xml = ""

                # Extract strings from DEX files
                for fname in self.apk_files:
                    if fname.endswith(".dex"):
                        try:
                            dex_data = apk.read(fname)
                            # Extract readable strings (ASCII, min 6 chars)
                            strings = re.findall(rb'[\x20-\x7E]{6,}', dex_data)
                            self.dex_strings.extend(s.decode("ascii") for s in strings[:5000])
                        except Exception:
                            pass
        except zipfile.BadZipFile:
            self._add_finding(
                name="Invalid APK File",
                severity="critical",
                description="The uploaded file is not a valid APK (ZIP) archive",
                impact="The file may be corrupted or tampered with",
                remediation="Verify the integrity of the APK file",
                category="File Integrity",
            )

    def _analyze_manifest(self):
        """Analyze the Android Manifest for security issues."""
        if not self.manifest_xml:
            return

        # Check for cleartext traffic
        if "cleartextTrafficPermitted" in self.manifest_xml and "true" in self.manifest_xml:
            self._add_finding(
                name="Cleartext Traffic Allowed",
                severity="high",
                description="Application allows cleartext (unencrypted) HTTP traffic",
                impact="Network communications can be intercepted and read by attackers",
                remediation="Set android:usesCleartextTraffic='false' in the manifest and use HTTPS for all communications",
                category="Network Security",
            )

    def _analyze_permissions(self):
        """Analyze requested permissions for over-privileged access."""
        # Extract permissions from manifest
        perm_pattern = r'uses-permission[^>]*android:name=["\']([^"\']+)'
        self.permissions = re.findall(perm_pattern, self.manifest_xml)

        # Also check DEX strings for permission references
        for s in self.dex_strings:
            if s.startswith("android.permission.") and s not in self.permissions:
                self.permissions.append(s)

        dangerous_found = []
        for perm in self.permissions:
            if perm in DANGEROUS_PERMISSIONS:
                sev, desc = DANGEROUS_PERMISSIONS[perm]
                dangerous_found.append((perm, sev, desc))

        if dangerous_found:
            critical = [p for p in dangerous_found if p[1] == "critical"]
            high = [p for p in dangerous_found if p[1] == "high"]

            if critical:
                self._add_finding(
                    name="Critical Permissions Requested",
                    severity="critical",
                    description=f"App requests {len(critical)} critical permission(s)",
                    impact="These permissions grant the app ability to perform highly sensitive operations",
                    remediation="Review and justify each critical permission; remove unnecessary ones",
                    category="Permissions",
                    evidence="\n".join(f"- {p[0]}: {p[2]}" for p in critical),
                )

            if high:
                self._add_finding(
                    name="High-Risk Permissions Requested",
                    severity="high",
                    description=f"App requests {len(high)} high-risk permission(s)",
                    impact="These permissions can access sensitive user data and device features",
                    remediation="Follow the principle of least privilege; request only necessary permissions",
                    category="Permissions",
                    evidence="\n".join(f"- {p[0]}: {p[2]}" for p in high),
                )

        if len(self.permissions) > 15:
            self._add_finding(
                name="Excessive Permissions",
                severity="medium",
                description=f"App requests {len(self.permissions)} permissions, which is unusually high",
                impact="Over-privileged apps increase the attack surface and risk of data exposure",
                remediation="Review all permissions and remove those not strictly necessary for app functionality",
                category="Permissions",
            )

    def _check_debuggable(self):
        """Check if the app is built in debug mode."""
        if 'android:debuggable="true"' in self.manifest_xml or "debuggable" in " ".join(self.dex_strings[:100]):
            self._add_finding(
                name="Application is Debuggable",
                severity="critical",
                description="The application has the debuggable flag set to true",
                impact="Attackers can attach a debugger, inspect memory, and extract sensitive data at runtime",
                remediation="Set android:debuggable='false' in the release build configuration",
                category="Build Configuration",
            )

    def _check_backup_flag(self):
        """Check if backup is enabled."""
        if 'android:allowBackup="true"' in self.manifest_xml:
            self._add_finding(
                name="Application Data Backup Enabled",
                severity="medium",
                description="App allows data backup via adb, potentially exposing sensitive data",
                impact="An attacker with physical access can extract app data including credentials and tokens",
                remediation="Set android:allowBackup='false' or implement a BackupAgent with proper encryption",
                category="Data Protection",
            )

    def _check_exported_components(self):
        """Check for exported components (activities, services, receivers, providers)."""
        component_types = ["activity", "service", "receiver", "provider"]
        exported = []

        for comp_type in component_types:
            pattern = rf'<{comp_type}[^>]*exported=["\']true["\'][^>]*'
            matches = re.findall(pattern, self.manifest_xml, re.IGNORECASE)
            for match in matches:
                name_match = re.search(r'android:name=["\']([^"\']+)', match)
                name = name_match.group(1) if name_match else "Unknown"
                exported.append(f"{comp_type}: {name}")

        if exported:
            self._add_finding(
                name="Exported Components Found",
                severity="high",
                description=f"Found {len(exported)} exported component(s) accessible to other apps",
                impact="Exported components can be invoked by any app, potentially exposing functionality or data",
                remediation="Review each exported component; set exported='false' unless external access is required",
                category="Component Security",
                evidence="\n".join(f"- {e}" for e in exported[:10]),
            )

    def _check_network_security(self):
        """Check network security configuration."""
        if "network_security_config" not in self.manifest_xml and "network-security-config" not in " ".join(self.apk_files):
            self._add_finding(
                name="Missing Network Security Configuration",
                severity="medium",
                description="No network security configuration file found",
                impact="The app may not properly validate SSL certificates or may allow insecure connections",
                remediation="Add a network_security_config.xml with proper certificate pinning and cleartext restrictions",
                category="Network Security",
            )

    def _detect_hardcoded_secrets(self):
        """Search for hardcoded secrets in DEX strings and resources."""
        all_text = " ".join(self.dex_strings)
        secrets_found = []

        for secret_type, pattern in SECRET_PATTERNS.items():
            matches = re.findall(pattern, all_text)
            if matches:
                # Mask found secrets
                masked = [m[:6] + "..." + m[-4:] if isinstance(m, str) and len(m) > 10 else "***" for m in matches[:3]]
                secrets_found.append((secret_type, masked))

        if secrets_found:
            self._add_finding(
                name="Hardcoded Secrets Detected",
                severity="critical",
                description=f"Found {len(secrets_found)} type(s) of hardcoded secrets in the application",
                impact="Hardcoded credentials and API keys can be extracted by anyone who decompiles the APK",
                remediation="Move all secrets to a secure backend service; use Android Keystore for local credentials",
                category="Secrets Management",
                evidence="\n".join(f"- {s[0]}: {', '.join(s[1])}" for s in secrets_found),
            )

    def _check_certificate(self):
        """Check APK signing certificate information."""
        cert_files = [f for f in self.apk_files if f.startswith("META-INF/") and f.endswith((".RSA", ".DSA", ".EC"))]

        if not cert_files:
            self._add_finding(
                name="Missing Code Signing Certificate",
                severity="high",
                description="No code signing certificate found in the APK",
                impact="The APK cannot be verified for authenticity and integrity",
                remediation="Sign the APK with a valid code signing certificate",
                category="Code Signing",
            )

    def _check_min_sdk(self):
        """Check minimum SDK version for known vulnerabilities."""
        sdk_match = re.search(r'minSdkVersion["\s:=]+(\d+)', self.manifest_xml + " ".join(self.dex_strings[:200]))
        if sdk_match:
            min_sdk = int(sdk_match.group(1))
            if min_sdk < 21:
                self._add_finding(
                    name="Low Minimum SDK Version",
                    severity="medium",
                    description=f"App targets minimum SDK {min_sdk} (Android {self._sdk_to_version(min_sdk)})",
                    impact="Older Android versions have known security vulnerabilities that cannot be patched",
                    remediation="Increase minSdkVersion to at least 21 (Android 5.0 Lollipop) or higher",
                    category="Build Configuration",
                )

    def _check_third_party_libs(self):
        """Identify potentially vulnerable third-party libraries."""
        known_libs = {
            "okhttp": "OkHttp HTTP Client",
            "retrofit": "Retrofit REST Client",
            "gson": "Google Gson JSON",
            "firebase": "Firebase SDK",
            "facebook": "Facebook SDK",
            "crashlytics": "Crashlytics",
            "admob": "Google AdMob",
            "appsflyer": "AppsFlyer Analytics",
            "adjust": "Adjust SDK",
        }

        found_libs = []
        all_files = " ".join(self.apk_files).lower()
        all_strings = " ".join(self.dex_strings[:2000]).lower()

        for lib_id, lib_name in known_libs.items():
            if lib_id in all_files or lib_id in all_strings:
                found_libs.append(lib_name)

        if found_libs:
            self._add_finding(
                name="Third-Party Libraries Detected",
                severity="info",
                description=f"Found {len(found_libs)} third-party library/libraries in the APK",
                impact="Third-party libraries may contain known vulnerabilities if not kept up to date",
                remediation="Regularly update all third-party dependencies and check for known CVEs",
                category="Dependencies",
                evidence="\n".join(f"- {lib}" for lib in found_libs),
            )

    @staticmethod
    def _sdk_to_version(sdk: int) -> str:
        """Convert SDK level to Android version."""
        versions = {
            14: "4.0", 15: "4.0.3", 16: "4.1", 17: "4.2", 18: "4.3",
            19: "4.4", 21: "5.0", 22: "5.1", 23: "6.0", 24: "7.0",
            25: "7.1", 26: "8.0", 27: "8.1", 28: "9.0", 29: "10",
            30: "11", 31: "12", 32: "12L", 33: "13", 34: "14",
        }
        return versions.get(sdk, f"SDK {sdk}")
