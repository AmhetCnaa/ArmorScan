"""
Unit tests for Patch Exporter (patch_exporter.py).
"""

from pathlib import Path
import pytest

from armorscan.remediations.patch_exporter import PatchExporter


def test_export_nginx_patch(tmp_path):
    target_file = tmp_path / "security-headers.conf"
    out_path = PatchExporter.export("nginx", str(target_file))

    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")
    assert "Strict-Transport-Security" in content
    assert "Content-Security-Policy" in content
    assert "server_tokens off" in content
    assert "location ~ /\\.(?!well-known)" in content


def test_export_express_patch(tmp_path):
    target_file = tmp_path / "securityMiddleware.js"
    out_path = PatchExporter.export("express", str(target_file))

    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")
    assert "helmet" in content
    assert "rateLimit" in content
    assert "TRACE" in content


def test_export_fastapi_patch(tmp_path):
    target_file = tmp_path / "security_middleware.py"
    out_path = PatchExporter.export("fastapi", str(target_file))

    assert out_path.exists()
    content = out_path.read_text(encoding="utf-8")
    assert "SecurityHeadersMiddleware" in content
    assert "Strict-Transport-Security" in content
    assert "Content-Security-Policy" in content


def test_export_invalid_framework():
    with pytest.raises(ValueError) as excinfo:
        PatchExporter.export("ruby_rails")
    assert "Unsupported framework" in str(excinfo.value)
