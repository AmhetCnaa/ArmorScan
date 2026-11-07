"""
Unit and Integration Tests for Static AST Route Mapper & Shadow API Auditor.
Verifies parsing of FastAPI, Flask, and Express.js files, parameter extraction,
and detection of unprotected shadow API endpoints lacking auth middleware.
"""

from pathlib import Path
import pytest

from armorscan.core.ast_mapper import AstSourceMapper
from armorscan.core.models import Confidence, Severity


def test_fastapi_ast_route_and_shadow_api_parsing(tmp_path: Path):
    fastapi_code = """
from fastapi import FastAPI, Depends, Header
from typing import Optional

app = FastAPI()

def verify_token():
    pass

@app.get("/api/v1/public-feed")
async def public_feed(limit: int = 10, q: Optional[str] = None):
    return {"feed": []}

@app.get("/api/v1/users/{user_id}", dependencies=[Depends(verify_token)])
async def get_user(user_id: int):
    return {"user_id": user_id}

@app.post("/admin/system/flush-cache")
async def flush_cache(force: bool = False):
    return {"flushed": True}
"""
    app_file = tmp_path / "main.py"
    app_file.write_text(fastapi_code, encoding="utf-8")

    mapper = AstSourceMapper()
    result = mapper.scan_directory(tmp_path)

    assert result.scanned_files_count == 1
    assert len(result.endpoints) == 3

    # 1. Protected endpoint verification
    user_ep = next((ep for ep in result.endpoints if "/users/" in ep.path), None)
    assert user_ep is not None
    assert user_ep.method == "GET"
    assert user_ep.is_protected is True
    assert len(user_ep.auth_mechanisms) > 0

    # 2. Unprotected Shadow API route detection
    assert len(result.unprotected_shadow_routes) == 1
    shadow_ep = result.unprotected_shadow_routes[0]
    assert shadow_ep.path == "/admin/system/flush-cache"
    assert shadow_ep.method == "POST"
    assert shadow_ep.is_protected is False
    assert shadow_ep.parameters[0].name == "force"

    # 3. Finding generation
    findings = mapper.generate_findings(result, base_url="https://app.dev")
    assert len(findings) == 1
    f = findings[0]
    assert f.id == "SHADOW_API_UNPROTECTED_ROUTE"
    assert f.severity == Severity.HIGH
    assert f.confidence == Confidence.CONFIRMED
    assert "flush-cache" in f.title
    assert "CWE-306" in f.cwe_id


def test_express_ast_route_and_shadow_api_parsing(tmp_path: Path):
    express_code = """
const express = require('express');
const router = express.Router();

router.get('/api/orders/:id', authMiddleware, (req, res) => {
    res.json({ id: req.params.id });
});

router.post('/admin/reset-database', (req, res) => {
    res.json({ reset: true });
});
"""
    js_file = tmp_path / "routes.js"
    js_file.write_text(express_code, encoding="utf-8")

    mapper = AstSourceMapper()
    result = mapper.scan_directory(tmp_path)

    assert result.scanned_files_count == 1
    assert len(result.endpoints) == 2

    # Orders is protected
    orders_ep = next((ep for ep in result.endpoints if "/orders/" in ep.path), None)
    assert orders_ep is not None
    assert orders_ep.is_protected is True
    assert orders_ep.parameters[0].name == "id"

    # Admin reset is unprotected shadow API
    assert len(result.unprotected_shadow_routes) == 1
    admin_ep = result.unprotected_shadow_routes[0]
    assert admin_ep.path == "/admin/reset-database"
    assert admin_ep.is_protected is False
