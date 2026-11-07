# 🛡️ ArmorScan Ground Truth Benchmark Report

> **Execution Date:** 2026-11-07 19:59:57 UTC  
> **Target Base URL:** `http://127.0.0.1:8888`  
> **Total Evaluated Endpoints:** 24  

## 📊 Module Accuracy & Verification Metrics

| Module | True Positives (TP) | False Positives (FP) | False Negatives (FN) | Precision | Recall | F1-Score | Status |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `authz_check` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `cookies` | 3 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `cors` | 2 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `error_leak` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `exposure` | 2 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `graphql` | 0 | 0 | 0 | - | - | - | N/A |
| `headers` | 6 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `jwt_audit` | 3 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `multi_step` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `nosqli` | 0 | 0 | 0 | - | - | - | N/A |
| `ratelimit` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `redirect` | 1 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `reflection` | 2 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `secret_leak` | 5 | 0 | 0 | 100.0% | 100.0% | 1.000 | ✅ PASS |
| `sqli` | 0 | 0 | 0 | - | - | - | N/A |
| `ssrf_check` | 0 | 0 | 0 | - | - | - | N/A |
| `templates` | 0 | 0 | 0 | - | - | - | N/A |
| `tls` | 0 | 0 | 0 | - | - | - | N/A |
| `traversal` | 0 | 0 | 0 | - | - | - | N/A |
| **OVERALL** | **28** | **0** | **0** | **100.0%** | **100.0%** | **1.000** | **✅ PASS** |

## 🔍 Endpoint Test Case Breakdown

| Test Case ID | Module | Endpoint Path | Type | Expected | Found | Result |
| :--- | :--- | :--- | :---: | :--- | :--- | :---: |
| `reflection_vulnerable` | `reflection` | `/vuln/reflect?q=test` | Vulnerable | `SCRIPT_CONTEXT_INPUT_REFLECTION`, `UNENCODED_HTML_INPUT_REFLECTION` | `SCRIPT_CONTEXT_INPUT_REFLECTION`, `ATTRIBUTE_CONTEXT_INPUT_REFLECTION`, `UNENCODED_HTML_INPUT_REFLECTION` | ✅ OK |
| `reflection_safe` | `reflection` | `/safe/reflect?q=test` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
| `redirect_vulnerable` | `redirect` | `/vuln/redirect?next=/dashboard` | Vulnerable | `OPEN_REDIRECT_UNVALIDATED` | `OPEN_REDIRECT_UNVALIDATED` | ✅ OK |
| `redirect_safe` | `redirect` | `/safe/redirect?next=/dashboard` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
| `error_leak_vulnerable` | `error_leak` | `/vuln/error?id=1` | Vulnerable | `DATABASE_ERROR_DISCLOSURE` | `DATABASE_ERROR_DISCLOSURE` | ✅ OK |
| `error_leak_safe` | `error_leak` | `/safe/error?id=1` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
| `jwt_audit_vulnerable` | `jwt_audit` | `/vuln/jwt` | Vulnerable | `JWT_INSECURE_ALGORITHM_NONE`, `JWT_MISSING_EXPIRATION`, `JWT_SENSITIVE_DATA_IN_PAYLOAD` | `JWT_INSECURE_ALGORITHM_NONE`, `JWT_MISSING_EXPIRATION`, `JWT_SENSITIVE_DATA_IN_PAYLOAD` | ✅ OK |
| `jwt_audit_safe` | `jwt_audit` | `/safe/jwt` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
| `secret_leak_vulnerable` | `secret_leak` | `/vuln/secrets` | Vulnerable | `OPENAI_API_KEY_LEAK`, `AWS_ACCESS_KEY_LEAK`, `STRIPE_SECRET_KEY_LEAK`, `SLACK_WEBHOOK_LEAK`, `INTERNAL_IP_DISCLOSURE` | `OPENAI_API_KEY_LEAK`, `AWS_ACCESS_KEY_LEAK`, `STRIPE_SECRET_KEY_LEAK`, `SLACK_WEBHOOK_LEAK`, `INTERNAL_IP_DISCLOSURE` | ✅ OK |
| `secret_leak_safe` | `secret_leak` | `/safe/secrets` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
| `headers_vulnerable` | `headers` | `/vuln/headers` | Vulnerable | `MISSING_CSP`, `MISSING_X_FRAME_OPTIONS`, `MISSING_X_CONTENT_TYPE_OPTIONS`, `MISSING_REFERRER_POLICY`, `MISSING_PERMISSIONS_POLICY`, `SERVER_VERSION_DISCLOSURE` | `MISSING_CSP`, `MISSING_X_FRAME_OPTIONS`, `MISSING_X_CONTENT_TYPE_OPTIONS`, `MISSING_REFERRER_POLICY`, `MISSING_PERMISSIONS_POLICY`, `SERVER_VERSION_DISCLOSURE` | ✅ OK |
| `headers_safe` | `headers` | `/safe/headers` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
| `cookies_vulnerable` | `cookies` | `/vuln/cookies` | Vulnerable | `COOKIE_MISSING_HTTPONLY_SESSION`, `COOKIE_MISSING_SECURE_SESSION`, `COOKIE_MISSING_SAMESITE` | `COOKIE_MISSING_HTTPONLY_SESSION`, `COOKIE_MISSING_SECURE_SESSION`, `COOKIE_MISSING_SAMESITE` | ✅ OK |
| `cookies_safe` | `cookies` | `/safe/cookies` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
| `cors_vulnerable` | `cors` | `/vuln/cors` | Vulnerable | `CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS`, `HTTP_TRACE_METHOD_ENABLED` | `CORS_ARBITRARY_ORIGIN_WITH_CREDENTIALS`, `CORS_TRUST_NULL_ORIGIN_CREDENTIALS`, `CORS_REGEX_BYPASS_ORIGIN`, `CORS_REGEX_BYPASS_ORIGIN`, `HTTP_TRACE_METHOD_ENABLED` | ✅ OK |
| `cors_safe` | `cors` | `/safe/cors` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
| `ratelimit_vulnerable` | `ratelimit` | `/vuln/ratelimit` | Vulnerable | `MISSING_RATE_LIMITING` | `MISSING_RATE_LIMITING` | ✅ OK |
| `ratelimit_safe` | `ratelimit` | `/safe/ratelimit` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
| `exposure_vulnerable` | `exposure` | `/vuln/exposure` | Vulnerable | `EXPOSED_ENV_FILE`, `EXPOSED_GIT_REPOSITORY` | `EXPOSED_ENV_FILE`, `EXPOSED_GIT_REPOSITORY` | ✅ OK |
| `exposure_safe` | `exposure` | `/safe/exposure` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
| `authz_check_vulnerable` | `authz_check` | `/vuln/idor` | Vulnerable | `MISSING_AUTHENTICATION_GATE` | `MISSING_AUTHENTICATION_GATE` | ✅ OK |
| `authz_check_safe` | `authz_check` | `/safe/idor` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
| `multi_step_vulnerable` | `multi_step` | `/vuln/logic_idor?user_id=usr_alice` | Vulnerable | `CROSS_TENANT_OBJECT_ACCESS` | `CROSS_TENANT_OBJECT_ACCESS` | ✅ OK |
| `multi_step_safe` | `multi_step` | `/safe/logic_idor?user_id=usr_alice` | Safe (Clean) | *(None)* | *(None)* | ✅ OK |
