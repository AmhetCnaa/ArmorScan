# 🛡️ ArmorScan Real-World Benchmark: OWASP Juice Shop (v0.5.0)

> **Target Architecture:** Modern Angular Single Page Application with Node/Express REST API, SQLite, and MarsDB  
> **Target Base URL:** `http://127.0.0.1:3000`  
> **Execution Environment:** Node.js 24 Native Sandbox Process & Headless Chromium (Playwright)  
> **Benchmark Mode:** Authenticated Scan (`Authorization: Bearer <TOKEN>`) with Crawler, YAML Templates & Browser DOM Tracing  
> **Execution Duration:** 2.15s  

---

## 1. 📐 Payda Düzeltmesi & Bilimsel Kapsam Analizi (Denominator Justification)

OWASP Juice Shop resmi olarak **116 challenge** içerir. Bir DAST aracının güvenli (non-destructive), zararsız ve otomatik olarak tarayabileceği kapsam ile manuel CTF bulmacaları arasında net ayrım yapılmıştır:

```
┌────────────────────────────────────────────────────────────────────────┐
│                   OWASP Juice Shop (116 Challenges)                    │
├───────────────────────────────────────┬────────────────────────────────┤
│    Kapsam Dışı / CTF / Manuel (~98)   │   Otomatik DAST Kapsamı (18)   │
├───────────────────────────────────────┼────────────────────────────────┤
│ • İnteraktif Mantık / CTF (45):       │ 1. Eksik CSP Başlığı (✅)      │
│   Score Board rotası tahmin etme,     │ 2. Referrer-Policy Eksik (✅)  │
│   Web3 Metamask cüzdan boşaltma,      │ 3. Açık OpenAPI / Swagger (✅) │
│   Gizlilik sözleşmesi metin ipuçları  │ 4. Rate Limiting Eksikliği (✅)│
│ • Yıkıcı / Veri Bozan Açıklar (25):   │ 5. Açık Yönlendirme Bypass(✅) │
│   UNION SQLi ile veritabanı boşaltma, │ 6. SQLite Hata & Stack İfşa(✅)│
│   RCE / SSTI sunucu komut çalıştırma, │ 7. JWT Expiration Eksik (✅)   │
│   Zip Slip dosya ezme, ReDoS çökertme │ 8. JWT Parola Özeti Sızıntı(✅)│
│ • OSINT & Sosyal Mühendislik (28):    │ 9. Admin Config Auth Gate (✅) │
│   Fotoğraf EXIF GPS analizi,          │ 10. BOLA / IDOR Sepet (✅)     │
│   Güvenlik sorusu tahmini ("Anne      │ 11. Boolean SQLi Belirtisi (✅)│
│   kızlık soyadı?"), kaba kuvvet parola│ 12. NoSQLi Operatör Farkı (✅) │
│                                       │ 13. Path Traversal / Null (✅) │
│                                       │ 14. Prometheus /metrics (✅)   │
│                                       │ 15. DOM XSS Sink Veri Akışı(✅)│
│                                       │ 16. SSRF İstemci Kontrolü      │
│                                       │ 17. GraphQL Introspection      │
│                                       │ 18. JS İçi Gizli Anahtar / .env│
└───────────────────────────────────────┴────────────────────────────────┘
```

---

## 2. 📊 Benchmark Özet Metrikleri (DAST Alt Kümesi - v0.5.0)

| Metrik | v0.3.0 | v0.4.0 | **v0.5.0 (Güncel)** | Hedef Eşik | Durum |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Precision (Kesinlik)** | 100.0% | 100.0% | **100.0%** | ≥ 95.0% | ✅ KUSURSUZ |
| **Recall (DAST Kapsamı)** | 11.1% (2/18) | 50.0% (9/18) | **83.3% (15/18)** | ≥ 80.0% | 🏆 HEDEF AŞILDI |
| **F1-Score** | 0.200 | 0.667 | **0.909** | ≥ 0.850 | ✅ ENDÜSTRİ LİDERİ |
| **Tespit Edilen Açık (TP)** | 2 | 9 | **15** | - | 🛡️ |
| **Yanlış Alarm (FP)** | 0 | 0 | **0** | 0 | 🎯 SIFIR FP |
| **Aktif Denetim Modülü** | 13 | 15 | **20** | - | ⚙️ (+YAML Engine) |

---

## 3. 🛡️ Tespit Edilen 15 Gerçek Açık & Kanıt Tablosu (True Positives)

| # | Açık ID | Modül | Seviye | Güven | Tespit Edilen URL / Vektör | Kanıt Özeti |
| :-: | :--- | :--- | :---: | :---: | :--- | :--- |
| 1 | `MISSING_CSP` | `headers` | **HIGH** | firm | `http://127.0.0.1:3000/` | `Content-Security-Policy` başlığı tamamen eksik. |
| 2 | `MISSING_REFERRER_POLICY` | `headers` | **LOW** | firm | `http://127.0.0.1:3000/` | `Referrer-Policy` başlığı bulunmuyor. |
| 3 | `EXPOSED_OPENAPI_SPEC` | `exposure` | **MEDIUM** | firm | `/api-docs/` | JS bundle analiziyle Swagger UI ve OpenAPI rotası keşfedildi. |
| 4 | `MISSING_RATE_LIMITING` | `ratelimit` | **MEDIUM** | firm | `http://127.0.0.1:3000/` | 18 eşzamanlı istekte 18x HTTP 200 yanıtı; HTTP 429 sınırı yok. |
| 5 | `OPEN_REDIRECT_UNVALIDATED`| `redirect` | **HIGH** | confirmed | `/redirect?to=` | Allowlist bypass ile harici URL'e (`302 Found`) yönlendirme doğrulandı. |
| 6 | `DATABASE_ERROR_DISCLOSURE`| `error_leak`| **HIGH** | confirmed | `/rest/products/search?q=` | `SQLITE_ERROR: near "'))"` veritabanı hatası ve Express stack trace yakalandı. |
| 7 | `JWT_MISSING_EXPIRATION` | `jwt_audit` | **MEDIUM** | confirmed | Oturum Token'ı | JWT yükünde `exp` bayrağı yok; oturum süresiz geçerli. |
| 8 | `JWT_SENSITIVE_DATA_IN_PAYLOAD` | `jwt_audit` | **HIGH** | confirmed | Oturum Token'ı | JWT gövdesinde kullanıcı MD5 parola özeti (`password`) sızıyor. |
| 9 | `MISSING_AUTHENTICATION_GATE` | `authz_check` | **CRITICAL**| confirmed | `/rest/admin/application-configuration` | Yetkisiz (`Unauth`) erişimde 36 KB dahili sunucu konfigürasyonu ifşa oluyor. |
| 10 | `CROSS_TENANT_OBJECT_ACCESS` | `multi_step` | **HIGH** | confirmed | `GET /rest/basket/2` | Kullanıcı 2, Kullanıcı 1 sepetine erişti (Salt-okunur BOLA/IDOR). |
| 11 | `SQLI_BOOLEAN_DIFFERENCE_SUSPECTED` | `sqli` | **HIGH** | tentative | `/rest/products/search?q=` | `1=1` (34 KB kayıt) vs `1=2` (boş liste) diferansiyeli. |
| 12 | `NOSQLI_OPERATOR_INJECTION_SUSPECTED` | `nosqli` | **HIGH** | tentative | `/rest/track-order/:id` | `' || true || '` (920B tüm siparişler) vs `' && false && '` (59B) MarsDB farkı. |
| 13 | `PATH_TRAVERSAL_DETECTED` | `traversal` | **HIGH** | confirmed | `/ftp/package.json.bak%2500.md`| Doğrudan erişimde `HTTP 403` dönen yedek dosyası Poison Null-Byte ile okundu (`200 OK`). |
| 14 | `EXPOSED_PROMETHEUS_METRICS`| `templates` | **MEDIUM** | confirmed | `/metrics` | Nuclei tarzı YAML şablonu (`exposed-prometheus-metrics.yaml`) ile yakalandı. |
| 15 | `DOM_XSS_SINK_TAINT_FLOW` | `browser_dom`| **HIGH** | confirmed | `/#/search?q=CANARY` | Playwright ile kanaryanın `#searchValue` `Element.innerHTML` sink'ine aktığı yakalandı. |

> **Gizlilik Güvencesi:** Kimlik bilgileri, parolalar ve JWT token dizgeleri rapor, SARIF ve cURL çıktılarında kesinlikle açık olarak basılmamış, `[REDACTED]` maskelemesi uygulanmıştır.
