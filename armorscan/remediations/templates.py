"""
Remediation template generator for web application security.
Generates copy-paste ready configurations for Nginx, Express.js (Helmet), FastAPI, and Apache.
"""

from __future__ import annotations

from typing import Dict


def get_hsts_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block:\n"
            "add_header Strict-Transport-Security "
            '"max-age=31536000; includeSubDomains; preload" always;'
        ),
        "express": (
            "// Using helmet middleware in Express.js:\n"
            "const helmet = require('helmet');\n"
            "app.use(helmet.hsts({\n"
            "  maxAge: 31536000,\n"
            "  includeSubDomains: true,\n"
            "  preload: true\n"
            "}));"
        ),
        "fastapi": (
            "# In FastAPI using custom middleware:\n"
            "from starlette.middleware.base import BaseHTTPMiddleware\n"
            "from fastapi import FastAPI\n\n"
            "class SecurityHeadersMiddleware(BaseHTTPMiddleware):\n"
            "    async def dispatch(self, request, call_next):\n"
            "        response = await call_next(request)\n"
            '        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"\n'
            "        return response\n\n"
            "app = FastAPI()\n"
            "app.add_middleware(SecurityHeadersMiddleware)"
        ),
    }


def get_csp_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block (adjust directives for your domain assets):\n"
            "add_header Content-Security-Policy "
            '"default-src \'self\'; script-src \'self\'; style-src \'self\'; img-src \'self\' data:; font-src \'self\'; object-src \'none\'; base-uri \'self\'; form-action \'self\';" always;'
        ),
        "express": (
            "// Using helmet in Express.js (tight policy without unsafe-inline):\n"
            "const helmet = require('helmet');\n"
            "app.use(helmet.contentSecurityPolicy({\n"
            "  directives: {\n"
            "    defaultSrc: [\"'self'\"],\n"
            "    scriptSrc: [\"'self'\"],\n"
            "    styleSrc: [\"'self'\"],\n"
            "    imgSrc: [\"'self'\", 'data:'],\n"
            "    objectSrc: [\"'none'\"],\n"
            "    upgradeInsecureRequests: [],\n"
            "  },\n"
            "}));"
        ),
        "fastapi": (
            "# In FastAPI response headers:\n"
            '@app.middleware("http")\n'
            "async def add_csp_header(request, call_next):\n"
            "    response = await call_next(request)\n"
            '    response.headers["Content-Security-Policy"] = (\n'
            '        "default-src \'self\'; script-src \'self\'; object-src \'none\';"\n'
            "    )\n"
            "    return response"
        ),
    }


def get_x_frame_options_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block:\n"
            'add_header X-Frame-Options "DENY" always;\n'
            "# Or use 'SAMEORIGIN' if you intend to frame pages within the same origin."
        ),
        "express": (
            "// Using helmet in Express.js:\n"
            "const helmet = require('helmet');\n"
            "app.use(helmet.frameguard({ action: 'deny' }));"
        ),
        "fastapi": (
            "# In FastAPI middleware:\n"
            '@app.middleware("http")\n'
            "async def add_xfo_header(request, call_next):\n"
            "    response = await call_next(request)\n"
            '    response.headers["X-Frame-Options"] = "DENY"\n'
            "    return response"
        ),
    }


def get_x_content_type_options_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block:\n"
            'add_header X-Content-Type-Options "nosniff" always;'
        ),
        "express": (
            "// Using helmet in Express.js:\n"
            "const helmet = require('helmet');\n"
            "app.use(helmet.noSniff());"
        ),
        "fastapi": (
            "# In FastAPI middleware:\n"
            '@app.middleware("http")\n'
            "async def add_nosniff_header(request, call_next):\n"
            "    response = await call_next(request)\n"
            '    response.headers["X-Content-Type-Options"] = "nosniff"\n'
            "    return response"
        ),
    }


def get_referrer_policy_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block:\n"
            'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
        ),
        "express": (
            "// Using helmet in Express.js:\n"
            "const helmet = require('helmet');\n"
            "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));"
        ),
        "fastapi": (
            "# In FastAPI middleware:\n"
            '@app.middleware("http")\n'
            "async def add_referrer_policy(request, call_next):\n"
            "    response = await call_next(request)\n"
            '    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"\n'
            "    return response"
        ),
    }


def get_permissions_policy_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx server {} block (disables risky browser APIs):\n"
            'add_header Permissions-Policy "camera=(), microphone=(), geolocation=(), payment=()" always;'
        ),
        "express": (
            "// Using custom middleware or helmet in Express.js:\n"
            "app.use((req, res, next) => {\n"
            "  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');\n"
            "  next();\n"
            "});"
        ),
        "fastapi": (
            "# In FastAPI middleware:\n"
            '@app.middleware("http")\n'
            "async def add_permissions_policy(request, call_next):\n"
            "    response = await call_next(request)\n"
            '    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=(), payment=()"\n'
            "    return response"
        ),
    }


def get_server_masking_remediations() -> Dict[str, str]:
    return {
        "nginx": (
            "# In your nginx.conf http {} block:\n"
            "server_tokens off;"
        ),
        "express": (
            "// In Express.js:\n"
            "app.disable('x-powered-by');\n"
            "// Or using helmet:\n"
            "app.use(helmet.hidePoweredBy());"
        ),
        "fastapi": (
            "# In FastAPI/Uvicorn:\n"
            "# Run uvicorn with --no-server-header flag:\n"
            "uvicorn main:app --no-server-header"
        ),
    }


def get_complete_security_middleware() -> Dict[str, str]:
    """Provides a consolidated, all-in-one security configuration."""
    return {
        "nginx": (
            "# ==========================================\n"
            "# Production Security Headers Configuration\n"
            "# ==========================================\n"
            "server_tokens off;\n"
            'add_header X-Frame-Options "DENY" always;\n'
            'add_header X-Content-Type-Options "nosniff" always;\n'
            'add_header Referrer-Policy "strict-origin-when-cross-origin" always;\n'
            'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;\n'
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;\n'
            'add_header Content-Security-Policy "default-src \'self\'; script-src \'self\'; style-src \'self\'; img-src \'self\' data:; font-src \'self\'; object-src \'none\'; base-uri \'self\';" always;'
        ),
        "express": (
            "// ==========================================\n"
            "// Consolidated Helmet Setup in Express.js\n"
            "// ==========================================\n"
            "const express = require('express');\n"
            "const helmet = require('helmet');\n"
            "const app = express();\n\n"
            "app.use(helmet({\n"
            "  contentSecurityPolicy: {\n"
            "    directives: {\n"
            "      defaultSrc: [\"'self'\"],\n"
            "      scriptSrc: [\"'self'\"],\n"
            "      styleSrc: [\"'self'\"],\n"
            "      imgSrc: [\"'self'\", 'data:'],\n"
            "      objectSrc: [\"'none'\"],\n"
            "    },\n"
            "  },\n"
            "  hsts: {\n"
            "    maxAge: 31536000,\n"
            "    includeSubDomains: true,\n"
            "    preload: true,\n"
            "  },\n"
            "  frameguard: { action: 'deny' },\n"
            "  noSniff: true,\n"
            "  referrerPolicy: { policy: 'strict-origin-when-cross-origin' },\n"
            "}));"
        ),
        "fastapi": (
            "# ==========================================\n"
            "# Consolidated Security Headers Middleware for FastAPI\n"
            "# ==========================================\n"
            "from fastapi import FastAPI\n"
            "from starlette.middleware.base import BaseHTTPMiddleware\n\n"
            "class SecurityHeadersMiddleware(BaseHTTPMiddleware):\n"
            "    async def dispatch(self, request, call_next):\n"
            "        response = await call_next(request)\n"
            '        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"\n'
            '        response.headers["X-Frame-Options"] = "DENY"\n'
            '        response.headers["X-Content-Type-Options"] = "nosniff"\n'
            '        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"\n'
            '        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"\n'
            '        response.headers["Content-Security-Policy"] = "default-src \'self\'; script-src \'self\'; object-src \'none\';"\n'
            "        return response\n\n"
            "app = FastAPI()\n"
            "app.add_middleware(SecurityHeadersMiddleware)"
        ),
    }


def get_cookie_hygiene_remediations() -> Dict[str, str]:
    """Generates remediation snippets for secure cookie attributes (HttpOnly, Secure, SameSite)."""
    return {
        "express": (
            "// Express.js with express-session:\n"
            "const session = require('express-session');\n\n"
            "app.use(session({\n"
            "  name: '__Host-session',\n"
            "  secret: process.env.SESSION_SECRET,\n"
            "  resave: false,\n"
            "  saveUninitialized: false,\n"
            "  cookie: {\n"
            "    secure: true,      // Requires HTTPS\n"
            "    httpOnly: true,    // Prevents JavaScript access (XSS mitigation)\n"
            "    sameSite: 'lax',   // CSRF protection ('lax' or 'strict')\n"
            "    path: '/',\n"
            "    maxAge: 3600000    // 1 hour\n"
            "  }\n"
            "}));"
        ),
        "fastapi": (
            "# FastAPI secure cookie response:\n"
            "from fastapi import Response\n\n"
            "@app.post('/api/login')\n"
            "async def login(response: Response):\n"
            "    response.set_cookie(\n"
            "        key='__Host-auth_token',\n"
            "        value=jwt_token,\n"
            "        httponly=True,   # Mitigates XSS cookie theft\n"
            "        secure=True,     # Only sent over HTTPS\n"
            "        samesite='lax',  # Mitigates CSRF\n"
            "        path='/',\n"
            "        max_age=3600\n"
            "    )\n"
            "    return {'status': 'authenticated'}"
        ),
        "django": (
            "# Django settings.py (Production Security Checklist):\n"
            "SESSION_COOKIE_SECURE = True     # Transmit session cookie over HTTPS only\n"
            "SESSION_COOKIE_HTTPONLY = True   # Block document.cookie JS access\n"
            "SESSION_COOKIE_SAMESITE = 'Lax'  # Prevent CSRF\n"
            "CSRF_COOKIE_SECURE = True        # Transmit CSRF cookie over HTTPS only\n"
            "CSRF_COOKIE_HTTPONLY = False     # Set to True if not needed by JS\n"
            "CSRF_COOKIE_SAMESITE = 'Lax'"
        ),
    }


def get_cookie_prefix_remediations() -> Dict[str, str]:
    """Generates remediation guidance for __Host- and __Secure- cookie prefixes."""
    return {
        "express": (
            "// Enforce __Host- prefix in Express.js:\n"
            "// Note: __Host- requires Secure, Path=/, and NO Domain attribute.\n"
            "res.cookie('__Host-session', token, {\n"
            "  secure: true,\n"
            "  httpOnly: true,\n"
            "  sameSite: 'lax',\n"
            "  path: '/'\n"
            "});"
        ),
        "fastapi": (
            "# Enforce __Host- prefix in FastAPI:\n"
            "response.set_cookie(\n"
            "    key='__Host-session',\n"
            "    value=token,\n"
            "    secure=True,\n"
            "    httponly=True,\n"
            "    samesite='lax',\n"
            "    path='/',\n"
            ")"
        ),
        "django": (
            "# Django does not yet native-prefix session cookie names, but you can set:\n"
            "SESSION_COOKIE_NAME = '__Host-session'\n"
            "SESSION_COOKIE_SECURE = True\n"
            "SESSION_COOKIE_PATH = '/'\n"
            "SESSION_COOKIE_DOMAIN = None  # Must NOT specify domain for __Host-"
        ),
    }


def get_dotfile_exposure_remediations() -> Dict[str, str]:
    """Generates remediation rules to block dotfiles (.env, .git) and backup files."""
    return {
        "nginx": (
            "# In your nginx server {} block:\n"
            "# 1. Block access to all hidden files and directories (except .well-known for ACME/SSL)\n"
            "location ~ /\\.(?!well-known) {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}\n\n"
            "# 2. Block access to backup, source, and config extensions\n"
            "location ~* \\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist|env)$ {\n"
            "    deny all;\n"
            "    return 404;\n"
            "}"
        ),
        "apache": (
            "# In your .htaccess or VirtualHost block:\n"
            "# 1. Deny access to dotfiles (.env, .git)\n"
            '<FilesMatch "^\\.">\n'
            "    Require all denied\n"
            "</FilesMatch>\n\n"
            "# 2. Deny access to sensitive files and backups\n"
            '<FilesMatch "\\.(bak|config|sql|ini|log|env)$">\n'
            "    Require all denied\n"
            "</FilesMatch>"
        ),
        "express": (
            "// In Express.js static middleware:\n"
            "// Set dotfiles to 'deny' or 'ignore'\n"
            "const express = require('express');\n"
            "const app = express();\n\n"
            "app.use(express.static('public', {\n"
            "  dotfiles: 'deny',\n"
            "  etag: true,\n"
            "}));"
        ),
    }


def get_openapi_exposure_remediations() -> Dict[str, str]:
    """Guidance on securing or disabling public OpenAPI/Swagger specs in production."""
    return {
        "fastapi": (
            "# Disable Swagger & Redoc in FastAPI production:\n"
            "import os\n"
            "from fastapi import FastAPI\n\n"
            "is_prod = os.getenv('ENV') == 'production'\n"
            "app = FastAPI(\n"
            "    docs_url=None if is_prod else '/docs',\n"
            "    redoc_url=None if is_prod else '/redoc',\n"
            "    openapi_url=None if is_prod else '/openapi.json',\n"
            ")"
        ),
        "express": (
            "// Protect Swagger UI with authentication in Express:\n"
            "const swaggerUi = require('swagger-ui-express');\n"
            "const basicAuth = require('express-basic-auth');\n\n"
            "if (process.env.NODE_ENV === 'production') {\n"
            "  app.use('/api-docs', basicAuth({\n"
            "    users: { 'admin': process.env.DOCS_PASSWORD },\n"
            "    challenge: true,\n"
            "  }), swaggerUi.serve, swaggerUi.setup(swaggerDocument));\n"
            "} else {\n"
            "  app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));\n"
            "}"
        ),
    }


def get_cors_remediations() -> Dict[str, str]:
    """Generates remediation configurations for secure Cross-Origin Resource Sharing (CORS)."""
    return {
        "express": (
            "// Secure CORS configuration in Express.js:\n"
            "const cors = require('cors');\n\n"
            "const whitelist = ['https://yourdomain.com', 'https://app.yourdomain.com'];\n"
            "const corsOptions = {\n"
            "  origin: function (origin, callback) {\n"
            "    // Allow requests with no origin (like mobile apps or curl) or in whitelist\n"
            "    if (!origin || whitelist.indexOf(origin) !== -1) {\n"
            "      callback(null, true);\n"
            "    } else {\n"
            "      callback(new Error('Blocked by CORS policy'));\n"
            "    }\n"
            "  },\n"
            "  credentials: true,\n"
            "  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],\n"
            "  allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],\n"
            "  maxAge: 86400,\n"
            "};\n\n"
            "app.use(cors(corsOptions));"
        ),
        "fastapi": (
            "# Secure CORS configuration in FastAPI:\n"
            "from fastapi import FastAPI\n"
            "from fastapi.middleware.cors import CORSMiddleware\n\n"
            "app = FastAPI()\n\n"
            "origins = [\n"
            "    'https://yourdomain.com',\n"
            "    'https://app.yourdomain.com',\n"
            "]\n\n"
            "app.add_middleware(\n"
            "    CORSMiddleware,\n"
            "    allow_origins=origins,        # Explicit origin whitelist (never use ['*'] with credentials)\n"
            "    allow_credentials=True,\n"
            "    allow_methods=['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],\n"
            "    allow_headers=['Content-Type', 'Authorization'],\n"
            "    max_age=86400,\n"
            ")"
        ),
        "nginx": (
            "# Secure CORS configuration in Nginx:\n"
            "# Whitelist specific trusted origins using map:\n"
            "map $http_origin $cors_origin {\n"
            "    default '';\n"
            "    '~^https://(www\\.)?yourdomain\\.com$' '$http_origin';\n"
            "    '~^https://app\\.yourdomain\\.com$' '$http_origin';\n"
            "}\n\n"
            "server {\n"
            "    # ...\n"
            "    add_header Access-Control-Allow-Origin $cors_origin always;\n"
            "    add_header Access-Control-Allow-Credentials 'true' always;\n"
            "    add_header Access-Control-Allow-Methods 'GET, POST, OPTIONS, PUT, DELETE' always;\n"
            "    add_header Access-Control-Allow-Headers 'DNT,User-Agent,X-Requested-With,If-Modified-Since,Cache-Control,Content-Type,Range,Authorization' always;\n"
            "}"
        ),
    }


def get_method_security_remediations() -> Dict[str, str]:
    """Generates remediation rules to disable TRACE/TRACK and restrict dangerous HTTP verbs."""
    return {
        "nginx": (
            "# Disable TRACE and restrict HTTP methods in Nginx:\n"
            "if ($request_method = TRACE) {\n"
            "    return 405;\n"
            "}\n\n"
            "# Alternatively, allow only approved methods in a location block:\n"
            "location / {\n"
            "    limit_except GET POST OPTIONS HEAD {\n"
            "        deny all;\n"
            "    }\n"
            "}"
        ),
        "apache": (
            "# Disable TRACE method in Apache httpd.conf:\n"
            "TraceEnable Off\n\n"
            "# Restrict methods in .htaccess:\n"
            "<LimitExcept GET POST OPTIONS HEAD>\n"
            "    Require all denied\n"
            "</LimitExcept>"
        ),
        "express": (
            "// Block TRACE / TRACK in Express.js:\n"
            "app.use((req, res, next) => {\n"
            "  if (req.method === 'TRACE' || req.method === 'TRACK') {\n"
            "    return res.status(405).send('Method Not Allowed');\n"
            "  }\n"
            "  next();\n"
            "});"
        ),
    }


def get_rate_limit_remediations() -> Dict[str, str]:
    """Generates remediation configurations for HTTP rate limiting and brute-force mitigation."""
    return {
        "nginx": (
            "# In your nginx.conf http {} block:\n"
            "limit_req_zone $binary_remote_addr zone=api_limit:10m rate=10r/s;\n"
            "limit_req_status 429;\n\n"
            "# In your server {} or location {} block:\n"
            "location /api/ {\n"
            "    limit_req zone=api_limit burst=20 nodelay;\n"
            "    proxy_pass http://backend_upstream;\n"
            "}"
        ),
        "express": (
            "// In Express.js using express-rate-limit:\n"
            "const rateLimit = require('express-rate-limit');\n\n"
            "const apiLimiter = rateLimit({\n"
            "  windowMs: 15 * 60 * 1000, // 15 minutes\n"
            "  max: 100, // Limit each IP to 100 requests per window\n"
            "  standardHeaders: true, // Return RateLimit-* headers\n"
            "  legacyHeaders: false, // Disable X-RateLimit-* headers\n"
            "  message: { error: 'Too many requests, please try again later.' },\n"
            "  statusCode: 429,\n"
            "});\n\n"
            "app.use('/api/', apiLimiter);"
        ),
        "fastapi": (
            "# In FastAPI using slowapi:\n"
            "from fastapi import FastAPI, Request\n"
            "from slowapi import Limiter, _rate_limit_exceeded_handler\n"
            "from slowapi.util import get_remote_address\n"
            "from slowapi.errors import RateLimitExceeded\n\n"
            "limiter = Limiter(key_func=get_remote_address)\n"
            "app = FastAPI()\n"
            "app.state.limiter = limiter\n"
            "app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)\n\n"
            "@app.get('/api/sensitive')\n"
            "@limiter.limit('15/minute')\n"
            "async def sensitive_route(request: Request):\n"
            "    return {'status': 'success'}"
        ),
    }


def get_reflection_remediations() -> Dict[str, str]:
    """Generates context-aware encoding and sanitization remediations for XSS mitigation."""
    return {
        "express": (
            "// 1. In Express templates (EJS/Handlebars/Pug):\n"
            "// Always use auto-escaping syntax: <%= query %> (EJS) or {{ query }} (Handlebars)\n"
            "// Never use raw HTML output: <%- query %> or {{{ query }}}\n\n"
            "// 2. For rich HTML user input, sanitize using DOMPurify / sanitize-html:\n"
            "const sanitizeHtml = require('sanitize-html');\n"
            "const cleanInput = sanitizeHtml(req.query.q, {\n"
            "  allowedTags: ['b', 'i', 'em', 'strong', 'a'],\n"
            "  allowedAttributes: { 'a': ['href'] }\n"
            "});"
        ),
        "fastapi": (
            "# In FastAPI / Jinja2 templates:\n"
            "# 1. Ensure Jinja2 autoescape is enabled (default in FastAPI Starlette Templates):\n"
            "from fastapi.templating import Jinja2Templates\n"
            "templates = Jinja2Templates(directory='templates', autoescape=True)\n\n"
            "# 2. For manual string responses, use html.escape:\n"
            "import html\n"
            "safe_output = html.escape(user_query)"
        ),
        "react": (
            "// In React / Vue frontend:\n"
            "// Native JSX automatically escapes strings: <div>{userInput}</div>\n"
            "// NEVER use dangerouslySetInnerHTML with unsanitized user content:\n"
            "// AVOID: <div dangerouslySetInnerHTML={{ __html: userInput }} />\n"
            "// SAFE: import DOMPurify from 'dompurify';\n"
            "<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(userInput) }} />"
        ),
    }


def get_open_redirect_remediations() -> Dict[str, str]:
    """Generates remediation rules for validating redirect URLs and preventing Open Redirects."""
    return {
        "express": (
            "// Enforce safe redirects in Express.js:\n"
            "const allowedHosts = ['myapp.com', 'auth.myapp.com'];\n\n"
            "app.get('/login', (req, res) => {\n"
            "  const target = req.query.redirect || '/dashboard';\n"
            "  // 1. Only allow relative paths starting with / (disallowing //)\n"
            "  if (target.startsWith('/') && !target.startsWith('//')) {\n"
            "    return res.redirect(target);\n"
            "  }\n"
            "  // 2. Or validate against explicit host whitelist\n"
            "  try {\n"
            "    const parsed = new URL(target, 'https://myapp.com');\n"
            "    if (allowedHosts.includes(parsed.hostname)) {\n"
            "      return res.redirect(target);\n"
            "    }\n"
            "  } catch (e) {}\n"
            "  return res.redirect('/dashboard');\n"
            "});"
        ),
        "fastapi": (
            "# Enforce safe redirects in FastAPI:\n"
            "from urllib.parse import urlparse\n"
            "from fastapi.responses import RedirectResponse\n\n"
            "ALLOWED_DOMAINS = {'myapp.com', 'auth.myapp.com'}\n\n"
            "@app.get('/auth/callback')\n"
            "def auth_callback(next_url: str = '/dashboard'):\n"
            "    # Relative path check\n"
            "    if next_url.startswith('/') and not next_url.startswith('//'):\n"
            "        return RedirectResponse(url=next_url)\n"
            "    # Absolute URL whitelist check\n"
            "    parsed = urlparse(next_url)\n"
            "    if parsed.netloc in ALLOWED_DOMAINS:\n"
            "        return RedirectResponse(url=next_url)\n"
            "    return RedirectResponse(url='/dashboard')"
        ),
    }


def get_error_leak_remediations() -> Dict[str, str]:
    """Generates error masking and generic exception handler templates."""
    return {
        "express": (
            "// Global centralized error handler in Express (place as last app.use):\n"
            "app.use((err, req, res, next) => {\n"
            "  console.error(err.stack); // Log internally\n"
            "  if (process.env.NODE_ENV === 'production') {\n"
            "    res.status(500).json({ error: 'Internal Server Error' });\n"
            "  } else {\n"
            "    res.status(500).json({ error: err.message, stack: err.stack });\n"
            "  }\n"
            "});"
        ),
        "fastapi": (
            "# Global generic exception handler in FastAPI:\n"
            "from fastapi import Request\n"
            "from fastapi.responses import JSONResponse\n\n"
            "@app.exception_handler(Exception)\n"
            "async def generic_exception_handler(request: Request, exc: Exception):\n"
            "    # Log detailed traceback to internal secure logger\n"
            "    logger.exception(f'Unhandled error at {request.url}: {exc}')\n"
            "    # Return opaque message to client\n"
            "    return JSONResponse(\n"
            "        status_code=500,\n"
            "        content={'error': 'An unexpected error occurred. Please contact support.'}\n"
            "    )"
        ),
        "django": (
            "# In Django settings.py for production:\n"
            "DEBUG = False\n"
            "ALLOWED_HOSTS = ['yourdomain.com', 'www.yourdomain.com']\n"
            "# Define custom 500 handler in urls.py:\n"
            "handler500 = 'my_app.views.custom_500'"
        ),
    }


def get_jwt_audit_remediations() -> Dict[str, str]:
    """Generates remediation patterns for secure JSON Web Token lifecycle and algorithm enforcement."""
    return {
        "express": (
            "// Secure JWT signing in Node.js / Express:\n"
            "const jwt = require('jsonwebtoken');\n\n"
            "// 1. Explicitly specify robust asymmetric algorithm (RS256) or strong HMAC (HS256)\n"
            "// 2. Enforce short expiration time (e.g. 15m for access token)\n"
            "const token = jwt.sign(\n"
            "  { sub: user.id, role: user.role }, // Minimal claims, NEVER include passwords/secrets\n"
            "  process.env.JWT_SECRET,\n"
            "  { algorithm: 'HS256', expiresIn: '15m' }\n"
            ");"
        ),
        "fastapi": (
            "# Secure JWT creation in Python / FastAPI:\n"
            "from datetime import datetime, timedelta, timezone\n"
            "from jose import jwt\n\n"
            "SECRET_KEY = os.getenv('JWT_SECRET_KEY')\n"
            "ALGORITHM = 'HS256'\n\n"
            "def create_access_token(data: dict, expires_delta: timedelta = timedelta(minutes=15)):\n"
            "    to_encode = data.copy()\n"
            "    expire = datetime.now(timezone.utc) + expires_delta\n"
            "    to_encode.update({'exp': expire})\n"
            "    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)"
        ),
    }


def get_secret_leak_remediations() -> Dict[str, str]:
    """Generates architecture guidance for keeping credentials off client-side bundles."""
    return {
        "general": (
            "# Environment Variable & API Key Hardening:\n"
            "# 1. Store all secret keys in server-side environment variables (.env / AWS Secrets Manager / Vault).\n"
            "# 2. In Vite / Next.js / Create React App:\n"
            "#    - NEVER prefix secret keys with NEXT_PUBLIC_ or VITE_.\n"
            "#    - Only public IDs (like Google Analytics tracking ID) belong in client bundles.\n"
            "# 3. Route third-party API calls (OpenAI, Stripe, AWS) through a backend proxy endpoint:\n"
            "#    Client (Browser) -> Your Backend API -> Third-Party Service (with hidden API Key)"
        ),
    }


def get_authz_remediations() -> Dict[str, str]:
    """Generates remediation patterns for missing authentication gates and BOLA/IDOR protection."""
    return {
        "fastapi": (
            "# Enforce mandatory authentication dependency in FastAPI:\n"
            "from fastapi import Depends, HTTPException, status\n"
            "from fastapi.security import OAuth2PasswordBearer\n\n"
            "oauth2_scheme = OAuth2PasswordBearer(tokenUrl='/api/login')\n\n"
            "async def get_current_user(token: str = Depends(oauth2_scheme)):\n"
            "    user = verify_token(token)\n"
            "    if not user:\n"
            "        raise HTTPException(\n"
            "            status_code=status.HTTP_401_UNAUTHORIZED,\n"
            "            detail='Authentication credentials required',\n"
            "            headers={'WWW-Authenticate': 'Bearer'},\n"
            "        )\n"
            "    return user\n\n"
            "@app.get('/api/user/profile')\n"
            "async def get_profile(current_user: User = Depends(get_current_user)):\n"
            "    return {'id': current_user.id, 'username': current_user.username}"
        ),
        "express": (
            "// Enforce authentication guard middleware in Express.js:\n"
            "const jwt = require('jsonwebtoken');\n\n"
            "function authenticateToken(req, res, next) {\n"
            "  const authHeader = req.headers['authorization'];\n"
            "  const token = authHeader && authHeader.split(' ')[1];\n"
            "  if (!token) {\n"
            "    return res.status(401).json({ error: 'Access token required' });\n"
            "  }\n"
            "  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {\n"
            "    if (err) return res.status(403).json({ error: 'Invalid or expired token' });\n"
            "    req.user = user;\n"
            "    next();\n"
            "  });\n"
            "}\n\n"
            "// Apply to protected routes:\n"
            "app.use('/api/user', authenticateToken);"
        ),
        "nginx": (
            "# Enforce auth_request subrequest verification in Nginx:\n"
            "location /api/private/ {\n"
            "    auth_request /auth/verify;\n"
            "    error_page 401 = @unauthorized;\n"
            "    proxy_pass http://backend_upstream;\n"
            "}\n\n"
            "location = /auth/verify {\n"
            "    internal;\n"
            "    proxy_pass http://auth_service/verify;\n"
            "    proxy_pass_request_body off;\n"
            "    proxy_set_header Content-Length '';\n"
            "}"
        ),
    }





