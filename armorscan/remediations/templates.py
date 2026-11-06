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



