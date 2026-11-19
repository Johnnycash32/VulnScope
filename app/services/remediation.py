from __future__ import annotations

from typing import Any


def _entry(
    advice: str,
    python: str | None = None,
    node: str | None = None,
    php: str | None = None,
) -> dict[str, Any]:
    code: dict[str, str] = {}
    if python:
        code["python"] = python
    if node:
        code["node"] = node
    if php:
        code["php"] = php
    return {"advice": advice, "code": code}


REMEDIATION_KB: dict[str, dict[str, Any]] = {
    "Cross Site Scripting (Reflected)": _entry(
        advice=(
            "Validate and sanitize all user input. Encode output contextually "
            "(HTML, JS, CSS, URL) before rendering it in the page."
        ),
        python=(
            "from markupsafe import escape\n"
            "return escape(user_input)\n"
        ),
        node=(
            "const escapeHtml = require('escape-html');\n"
            "res.send(escapeHtml(userInput));\n"
        ),
        php=(
            "echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');\n"
        ),
    ),
    "Cross Site Scripting (Persistent)": _entry(
        advice=(
            "Sanitize input on storage and encode output on retrieval. Use a "
            "templating engine with auto-escaping enabled."
        ),
        python=(
            "# Jinja2 auto-escapes by default\n"
            "render_template('page.html', comment=user_comment)\n"
        ),
        node=(
            "// Use an auto-escaping template engine such as EJS or Pug\n"
            "res.render('page', { comment: userComment });\n"
        ),
        php=(
            "echo htmlspecialchars($comment, ENT_QUOTES | ENT_HTML5, 'UTF-8');\n"
        ),
    ),
    "Cross Site Scripting (DOM)": _entry(
        advice=(
            "Avoid inserting untrusted data into the DOM via innerHTML. Use "
            "textContent or a safe DOM API instead."
        ),
        node=(
            "element.textContent = userInput;  // not innerHTML\n"
        ),
    ),
    "SQL Injection": _entry(
        advice=(
            "Use parameterized queries / prepared statements. Never concatenate "
            "user input into SQL strings."
        ),
        python=(
            "cursor.execute(\n"
            "    \"SELECT * FROM users WHERE id = %s\",\n"
            "    (user_id,),\n"
            ")\n"
        ),
        node=(
            "db.query(\n"
            "  'SELECT * FROM users WHERE id = ?',\n"
            "  [userId],\n"
            ")\n"
        ),
        php=(
            "$stmt = $pdo->prepare('SELECT * FROM users WHERE id = :id');\n"
            "$stmt->execute(['id' => $userId]);\n"
        ),
    ),
    "Missing Anti-clickjacking Header": _entry(
        advice=(
            "Send the X-Frame-Options header (DENY or SAMEORIGIN) to prevent "
            "clickjacking via iframes."
        ),
        python=(
            "response.headers['X-Frame-Options'] = 'DENY'\n"
        ),
        node=(
            "res.setHeader('X-Frame-Options', 'DENY');\n"
        ),
        php=(
            "header('X-Frame-Options: DENY');\n"
        ),
    ),
    "Content Security Policy Header Not Set": _entry(
        advice=(
            "Implement a Content-Security-Policy header restricting script, "
            "style, and other resource sources."
        ),
        python=(
            "response.headers['Content-Security-Policy'] = \"default-src 'self'\"\n"
        ),
        node=(
            "res.setHeader(\n"
            "  'Content-Security-Policy',\n"
            "  \"default-src 'self'\"\n"
            ");\n"
        ),
        php=(
            "header(\"Content-Security-Policy: default-src 'self'\");\n"
        ),
    ),
    "X-Content-Type-Options Header Missing": _entry(
        advice="Send X-Content-Type-Options: nosniff to prevent MIME-type sniffing.",
        python=(
            "response.headers['X-Content-Type-Options'] = 'nosniff'\n"
        ),
        node=(
            "res.setHeader('X-Content-Type-Options', 'nosniff');\n"
        ),
        php=(
            "header('X-Content-Type-Options: nosniff');\n"
        ),
    ),
    "Strict-Transport-Security Header Not Set": _entry(
        advice=(
            "Send Strict-Transport-Security to enforce HTTPS (HSTS) for the site."
        ),
        python=(
            "response.headers['Strict-Transport-Security'] = 'max-age=31536000; "
            "includeSubDomains'\n"
        ),
        node=(
            "res.setHeader(\n"
            "  'Strict-Transport-Security',\n"
            "  'max-age=31536000; includeSubDomains'\n"
            ");\n"
        ),
        php=(
            "header('Strict-Transport-Security: max-age=31536000; "
            "includeSubDomains');\n"
        ),
    ),
    "Cookie No HttpOnly Flag": _entry(
        advice=(
            "Set the HttpOnly flag on session cookies to prevent "
            "client-side script access."
        ),
        python=(
            "response.set_cookie('sessionid', value, httponly=True)\n"
        ),
        node=(
            "res.cookie('sessionid', value, { httpOnly: true });\n"
        ),
        php=(
            "setcookie('sessionid', $value, 0, '/', '', false, true);\n"
        ),
    ),
    "Cookie Without Secure Flag": _entry(
        advice="Set the Secure flag on cookies so they are only sent over HTTPS.",
        python=(
            "response.set_cookie('sessionid', value, secure=True)\n"
        ),
        node=(
            "res.cookie('sessionid', value, { secure: true });\n"
        ),
        php=(
            "setcookie('sessionid', $value, 0, '/', '', true, false);\n"
        ),
    ),
    "Server Leaks Information via \"X-Powered-By\" HTTP Response Header Field(s)": _entry(
        advice=(
            "Remove or obscure server technology headers to avoid disclosing "
            "the stack to attackers."
        ),
        python=(
            "response.headers.pop('X-Powered-By', None)\n"
        ),
        node=(
            "res.removeHeader('X-Powered-By');\n"
        ),
        php=(
            "header_remove('X-Powered-By');\n"
        ),
    ),
    "Directory Browsing": _entry(
        advice=(
            "Disable directory listing on the web server so directory contents "
            "are not exposed."
        ),
        python=(
            "# Configure your WSGI server / reverse proxy to disable indexes\n"
            "# e.g. nginx: autoindex off;\n"
        ),
        node=(
            "// Configure your static file server to disable directory listings\n"
        ),
    ),
    "Heartbleed": _entry(
        advice=(
            "Upgrade OpenSSL to a patched version and reissue any potentially "
            "exposed SSL certificates and keys."
        ),
    ),
    "SSL Certificate Cannot Be Trusted": _entry(
        advice=(
            "Install a valid SSL/TLS certificate issued by a trusted "
            "Certificate Authority."
        ),
    ),
}


def get_remediation(alert_name: str) -> dict[str, Any] | None:
    """Return remediation advice and code snippets for a ZAP alert name.

    Returns None when the alert name is not in the knowledge base.
    """
    return REMEDIATION_KB.get(alert_name)
