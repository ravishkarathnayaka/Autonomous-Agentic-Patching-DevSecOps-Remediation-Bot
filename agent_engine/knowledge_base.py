"""Remediation knowledge base providing secure coding patterns and LLM prompt guidance per CWE."""

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass
class CWEPattern:
    cwe_id: str
    name: str
    description: str
    owasp_category: str
    secure_pattern: str
    insecure_anti_pattern: str
    patch_instructions: str


REMEDIATION_CATALOG: Dict[str, CWEPattern] = {
    "CWE-89": CWEPattern(
        cwe_id="CWE-89",
        name="SQL Injection",
        description="Improper neutralization of special elements used in an SQL command.",
        owasp_category="A03:2021-Injection",
        secure_pattern="cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))",
        insecure_anti_pattern="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        patch_instructions="Replace dynamic string interpolation (f-strings, format, %) with parameterized query placeholders."
    ),
    "CWE-78": CWEPattern(
        cwe_id="CWE-78",
        name="OS Command Injection",
        description="Improper neutralization of special elements used in an OS command.",
        owasp_category="A03:2021-Injection",
        secure_pattern="subprocess.run(['ping', '-c', '1', host], shell=False, check=True)",
        insecure_anti_pattern="os.system(f'ping -c 1 {host}')",
        patch_instructions="Use subprocess with shell=False and pass arguments as an explicit argument list. Validate/sanitize input."
    ),
    "CWE-22": CWEPattern(
        cwe_id="CWE-22",
        name="Path Traversal",
        description="Improper limitation of a pathname to a restricted directory ('Path Traversal').",
        owasp_category="A01:2021-Broken Access Control",
        secure_pattern="target = (base_dir / filename).resolve()\nif not str(target).startswith(str(base_dir.resolve())):\n    raise PermissionError('Access denied')",
        insecure_anti_pattern="open(os.path.join(base_dir, user_filename))",
        patch_instructions="Resolve absolute canonical path using Path.resolve() and verify target begins with authorized base directory."
    ),
    "CWE-798": CWEPattern(
        cwe_id="CWE-798",
        name="Use of Hard-coded Credentials",
        description="Storage or embedding of secrets/passwords/API keys directly in source code.",
        owasp_category="A07:2021-Identification and Authentication Failures",
        secure_pattern="api_key = os.getenv('API_KEY', '')",
        insecure_anti_pattern="API_KEY = 'sk-1234567890abcdef'",
        patch_instructions="Extract secret into environment variables via os.environ or an external vault, and provide fallback or validation."
    ),
    "CWE-502": CWEPattern(
        cwe_id="CWE-502",
        name="Deserialization of Untrusted Data",
        description="Unsafe deserialization of arbitrary objects allowing remote code execution.",
        owasp_category="A08:2021-Software and Data Integrity Failures",
        secure_pattern="data = json.loads(payload) # or yaml.safe_load(payload)",
        insecure_anti_pattern="data = pickle.loads(payload)",
        patch_instructions="Avoid pickle/marshal on untrusted inputs. Use safe serialization formats such as JSON or yaml.safe_load()."
    ),
    "CWE-327": CWEPattern(
        cwe_id="CWE-327",
        name="Use of Broken or Risky Cryptographic Algorithm",
        description="Use of obsolete or weak cryptographic hashes (MD5, SHA1) or ciphers (DES).",
        owasp_category="A02:2021-Cryptographic Failures",
        secure_pattern="hash_val = hashlib.sha256(data).hexdigest()",
        insecure_anti_pattern="hash_val = hashlib.md5(data).hexdigest()",
        patch_instructions="Upgrade weak hashing or encryption algorithms to SHA-256, SHA-3, or modern authenticated ciphers like AES-GCM."
    ),
    "CWE-79": CWEPattern(
        cwe_id="CWE-79",
        name="Cross-site Scripting (XSS)",
        description="Improper neutralization of input during web page generation.",
        owasp_category="A03:2021-Injection",
        secure_pattern="return f'<div>{html.escape(user_comment)}</div>'",
        insecure_anti_pattern="return f'<div>{user_comment}</div>'",
        patch_instructions="Sanitize and contextual encode dynamic output using html.escape() or safe template engine escaping."
    ),
    "CWE-918": CWEPattern(
        cwe_id="CWE-918",
        name="Server-Side Request Forgery (SSRF)",
        description="Server makes network requests to an arbitrary user-supplied URL.",
        owasp_category="A10:2021-Server-Side Request Forgery",
        secure_pattern="if not is_allowed_domain(target_url):\n    raise ValueError('Disallowed host')\nresponse = requests.get(target_url, allow_redirects=False)",
        insecure_anti_pattern="response = requests.get(request.args.get('url'))",
        patch_instructions="Validate request target against strict hostname whitelist, disable automatic HTTP redirects, and prohibit internal IP ranges (127.0.0.1, 10.0.0.0/8, 169.254.169.254)."
    )
}


def get_cwe_pattern(cwe_id: str) -> Optional[CWEPattern]:
    """Retrieve CWE remediation pattern by ID (e.g. 'CWE-89' or '89')."""
    clean = cwe_id.upper().strip()
    if not clean.startswith("CWE-"):
        clean = f"CWE-{clean}"
    return REMEDIATION_CATALOG.get(clean)


def list_supported_cwes() -> List[str]:
    """List all supported CWE IDs in the knowledge base."""
    return sorted(list(REMEDIATION_CATALOG.keys()))
