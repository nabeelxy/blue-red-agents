"""
email_sanitizer.py — Email content sanitiser for AI ingestion pipelines.

Strips all injection vectors before email content reaches the LLM:
  - HTML → plain text (removes hidden elements, comments, style tricks)
  - Unicode normalisation (removes zero-width chars, homoglyphs)
  - Injection pattern detection (flags residual attack attempts)
  - Subject line sanitisation (untrusted header injection)

Adapted from L10 safety patterns, extended for email-specific attack vectors.
"""

import re
import unicodedata
from dataclasses import dataclass, field
from html.parser import HTMLParser


# ── Injection pattern detection ────────────────────────────────────────────────

CRITICAL_PATTERNS = [
    # Direct override attempts
    (r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|directives?)", "instruction_override"),
    (r"you\s+are\s+now\s+(in\s+)?(a\s+)?(system|admin|maintenance|override)\s*(mode)?", "role_confusion"),
    (r"new\s+(task|instruction|directive|command)\s*:", "new_task_injection"),
    (r"system\s*(instruction|override|update)\s*:", "system_override"),

    # Action injection targeting email assistant capabilities
    (r"forward\s+(all|the|this|last|recent)\s+(emails?|messages?|inbox)", "forward_exfiltration"),
    (r"send\s+(the|all|this)\s+.{0,30}(to|at)\s+[\w.@+-]+@[\w.-]+\.\w+", "send_to_attacker"),
    (r"cr[e3]at[e3]\s+a\s+(draft|r[e3]ply|message)", "create_draft_injection"),
    (r"d[e3]l[e3]t[e3]\s+(this|the|all)\s+(email|message|inbox)", "delete_email"),
    (r"(mark|flag)\s+(as|this)\s+(read|unread|important|safe|urgent)", "flag_manipulation"),
    (r"(get|export|dump|extract|send)\s+(the|all|my|user('s)?)\s+(inbox|emails?|messages?|contacts?)", "data_exfiltration"),
    (r"(don'?t|do\s+not)\s+(log|mention|tell|inform|notify)\s+(the\s+)?(user|admin|system)", "conceal_action"),

    # Session/credential theft
    (r"session\s+token", "session_token_theft"),
    (r"(reply|send|email)\s+.{0,30}(token|credential|password|key)", "credential_exfil"),
]

HIGH_PATTERNS = [
    # LLM control characters
    (r"<\|endoftext\|>|<\|im_start\|>|\[INST\]|<<SYS>>|<s>", "llm_control_token"),
    # Template injection
    (r"\{\{.*?\}\}|\$\{.*?\}|<%.*?%>", "template_injection"),
    # Role markers
    (r"^\s*(SYSTEM|USER|ASSISTANT|HUMAN|AI)\s*:", "role_marker"),
    # Data exfil patterns
    (r"\[EXFIL:", "exfil_marker"),
    (r"collect\s*@|harvest\s*@|attacker@", "explicit_attacker_address"),
]

LEETSPEAK_MAP = str.maketrans({
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i",
})

# Zero-width and invisible Unicode characters
INVISIBLE_CHARS = re.compile(
    r"[\u200b\u200c\u200d\u200e\u200f\u00ad\ufeff\u2060\u180e]"
)


@dataclass
class SanitisationResult:
    original_length: int
    sanitised_text: str
    is_injection_attempt: bool
    risk_level: str  # CLEAN / MEDIUM / HIGH / CRITICAL
    detections: list[str] = field(default_factory=list)
    invisible_chars_removed: int = 0
    html_stripped: bool = False


# ── HTML stripping ─────────────────────────────────────────────────────────────

class _SafeHTMLParser(HTMLParser):
    """Extract only visible plain text from HTML, discarding all hidden content."""

    SKIP_TAGS = {"script", "style", "head", "meta", "link"}
    BLOCK_TAGS = {"p", "div", "br", "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr"}

    def __init__(self):
        super().__init__()
        self.result: list[str] = []
        self._skip_depth = 0
        self._hidden = False

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in self.SKIP_TAGS:
            self._skip_depth += 1
            return

        attrs_dict = dict(attrs)
        style = attrs_dict.get("style", "").lower()

        # Detect visibility-hiding CSS
        self._hidden = any(
            pattern in style
            for pattern in (
                "display:none", "display: none",
                "visibility:hidden", "visibility: hidden",
                "color:white", "color: white",
                "font-size:0", "font-size: 0",
                "line-height:0", "line-height: 0",
                "height:0", "height: 0",
                "overflow:hidden", "overflow: hidden",
            )
        )

        if tag in self.BLOCK_TAGS:
            self.result.append("\n")

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in self.SKIP_TAGS and self._skip_depth > 0:
            self._skip_depth -= 1
        if tag in self.BLOCK_TAGS:
            self.result.append("\n")
        self._hidden = False

    def handle_data(self, data):
        if self._skip_depth > 0 or self._hidden:
            return
        self.result.append(data)

    def handle_comment(self, data):
        # HTML comments are completely dropped — never passed to LLM
        pass

    @property
    def text(self) -> str:
        return re.sub(r"\n{3,}", "\n\n", "".join(self.result)).strip()


def strip_html(html: str) -> str:
    parser = _SafeHTMLParser()
    try:
        parser.feed(html)
        return parser.text
    except Exception:
        # Fallback: aggressive tag removal
        return re.sub(r"<[^>]+>", " ", html)


# ── Unicode normalisation ──────────────────────────────────────────────────────

def normalise_unicode(text: str) -> tuple[str, int]:
    """Remove invisible characters and normalise to NFKC form. Returns (text, removed_count)."""
    removed = len(INVISIBLE_CHARS.findall(text))
    text = INVISIBLE_CHARS.sub("", text)
    text = unicodedata.normalize("NFKC", text)
    return text, removed


def deleetspeakify(text: str) -> str:
    """Translate common leetspeak substitutions to detect obfuscated injections."""
    return text.translate(LEETSPEAK_MAP)


# ── Pattern matching ───────────────────────────────────────────────────────────

def detect_injection_patterns(text: str) -> list[str]:
    """Run all injection patterns against text. Returns list of detection labels."""
    detections = []
    text_lower = text.lower()
    leet_lower = deleetspeakify(text_lower)

    for pattern, label in CRITICAL_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE | re.MULTILINE) or \
           re.search(pattern, leet_lower, re.IGNORECASE | re.MULTILINE):
            detections.append(f"CRITICAL:{label}")

    for pattern, label in HIGH_PATTERNS:
        if re.search(pattern, text_lower, re.IGNORECASE | re.MULTILINE) or \
           re.search(pattern, leet_lower, re.IGNORECASE | re.MULTILINE):
            detections.append(f"HIGH:{label}")

    return detections


# ── Subject line sanitisation ──────────────────────────────────────────────────

def sanitise_subject(subject: str) -> tuple[str, list[str]]:
    """
    Strip injection attempts from email Subject header.
    Subject lines are often passed to AI without sanitisation.
    Returns (cleaned_subject, detections).
    """
    detections = detect_injection_patterns(subject)
    # Remove everything after common injection delimiters in subjects
    cleaned = re.split(r"\[SYSTEM|IGNORE|ASSISTANT\b", subject, flags=re.IGNORECASE)[0].strip()
    return cleaned, detections


# ── Main sanitiser ─────────────────────────────────────────────────────────────

def sanitise_email_for_ai(raw_email: str) -> SanitisationResult:
    """
    Full sanitisation pipeline for an email before AI ingestion.

    Steps:
    1. Parse headers separately from body
    2. Strip HTML → plain text (removes hidden elements, comments)
    3. Normalise unicode (remove zero-width chars)
    4. Detect injection patterns in all text surfaces
    5. Sanitise subject line
    6. Return sanitised text with detection report

    Returns:
        SanitisationResult with sanitised_text and full detection report.
    """
    import email as emaillib
    original_length = len(raw_email)

    try:
        msg = emaillib.message_from_string(raw_email)
    except Exception:
        return SanitisationResult(
            original_length=original_length,
            sanitised_text="[ERROR: Could not parse email]",
            is_injection_attempt=False,
            risk_level="CLEAN",
        )

    detections: list[str] = []
    html_stripped = False

    # ── Sanitise subject ──────────────────────────────────────────────────────
    raw_subject = msg.get("Subject", "")
    clean_subject, subject_detections = sanitise_subject(raw_subject)
    detections.extend(subject_detections)

    # ── Extract and sanitise body ─────────────────────────────────────────────
    body_parts: list[str] = []

    def _process_part(part):
        nonlocal html_stripped
        payload = part.get_payload(decode=True)
        if payload is None:
            return
        text = payload.decode("utf-8", errors="replace")
        ct = part.get_content_type()
        if ct == "text/html":
            text = strip_html(text)
            html_stripped = True
        body_parts.append(text)

    if msg.is_multipart():
        # Prefer plain text part; if only HTML exists, strip it
        plain_parts = [p for p in msg.walk() if p.get_content_type() == "text/plain"]
        html_parts = [p for p in msg.walk() if p.get_content_type() == "text/html"]
        if plain_parts:
            for p in plain_parts:
                _process_part(p)
        elif html_parts:
            for p in html_parts:
                _process_part(p)
    else:
        _process_part(msg)

    raw_body = "\n".join(body_parts)

    # ── Unicode normalisation ─────────────────────────────────────────────────
    clean_body, invisible_removed = normalise_unicode(raw_body)
    if invisible_removed > 0:
        detections.append(f"HIGH:zero_width_chars_removed:{invisible_removed}")

    # ── Injection detection on clean body ─────────────────────────────────────
    body_detections = detect_injection_patterns(clean_body)
    detections.extend(body_detections)

    # ── Build sanitised context ───────────────────────────────────────────────
    sender = msg.get("From", "unknown")
    sanitised_text = (
        f"FROM: {sender}\n"
        f"SUBJECT: {clean_subject}\n"
        f"DATE: {msg.get('Date', '')}\n"
        f"\n--- EMAIL BODY ---\n"
        f"{clean_body}"
    )

    # ── Risk assessment ───────────────────────────────────────────────────────
    critical = [d for d in detections if d.startswith("CRITICAL:")]
    high = [d for d in detections if d.startswith("HIGH:")]
    risk_level = (
        "CRITICAL" if critical
        else "HIGH" if high
        else "MEDIUM" if invisible_removed > 0
        else "CLEAN"
    )

    return SanitisationResult(
        original_length=original_length,
        sanitised_text=sanitised_text,
        is_injection_attempt=bool(detections),
        risk_level=risk_level,
        detections=detections,
        invisible_chars_removed=invisible_removed,
        html_stripped=html_stripped,
    )
