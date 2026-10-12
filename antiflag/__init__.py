"""AntiFlag: tell a harmless Wi-Fi, school or corporate proxy apart from a real VPN."""

from .classifier import assess
from .headers import HeaderFindings, analyze_headers, headers_from_wsgi
from .models import Assessment, NetworkInfo, NetworkKind, Verdict
from .network import NetworkDB, NetworkLookup, classify_org

__all__ = [
    "Assessment",
    "HeaderFindings",
    "NetworkDB",
    "NetworkInfo",
    "NetworkKind",
    "NetworkLookup",
    "Verdict",
    "analyze_headers",
    "assess",
    "classify_org",
    "headers_from_wsgi",
]

__version__ = "0.1.0"
