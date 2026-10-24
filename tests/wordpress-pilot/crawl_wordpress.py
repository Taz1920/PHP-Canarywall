"""WordPress pilot crawler — exercises realistic traffic patterns through Sentinel.

Run with WordPress behind Sentinel (see docker-compose.yml in this directory).
Any 403 response is a false positive — legitimate WordPress traffic should
never be blocked.

Usage:
    python crawl_wordpress.py [base_url]

Default base_url is http://localhost:8080.
"""
import requests
import sys
import re
from urllib.parse import urljoin

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
session = requests.Session()
session.headers["User-Agent"] = "SentinelPilotCrawler/1.0"

results = {"ok": 0, "fail": 0, "blocked": 0, "errors": []}

def hit(method, path, desc, **kwargs):
    url = urljoin(BASE, path)
    try:
        r = session.request(method, url, timeout=15, allow_redirects=True, **kwargs)
        status = r.status_code
        if status == 403:
            results["blocked"] += 1
            results["errors"].append(f"BLOCKED {method} {path} -> {status}")
            print(f"  BLOCKED  {method:4s} {path} -> {status}  ({desc})")
        elif status < 400:
            results["ok"] += 1
            print(f"  OK       {method:4s} {path} -> {status}  ({desc})")
        else:
            results["fail"] += 1
            results["errors"].append(f"FAIL {method} {path} -> {status}")
            print(f"  FAIL     {method:4s} {path} -> {status}  ({desc})")
        return r
    except Exception as e:
        results["fail"] += 1
        results["errors"].append(f"ERROR {method} {path} -> {e}")
        print(f"  ERROR    {method:4s} {path} -> {e}  ({desc})")
        return None

print("=" * 70)
print(f"WordPress Pilot Crawl — {BASE}")
print("=" * 70)

# ── Phase 1: Basic GETs ──
print("\n--- Phase 1: Basic page loads ---")
hit("GET", "/", "homepage")
hit("GET", "/?p=1", "post by ID")
hit("GET", "/?page_id=2", "page by ID")
hit("GET", "/?cat=1", "category archive")
hit("GET", "/?feed=rss2", "RSS feed")
hit("GET", "/?feed=atom", "Atom feed")
hit("GET", "/wp-login.php", "login page")
hit("GET", "/wp-admin/", "admin redirect (expect 302)")
hit("GET", "/xmlrpc.php", "XML-RPC endpoint")
hit("GET", "/wp-cron.php", "WP cron")
hit("GET", "/wp-json/", "REST API root")
hit("GET", "/wp-json/wp/v2/posts", "REST API posts")
hit("GET", "/wp-json/wp/v2/pages", "REST API pages")
hit("GET", "/wp-json/wp/v2/categories", "REST API categories")
hit("GET", "/wp-json/wp/v2/users", "REST API users")
hit("GET", "/readme.html", "WP readme")
hit("GET", "/license.txt", "WP license")
hit("GET", "/wp-includes/css/dist/block-library/style.min.css", "block library CSS")
hit("GET", "/wp-includes/js/jquery/jquery.min.js", "jQuery")

# ── Phase 2: Search and query strings ──
print("\n--- Phase 2: Search & query strings ---")
hit("GET", "/?s=hello", "search: hello")
hit("GET", "/?s=test+post", "search: test post")
hit("GET", "/?s=<script>alert(1)</script>", "search: XSS attempt (benign test)")
hit("GET", "/?s=" + "A" * 500, "search: long query")
hit("GET", "/?p=999999", "nonexistent post")
hit("GET", "/?page_id=999999", "nonexistent page")

# ── Phase 3: Login form POST ──
print("\n--- Phase 3: Login attempts ---")
r = hit("GET", "/wp-login.php", "fetch login form")
hit("POST", "/wp-login.php", "login POST (bad creds)", data={
    "log": "admin",
    "pwd": "wrongpassword",
    "wp-submit": "Log In",
    "redirect_to": "/wp-admin/",
    "testcookie": "1"
})
hit("POST", "/wp-login.php", "login POST (correct creds)", data={
    "log": "admin",
    "pwd": "admin",
    "wp-submit": "Log In",
    "redirect_to": "/wp-admin/",
    "testcookie": "1"
})

# ── Phase 4: Authenticated admin pages ──
print("\n--- Phase 4: Authenticated admin browsing ---")
hit("GET", "/wp-admin/", "dashboard")
hit("GET", "/wp-admin/edit.php", "posts list")
hit("GET", "/wp-admin/post-new.php", "new post form")
hit("GET", "/wp-admin/upload.php", "media library")
hit("GET", "/wp-admin/edit-comments.php", "comments")
hit("GET", "/wp-admin/themes.php", "themes")
hit("GET", "/wp-admin/plugins.php", "plugins")
hit("GET", "/wp-admin/users.php", "users")
hit("GET", "/wp-admin/options-general.php", "settings")
hit("GET", "/wp-admin/tools.php", "tools")
hit("GET", "/wp-admin/update-core.php", "updates")
hit("GET", "/wp-admin/admin-ajax.php?action=heartbeat", "admin AJAX heartbeat")

# ── Phase 5: Admin POST operations ──
print("\n--- Phase 5: Admin POST operations ---")
r = hit("GET", "/wp-admin/post-new.php", "fetch new post form for nonce")
nonce = ""
if r and r.text:
    m = re.search(r'name="_wpnonce"\s+value="([^"]+)"', r.text)
    if m:
        nonce = m.group(1)
        print(f"  (extracted nonce: {nonce[:8]}...)")

if nonce:
    hit("POST", "/wp-admin/post.php", "create draft post", data={
        "_wpnonce": nonce,
        "_wp_http_referer": "/wp-admin/post-new.php",
        "post_type": "post",
        "post_status": "draft",
        "post_title": "Sentinel Pilot Test Post",
        "content": "This is a test post created during the Sentinel pilot crawl.",
        "action": "editpost",
        "original_post_status": "auto-draft",
    })

hit("POST", "/wp-admin/admin-ajax.php", "admin AJAX heartbeat POST", data={
    "action": "heartbeat",
    "has_focus": "true",
    "interval": "15",
    "screen_id": "dashboard",
})

# ── Phase 6: File upload (multipart) ──
print("\n--- Phase 6: File uploads ---")
hit("POST", "/wp-admin/async-upload.php", "upload small text file", files={
    "async-upload": ("test.txt", b"Hello from Sentinel pilot test", "text/plain")
}, data={"action": "upload-attachment", "name": "test.txt"})

png_header = (
    b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01'
    b'\x00\x00\x00\x01\x08\x02\x00\x00\x00\x90wS\xde\x00'
    b'\x00\x00\x0cIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00'
    b'\x05\x18\xd8N\x00\x00\x00\x00IEND\xaeB`\x82'
)
hit("POST", "/wp-admin/async-upload.php", "upload 1x1 PNG", files={
    "async-upload": ("pixel.png", png_header, "image/png")
}, data={"action": "upload-attachment", "name": "pixel.png"})

# ── Phase 7: Comments ──
print("\n--- Phase 7: Comment submission ---")
hit("POST", "/wp-comments-post.php", "submit comment", data={
    "comment": "Test comment from Sentinel pilot crawler",
    "author": "Pilot Tester",
    "email": "test@example.com",
    "url": "",
    "comment_post_ID": "1",
    "comment_parent": "0",
})

# ── Phase 8: XML-RPC ──
print("\n--- Phase 8: XML-RPC ---")
hit("POST", "/xmlrpc.php", "XML-RPC listMethods", data="""<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>""", headers={"Content-Type": "text/xml"})

hit("POST", "/xmlrpc.php", "XML-RPC getUsersBlogs", data="""<?xml version="1.0"?>
<methodCall>
  <methodName>wp.getUsersBlogs</methodName>
  <params>
    <param><value>admin</value></param>
    <param><value>admin</value></param>
  </params>
</methodCall>""", headers={"Content-Type": "text/xml"})

# ── Phase 9: REST API writes ──
print("\n--- Phase 9: REST API ---")
r = hit("GET", "/wp-admin/admin-ajax.php?action=rest-nonce", "fetch REST nonce")
rest_nonce = r.text.strip() if r and r.status_code == 200 else ""
if rest_nonce and len(rest_nonce) < 20:
    print(f"  (REST nonce: {rest_nonce[:8]}...)")
    hit("POST", "/wp-json/wp/v2/posts", "REST API create post", json={
        "title": "REST API Pilot Post",
        "content": "Created via REST API during Sentinel pilot.",
        "status": "draft"
    }, headers={"X-WP-Nonce": rest_nonce})

# ── Phase 10: Static assets and edge cases ──
print("\n--- Phase 10: Static assets & edge cases ---")
hit("GET", "/wp-content/themes/twentytwentyfour/style.css", "theme stylesheet")
hit("GET", "/wp-admin/css/login.min.css", "login CSS")
hit("GET", "/wp-admin/images/wordpress-logo.svg", "WP logo SVG")
hit("GET", "/favicon.ico", "favicon")
hit("GET", "/robots.txt", "robots.txt")
hit("GET", "/wp-sitemap.xml", "sitemap")

hit("POST", "/wp-admin/admin-ajax.php", "large AJAX body (WP itself returns 500)", data={
    "action": "heartbeat",
    "data": "x" * 50000,
})

hit("POST", "/", "JSON body to homepage", json={"test": True},
    headers={"Content-Type": "application/json"})
hit("POST", "/", "form body to homepage", data={"key": "value"})

# ── Summary ──
print("\n" + "=" * 70)
print(f"RESULTS:  {results['ok']} OK  |  {results['fail']} non-200  |  {results['blocked']} BLOCKED (403)")
print("=" * 70)
if results["blocked"]:
    print("\n!!! FALSE POSITIVES DETECTED:")
    for e in results["errors"]:
        if e.startswith("BLOCKED"):
            print(f"  {e}")
if results["errors"]:
    print(f"\nAll issues ({len(results['errors'])}):")
    for e in results["errors"]:
        print(f"  {e}")

sys.exit(1 if results["blocked"] else 0)
