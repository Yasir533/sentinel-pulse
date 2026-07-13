import os
import socket
from flask import Flask, Response, redirect, url_for

app = Flask(__name__)

# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def get_local_ip() -> str:
    """Detect the LAN IP of this machine reliably."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"
    finally:
        s.close()


def get_user_model_source() -> str:
    """Return the source code of app/models/user.py."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                        "app", "models", "user.py")
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"# Error reading file: {e}"


# ──────────────────────────────────────────────
# Routes
# ──────────────────────────────────────────────

@app.route("/")
def index():
    """Root → redirect to /view for convenience."""
    return redirect(url_for("view"))


@app.route("/view")
def view():
    """
    Render a mobile-friendly HTML page showing user.py.
    Works great on both smartphone and laptop browsers.
    """
    code = get_user_model_source()
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Sentinel Pulse – User Model</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}

    body {{
      background: #0d1117;
      color: #e6edf3;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica,
                   Arial, sans-serif;
      min-height: 100vh;
    }}

    header {{
      background: linear-gradient(135deg, #161b22 0%, #1c2128 100%);
      border-bottom: 1px solid #30363d;
      padding: 16px 20px;
      display: flex;
      align-items: center;
      gap: 12px;
      position: sticky;
      top: 0;
      z-index: 10;
    }}

    header .badge {{
      background: #238636;
      color: #fff;
      font-size: 11px;
      font-weight: 700;
      letter-spacing: .5px;
      padding: 3px 8px;
      border-radius: 20px;
      text-transform: uppercase;
    }}

    header h1 {{
      font-size: 16px;
      font-weight: 600;
      color: #e6edf3;
    }}

    header .path {{
      font-size: 12px;
      color: #8b949e;
      margin-left: auto;
      font-family: "SFMono-Regular", Consolas, monospace;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
      max-width: 200px;
    }}

    .container {{
      max-width: 960px;
      margin: 24px auto;
      padding: 0 16px 40px;
    }}

    .file-card {{
      background: #161b22;
      border: 1px solid #30363d;
      border-radius: 10px;
      overflow: hidden;
      box-shadow: 0 4px 24px rgba(0,0,0,.4);
    }}

    .file-header {{
      background: #1c2128;
      border-bottom: 1px solid #30363d;
      padding: 10px 16px;
      display: flex;
      align-items: center;
      gap: 10px;
    }}

    .file-header .dot {{
      width: 12px; height: 12px; border-radius: 50%;
      display: inline-block;
    }}
    .dot.red   {{ background: #ff5f57; }}
    .dot.yellow{{ background: #ffbd2e; }}
    .dot.green {{ background: #28c940; }}

    .file-header .filename {{
      font-size: 13px;
      color: #8b949e;
      font-family: "SFMono-Regular", Consolas, monospace;
      margin-left: 4px;
    }}

    pre {{
      padding: 20px;
      overflow-x: auto;
      font-family: "SFMono-Regular", Consolas, "Liberation Mono", Menlo,
                   Courier, monospace;
      font-size: 13px;
      line-height: 1.7;
      color: #e6edf3;
      tab-size: 4;
      white-space: pre;
    }}

    /* Minimal syntax colouring (no JS needed) */
    .kw  {{ color: #ff7b72; }}  /* keywords */
    .str {{ color: #a5d6ff; }}  /* strings  */
    .cmt {{ color: #8b949e; font-style: italic; }}  /* comments */

    footer {{
      text-align: center;
      font-size: 11px;
      color: #484f58;
      margin-top: 32px;
    }}

    @media (max-width: 600px) {{
      pre {{ font-size: 11px; padding: 12px; }}
      header h1 {{ font-size: 14px; }}
      header .path {{ display: none; }}
    }}
  </style>
</head>
<body>

<header>
  <span class="badge">LIVE</span>
  <h1>Sentinel Pulse</h1>
  <span class="path">app/models/user.py</span>
</header>

<div class="container">
  <div class="file-card">
    <div class="file-header">
      <span class="dot red"></span>
      <span class="dot yellow"></span>
      <span class="dot green"></span>
      <span class="filename">user.py</span>
    </div>
    <pre><code>{code.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")}</code></pre>
  </div>
  <footer>Sentinel Pulse &mdash; Mobile Dev Server &mdash; port 8080</footer>
</div>

</body>
</html>"""
    return Response(html, mimetype="text/html")


# ──────────────────────────────────────────────
# Entry point
# ──────────────────────────────────────────────

if __name__ == "__main__":
    ip = get_local_ip()
    print("=" * 55)
    print("  Sentinel Pulse – Mobile Dev Server")
    print("=" * 55)
    print(f"  Laptop : http://127.0.0.1:8080")
    print(f"  Phone  : http://{ip}:8080")
    print("=" * 55)
    print("  Make sure your phone is on the same Wi-Fi!")
    print("  Press Ctrl+C to stop.")
    print("=" * 55)
    app.run(host="0.0.0.0", port=8080, debug=False, threaded=True)
