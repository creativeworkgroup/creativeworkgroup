import re
import os
from pathlib import Path
import time
import html
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv
from cryptography.fernet import Fernet
from supabase import create_client
from flask import Flask, request, jsonify, send_file, session

load_dotenv(Path(__file__).resolve().parent / '.env.local', override=True)

app = Flask(__name__)
app.secret_key = os.environ.get("MAIL_SESSION_SECRET")
if not app.secret_key:
    raise RuntimeError("MAIL_SESSION_SECRET is not configured.")



def require_access():
    if not session.get("mail_unlocked"):
        return jsonify({
            "success": False,
            "error": "Access restricted."
        }), 401
    return None


def build_proxy_url(row):
    address = str(row.get("address", "")).strip()
    port = int(row.get("port"))
    username = str(row.get("username") or "").strip()
    password = decrypt_credential(row["credential"]) if row.get("credential") else ""

    from urllib.parse import quote
    auth = ""
    if username:
        auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"
    return f"http://{auth}{address}:{port}"


def proxy_config(row):
    return {
        "id": row["id"],
        "address": row["address"],
        "port": row["port"],
        "username": row.get("username") or "",
        "status": row.get("status") or "active",
        "last_checked_at": row.get("last_checked_at"),
        "last_error": row.get("last_error"),
        "last_used_at": row.get("last_used_at"),
    }


def get_proxy_rows():
    db = get_supabase()
    response = (
        db.table("proxies")
        .select("id,address,port,username,credential,status,last_checked_at,last_error,last_used_at")
        .order("created_at")
        .execute()
    )
    return response.data or []


def choose_proxy():
    rows = get_proxy_rows()
    active = [row for row in rows if row.get("status") == "active"]
    if not active:
        return None

    # Stable human-facing proxy number based on creation order.
    # This is only a display label; credentials remain server-side.
    for index, row in enumerate(rows, start=1):
        row["_proxy_number"] = index

    active.sort(key=lambda row: row.get("last_used_at") or "")
    selected = active[0]

    from datetime import datetime, timezone
    get_supabase().table("proxies").update({
        "last_used_at": datetime.now(timezone.utc).isoformat()
    }).eq("id", selected["id"]).execute()

    return selected


@app.post("/api/auth/unlock")
def unlock():
    data = request.get_json(silent=True) or {}
    supplied = str(data.get("access_code", ""))

    expected = os.environ.get("MAIL_ACCESS_CODE")
    if not expected:
        return jsonify({
            "success": False,
            "error": "MAIL_ACCESS_CODE is not configured."
        }), 500

    if not supplied or supplied != expected:
        return jsonify({
            "success": False,
            "error": "Invalid access code."
        }), 401

    session["mail_unlocked"] = True
    return jsonify({"success": True})


@app.post("/api/auth/lock")
def lock():
    session.clear()
    return jsonify({"success": True})


@app.get("/")
def home():
    return send_file("index.html")


@app.get("/api/send")
def api_status():
    return jsonify({"status": "Mail API is running"})




def get_encryption_key():
    key = os.environ.get("SENDER_CONFIG_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError(
            "SENDER_CONFIG_ENCRYPTION_KEY is not configured."
        )
    return key.encode()


def get_supabase():
    url = os.environ.get("SUPABASE_URL")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY")

    if not url or not key:
        raise RuntimeError(
            "Supabase environment variables are not configured."
        )

    return create_client(url, key)


def encrypt_credential(value):
    cipher = Fernet(get_encryption_key())
    return cipher.encrypt(value.encode()).decode()


def decrypt_credential(value):
    cipher = Fernet(get_encryption_key())
    return cipher.decrypt(value.encode()).decode()


def public_sender(row):
    return {
        "id": row["id"],
        "name": row["name"],
        "email": row["email"],
        "provider": row["provider"],
        "status": row["status"],
    }


def get_sender_store():
    db = get_supabase()

    response = (
        db.table("senders")
        .select("*")
        .order("created_at")
        .execute()
    )

    store = {}

    for row in response.data or []:
        store[row["id"]] = {
            "id": row["id"],
            "name": row["name"],
            "email": row["email"],
            "provider": row["provider"],
            "credential": decrypt_credential(row["credential"]),
            "account_id": row.get("account_id"),
            "status": row["status"],
        }

    return store


def mark_sender_dead(sender_id):
    if not sender_id:
        return

    try:
        db = get_supabase()

        (
            db.table("senders")
            .update({"status": "dead"})
            .eq("id", sender_id)
            .execute()
        )
    except Exception:
        pass


@app.get("/api/senders")
def get_senders():
    denied = require_access()
    if denied:
        return denied

    try:
        db = get_supabase()

        response = (
            db.table("senders")
            .select("id,name,email,provider,status")
            .order("created_at")
            .execute()
        )

        response_json = jsonify({
            "success": True,
            "senders": [
                public_sender(row)
                for row in (response.data or [])
            ]
        })
        response_json.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
        response_json.headers["Pragma"] = "no-cache"
        return response_json

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


@app.post("/api/senders")
def add_sender():
    denied = require_access()
    if denied:
        return denied

    try:
        data = request.get_json(silent=True) or {}

        name = str(data.get("name", "")).strip()
        email = str(data.get("email", "")).strip()
        provider = str(data.get("provider", "")).strip().lower()
        credential = str(data.get("credential", "")).strip()
        account_id = str(data.get("account_id", "")).strip() or None

        if not name or not email or not credential:
            return jsonify({
                "success": False,
                "error": "Name, email and credential are required."
            }), 400

        if not re.match(
            r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$",
            email
        ):
            return jsonify({
                "success": False,
                "error": "Invalid sender email address."
            }), 400

        if provider not in ("cloudflare", "resend"):
            return jsonify({
                "success": False,
                "error": "Unsupported sender provider."
            }), 400

        if provider == "cloudflare" and not account_id:
            return jsonify({
                "success": False,
                "error": "Cloudflare account ID is required."
            }), 400

        db = get_supabase()

        row = {
            "name": name,
            "email": email,
            "provider": provider,
            "credential": encrypt_credential(credential),
            "account_id": account_id,
            "status": "active",
        }

        response = (
            db.table("senders")
            .insert(row)
            .execute()
        )

        if not response.data:
            return jsonify({
                "success": False,
                "error": "Failed to save sender."
            }), 500

        return jsonify({
            "success": True,
            "sender": public_sender(response.data[0])
        }), 201

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


@app.delete("/api/senders/<sender_id>")
def remove_sender(sender_id):
    denied = require_access()
    if denied:
        return denied

    try:
        db = get_supabase()

        (
            db.table("senders")
            .delete()
            .eq("id", sender_id)
            .execute()
        )

        return jsonify({
            "success": True
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


@app.patch("/api/senders/<sender_id>/status")
def update_sender_status(sender_id):
    denied = require_access()
    if denied:
        return denied

    try:
        data = request.get_json(silent=True) or {}
        status = str(data.get("status", "")).strip().lower()

        if status not in ("active", "paused"):
            return jsonify({
                "success": False,
                "error": "Sender status must be active or paused."
            }), 400

        db = get_supabase()
        response = (
            db.table("senders")
            .update({"status": status})
            .eq("id", sender_id)
            .execute()
        )

        if not response.data:
            return jsonify({
                "success": False,
                "error": "Sender was not found."
            }), 404

        return jsonify({
            "success": True,
            "sender": public_sender(response.data[0])
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc)
        }), 500


@app.get("/api/proxies")
def get_proxies():
    denied = require_access()
    if denied:
        return denied
    try:
        rows = get_proxy_rows()
        public = [proxy_config(row) for row in rows]
        return jsonify({
            "success": True,
            "proxies": public,
            "live": sum(1 for row in rows if row.get("status") == "active"),
            "dead": sum(1 for row in rows if row.get("status") == "dead"),
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


def test_proxy_connection(address, port, username="", password=""):
    from urllib.parse import quote

    auth = ""
    if username:
        auth = f"{quote(username, safe='')}:{quote(password, safe='')}@"

    proxy_url = f"http://{auth}{address}:{port}"
    proxies = {"http": proxy_url, "https": proxy_url}

    response = requests.get(
        "https://www.cloudflare.com/cdn-cgi/trace",
        proxies=proxies,
        timeout=15,
    )

    if not response.ok:
        raise RuntimeError(f"Proxy returned HTTP {response.status_code}.")

    return True


@app.post("/api/proxies/test-connection")
def test_proxy_connection_api():
    denied = require_access()
    if denied:
        return denied

    try:
        data = request.get_json(silent=True) or {}
        address = str(data.get("address", "")).strip()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()
        try:
            port = int(data.get("port"))
        except (TypeError, ValueError):
            port = 0

        if not address or not (1 <= port <= 65535):
            return jsonify({"success": False, "error": "Proxy address and a valid port are required."}), 400
        if not password:
            return jsonify({"success": False, "error": "Proxy password is required for a new connection test."}), 400

        try:
            test_proxy_connection(address, port, username, password)
        except Exception as exc:
            return jsonify({"success": False, "status": "dead", "error": str(exc)}), 502

        return jsonify({"success": True, "status": "active", "message": "Proxy is live and reachable."})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.post("/api/proxies")
def add_proxy():
    denied = require_access()
    if denied:
        return denied
    try:
        data = request.get_json(silent=True) or {}
        address = str(data.get("address", "")).strip()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()
        try:
            port = int(data.get("port"))
        except (TypeError, ValueError):
            port = 0

        if not address or not (1 <= port <= 65535):
            return jsonify({"success": False, "error": "Proxy address and a valid port are required."}), 400
        if not password:
            return jsonify({"success": False, "error": "Proxy password is required."}), 400

        try:
            test_proxy_connection(address, port, username, password)
        except Exception as exc:
            return jsonify({"success": False, "error": f"Proxy test failed: {exc}"}), 502

        db = get_supabase()
        response = db.table("proxies").insert({
            "address": address,
            "port": port,
            "username": username or None,
            "credential": encrypt_credential(password),
            "status": "active",
            "last_error": None,
        }).execute()

        if not response.data:
            return jsonify({"success": False, "error": "Failed to save proxy."}), 500

        return jsonify({
            "success": True,
            "proxy": proxy_config(response.data[0])
        }), 201
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.patch("/api/proxies/<proxy_id>")
def edit_proxy(proxy_id):
    denied = require_access()
    if denied:
        return denied
    try:
        data = request.get_json(silent=True) or {}
        address = str(data.get("address", "")).strip()
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", "")).strip()
        try:
            port = int(data.get("port"))
        except (TypeError, ValueError):
            port = 0

        if not address or not (1 <= port <= 65535):
            return jsonify({"success": False, "error": "Proxy address and a valid port are required."}), 400

        if password:
            test_password = password
        else:
            existing_rows = get_proxy_rows()
            existing = next((item for item in existing_rows if item["id"] == proxy_id), None)
            if not existing:
                return jsonify({"success": False, "error": "Proxy not found."}), 404
            test_password = decrypt_credential(existing["credential"])

        try:
            test_proxy_connection(address, port, username, test_password)
        except Exception as exc:
            return jsonify({"success": False, "error": f"Proxy test failed: {exc}"}), 502

        update = {
            "address": address,
            "port": port,
            "username": username or None,
            "status": "active",
            "last_error": None,
        }
        if password:
            update["credential"] = encrypt_credential(password)

        db = get_supabase()
        response = db.table("proxies").update(update).eq("id", proxy_id).execute()
        if not response.data:
            return jsonify({"success": False, "error": "Proxy not found."}), 404

        return jsonify({
            "success": True,
            "proxy": proxy_config(response.data[0])
        })
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.delete("/api/proxies/<proxy_id>")
def delete_proxy(proxy_id):
    denied = require_access()
    if denied:
        return denied
    try:
        response = (
            get_supabase()
            .table("proxies")
            .delete()
            .eq("id", proxy_id)
            .execute()
        )
        return jsonify({"success": True})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500


@app.post("/api/proxies/<proxy_id>/test")
def test_proxy(proxy_id):
    denied = require_access()
    if denied:
        return denied
    try:
        rows = get_proxy_rows()
        row = next((item for item in rows if item["id"] == proxy_id), None)
        if not row:
            return jsonify({"success": False, "error": "Proxy not found."}), 404

        proxy_url = build_proxy_url(row)
        proxies = {"http": proxy_url, "https": proxy_url}

        try:
            response = requests.get(
                "https://www.cloudflare.com/cdn-cgi/trace",
                proxies=proxies,
                timeout=15,
            )
            if not response.ok:
                raise RuntimeError(f"Proxy returned HTTP {response.status_code}.")
        except Exception as exc:
            error = str(exc)
            from datetime import datetime, timezone
            get_supabase().table("proxies").update({
                "status": "dead",
                "last_checked_at": datetime.now(timezone.utc).isoformat(),
                "last_error": error,
            }).eq("id", proxy_id).execute()
            return jsonify({
                "success": False,
                "status": "dead",
                "error": error,
            }), 502

        from datetime import datetime, timezone
        get_supabase().table("proxies").update({
            "status": "active",
            "last_checked_at": datetime.now(timezone.utc).isoformat(),
            "last_error": None,
        }).eq("id", proxy_id).execute()

        return jsonify({"success": True, "status": "active"})
    except Exception as exc:
        return jsonify({"success": False, "error": str(exc)}), 500



def render_email_content(body, buttons):
    # Self-contained CTA markers — no separate button metadata required.
    def replace_self_contained(match):
        import urllib.parse
        label = urllib.parse.unquote(match.group(1))
        url = urllib.parse.unquote(match.group(2))
        safe_label = html.escape(label)
        safe_url = html.escape(url, quote=True)
        return (
            '<div style="text-align:center;margin:18px 0;">'
            '<a href="' + safe_url + '" '
            'style="display:inline-block;padding:12px 24px;'
            'background:#3b82f6;color:#ffffff;text-decoration:none;'
            'border-radius:10px;font-weight:700;">'
            + safe_label +
            '</a></div>'
        )

    self_contained = re.compile(
        r'\[\[CTA_BUTTON:([^|]+)\|([^\]]+)\]\]'
    )
    body = self_contained.sub(replace_self_contained, body)

    """
    Converts the plain-text composer body plus CTA markers into:
      - safe HTML for HTML-capable email clients
      - plain text with clickable URLs visible
    """

    buttons = buttons if isinstance(buttons, list) else []

    button_map = {}

    for button in buttons:
        if not isinstance(button, dict):
            continue

        button_id = str(button.get("id", "")).strip()
        button_text = str(button.get("text", "")).strip()
        button_url = str(button.get("url", "")).strip()

        if not button_id or not button_text or not button_url:
            continue

        parsed = urlparse(button_url)

        if parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            continue

        button_map[button_id] = {
            "text": button_text,
            "url": button_url,
        }

    token_pattern = re.compile(r"\[\[CTA:([A-Za-z0-9_-]+)\]\]")

    html_parts = []
    text_parts = []

    cursor = 0

    for match in token_pattern.finditer(body):
        plain_before = body[cursor:match.start()]

        if plain_before:
            html_parts.append(
                html.escape(plain_before).replace("\n", "<br>")
            )
            text_parts.append(plain_before)

        button = button_map.get(match.group(1))

        if button:
            safe_text = html.escape(button["text"])
            safe_url = html.escape(button["url"], quote=True)

            html_parts.append(
                '<div style="margin:24px 0;text-align:center;">'
                '<a href="' + safe_url + '" '
                'style="display:inline-block;'
                'padding:12px 22px;'
                'background:#111827;'
                'color:#ffffff;'
                'text-decoration:none;'
                'border-radius:7px;'
                'font-family:Arial,sans-serif;'
                'font-size:14px;'
                'font-weight:600;">'
                + safe_text +
                '</a>'
                '</div>'
            )

            text_parts.append(
                "\n" +
                button["text"] +
                ": " +
                button["url"] +
                "\n"
            )
        else:
            # If a marker somehow has no matching button,
            # preserve it as harmless text instead of losing content.
            safe_marker = html.escape(match.group(0))
            html_parts.append(safe_marker)
            text_parts.append(match.group(0))

        cursor = match.end()

    remaining = body[cursor:]

    if remaining:
        html_parts.append(
            html.escape(remaining).replace("\n", "<br>")
        )
        text_parts.append(remaining)

    return (
        "<p>" + "".join(html_parts) + "</p>",
        "".join(text_parts)
    )


@app.post("/api/send")
def send_email():
    denied = require_access()
    if denied:
        return denied

    try:
        data = request.get_json(force=True)

        sender = data.get("sender") or {}
        recipients = data.get("to", [])
        variants = data.get("variants", [])

        if isinstance(recipients, str):
            recipients = [
                x.strip()
                for x in recipients.splitlines()
                if x.strip()
            ]

        if not isinstance(sender, dict):
            return jsonify({
                "error": "A valid sender is required."
            }), 400

        cleaned_variants = []

        for variant in variants:
            if not isinstance(variant, dict):
                continue

            subject = str(variant.get("subject", "")).strip()
            body = str(variant.get("body", "")).strip()

            if subject and body:
                buttons = variant.get("buttons", [])

                if not isinstance(buttons, list):
                    buttons = []

                cleaned_variants.append({
                    "subject": subject,
                    "body": body,
                    "buttons": buttons
                })

        if not cleaned_variants:
            return jsonify({
                "error": "At least one complete subject/body variant is required."
            }), 400

        sender_id = str(sender.get("id", "")).strip()

        if not sender_id:
            return jsonify({
                "error": "Sender ID is required."
            }), 400

        # Sender identity and credentials are resolved exclusively
        # from the server-side Supabase store. Never trust the
        # provider, email, name, or credential supplied by the browser.
        sender_store = get_sender_store()
        stored_sender = sender_store.get(sender_id)

        if not stored_sender:
            return jsonify({
                "error": "Sender was not found."
            }), 404

        if stored_sender.get("status") != "active":
            status_label = str(stored_sender.get("status") or "inactive").upper()
            return jsonify({
                "error": f"This sender is marked {status_label} and cannot be used.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 409

        sender_name = str(
            stored_sender.get("name", "")
        ).strip()

        sender_address = str(
            stored_sender.get("email", "")
        ).strip()

        provider = str(
            stored_sender.get("provider", "")
        ).strip().lower()

        sender_credential = stored_sender.get("credential")
        sender_account_id = stored_sender.get("account_id")

        if not sender_address:
            return jsonify({
                "error": "Sender email address is not configured.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        if not re.match(
            r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$",
            sender_address
        ):
            return jsonify({
                "error": "Invalid sender email address.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        if provider not in ("cloudflare", "resend"):
            return jsonify({
                "error": "Unsupported sender provider.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        if not sender_credential:
            return jsonify({
                "error": "Sender credential is not configured.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        proxy_row = choose_proxy()
        if not proxy_row:
            return jsonify({
                "error": "No active proxies are available.",
                "proxy_failed": True
            }), 503

        proxy_url = build_proxy_url(proxy_row)
        request_proxies = {"http": proxy_url, "https": proxy_url}

        if provider == "cloudflare":
            if not sender_account_id:
                return jsonify({
                    "error": "Cloudflare account ID is not configured.",
                    "sender_failed": True,
                    "sender_id": sender_id
                }), 500

            api_url = (
                "https://api.cloudflare.com/client/v4/accounts/"
                f"{sender_account_id}/email/sending/send"
            )

            headers = {
                "Authorization": f"Bearer {sender_credential}",
                "Content-Type": "application/json",
            }

        else:
            api_url = "https://api.resend.com/emails"

            headers = {
                "Authorization": f"Bearer {sender_credential}",
                "Content-Type": "application/json",
            }

        results = []
        sent = 0
        failed = 0

        import random

        shuffled_variants = []

        while len(shuffled_variants) < len(recipients):
            batch = list(
                range(len(cleaned_variants))
            )
            random.shuffle(batch)
            shuffled_variants.extend(batch)

        for index, recipient in enumerate(recipients):
            variant_index = shuffled_variants[index]
            variant = cleaned_variants[variant_index]

            if provider == "cloudflare":
                email_html, email_text = render_email_content(
                    variant["body"],
                    variant.get("buttons", [])
                )

                payload = {
                    "from": {
                        "address": sender_address,
                        "name": sender_name
                    },
                    "to": [recipient],
                    "subject": variant["subject"],
                    "text": email_text,
                    "html": email_html,
                }

            else:
                from_value = (
                    f"{sender_name} "
                    f"<{sender_address}>"
                    if sender_name
                    else sender_address
                )

                email_html, email_text = render_email_content(
                    variant["body"],
                    variant.get("buttons", [])
                )

                payload = {
                    "from": from_value,
                    "to": [recipient],
                    "subject": variant["subject"],
                    "text": email_text,
                    "html": email_html,
                }

            try:
                response = requests.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=30,
                    proxies=request_proxies,
                )

                try:
                    response_data = response.json()
                except Exception:
                    response_data = {}

                if provider == "cloudflare":
                    provider_success = (
                        response.ok
                        and response_data.get("success") is True
                    )
                else:
                    provider_success = (
                        response.ok
                        and bool(
                            response_data.get("id")
                        )
                    )

                if provider_success:
                    sent += 1

                    if provider == "cloudflare":
                        result_data = (
                            response_data.get(
                                "result",
                                {}
                            )
                        )

                        message_id = (
                            result_data.get(
                                "message_id"
                            )
                        )
                    else:
                        message_id = (
                            response_data.get("id")
                        )

                    results.append({
                        "email": recipient,
                        "status": "Sent",
                        "variant": variant_index + 1,
                        "message_id": message_id,
                        "sender_id": sender_id,
                        "sender": sender_address,
                        "provider": provider,
                        "proxy_number": proxy_row.get("_proxy_number"),
                    })

                else:
                    failed += 1

                    error_data = (
                        response_data.get(
                            "errors"
                        )
                        if provider == "cloudflare"
                        else response_data.get(
                            "message"
                        )
                    )

                    if not error_data:
                        error_data = response.text

                    # Authentication/configuration failures and provider
                    # throttling make this sender unavailable for the
                    # remainder of the current queue. Mark it DEAD so the
                    # frontend automatically skips it while other senders
                    # continue. This does not attempt to bypass provider
                    # limits; it simply removes the failed sender from the
                    # active pool.
                    throttle_error = False
                    if provider == "cloudflare":
                        cloudflare_errors = response_data.get("errors") or []
                        throttle_error = any(
                            str(item.get("code")) == "10004"
                            for item in cloudflare_errors
                            if isinstance(item, dict)
                        )
                    elif provider == "resend":
                        throttle_error = response.status_code == 429

                    sender_failed = (
                        response.status_code in (401, 403, 422, 429)
                        or throttle_error
                    )

                    results.append({
                        "email": recipient,
                        "status": "Failed",
                        "variant": variant_index + 1,
                        "error": error_data,
                        "sender_id": sender_id,
                        "sender": sender_address,
                        "provider": provider,
                        "sender_failed": sender_failed,
                        "proxy_number": proxy_row.get("_proxy_number"),
                    })

                    if sender_failed:
                        mark_sender_dead(sender_id)

                        return jsonify({
                            "success": False,
                            "results": results,
                            "sent": sent,
                            "failed": failed,
                            "total": len(recipients),
                            "sender_failed": True,
                            "sender_id": sender_id,
                            "sender": sender_address,
                            "provider": provider,
                        }), 502

            except requests.RequestException as exc:
                failed += 1
                proxy_error = str(exc)

                try:
                    from datetime import datetime, timezone
                    get_supabase().table("proxies").update({
                        "status": "dead",
                        "last_checked_at": datetime.now(timezone.utc).isoformat(),
                        "last_error": proxy_error,
                    }).eq("id", proxy_row["id"]).execute()
                except Exception:
                    pass

                results.append({
                    "email": recipient,
                    "status": "Failed",
                    "variant": variant_index + 1,
                    "error": proxy_error,
                    "sender_id": sender_id,
                    "sender": sender_address,
                    "provider": provider,
                    "sender_failed": False,
                    "proxy_failed": True,
                    "proxy_id": proxy_row["id"],
                    "proxy_number": proxy_row.get("_proxy_number"),
                })

                return jsonify({
                    "success": False,
                    "results": results,
                    "sent": sent,
                    "failed": failed,
                    "total": len(recipients),
                    "sender_failed": False,
                    "proxy_failed": True,
                    "proxy_id": proxy_row["id"],
                    "sender_id": sender_id,
                    "sender": sender_address,
                    "provider": provider,
                }), 502

            except Exception as exc:
                failed += 1

                results.append({
                    "email": recipient,
                    "status": "Failed",
                    "variant": variant_index + 1,
                    "error": str(exc),
                    "sender_id": sender_id,
                    "sender": sender_address,
                    "provider": provider,
                    "sender_failed": False,
                    "proxy_number": proxy_row.get("_proxy_number"),
                })

        return jsonify({
            "success": failed == 0,
            "results": results,
            "sent": sent,
            "failed": failed,
            "total": len(recipients),
            "sender_failed": False,
            "sender_id": sender_id,
            "sender": sender_address,
            "provider": provider,
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )

def send_email():
    denied = require_access()
    if denied:
        return denied

    try:
        data = request.get_json(force=True)

        sender = data.get("sender") or {}
        recipients = data.get("to", [])
        variants = data.get("variants", [])

        if isinstance(recipients, str):
            recipients = [
                x.strip()
                for x in recipients.splitlines()
                if x.strip()
            ]

        if not isinstance(sender, dict):
            return jsonify({
                "error": "A valid sender is required."
            }), 400

        cleaned_variants = []

        for variant in variants:
            if not isinstance(variant, dict):
                continue

            subject = str(variant.get("subject", "")).strip()
            body = str(variant.get("body", "")).strip()

            if subject and body:
                buttons = variant.get("buttons", [])

                if not isinstance(buttons, list):
                    buttons = []

                cleaned_variants.append({
                    "subject": subject,
                    "body": body,
                    "buttons": buttons
                })

        if not cleaned_variants:
            return jsonify({
                "error": "At least one complete subject/body variant is required."
            }), 400

        sender_id = str(sender.get("id", "")).strip()

        if not sender_id:
            return jsonify({
                "error": "Sender ID is required."
            }), 400

        # Sender identity and credentials are resolved exclusively
        # from the server-side Supabase store. Never trust the
        # provider, email, name, or credential supplied by the browser.
        sender_store = get_sender_store()
        stored_sender = sender_store.get(sender_id)

        if not stored_sender:
            return jsonify({
                "error": "Sender was not found."
            }), 404

        if stored_sender.get("status") != "active":
            status_label = str(stored_sender.get("status") or "inactive").upper()
            return jsonify({
                "error": f"This sender is marked {status_label} and cannot be used.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 409

        sender_name = str(
            stored_sender.get("name", "")
        ).strip()

        sender_address = str(
            stored_sender.get("email", "")
        ).strip()

        provider = str(
            stored_sender.get("provider", "")
        ).strip().lower()

        sender_credential = stored_sender.get("credential")
        sender_account_id = stored_sender.get("account_id")

        if not sender_address:
            return jsonify({
                "error": "Sender email address is not configured.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        if not re.match(
            r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$",
            sender_address
        ):
            return jsonify({
                "error": "Invalid sender email address.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        if provider not in ("cloudflare", "resend"):
            return jsonify({
                "error": "Unsupported sender provider.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        if not sender_credential:
            return jsonify({
                "error": "Sender credential is not configured.",
                "sender_failed": True,
                "sender_id": sender_id
            }), 500

        proxy_row = choose_proxy()
        if not proxy_row:
            return jsonify({
                "error": "No active proxies are available.",
                "proxy_failed": True
            }), 503

        proxy_url = build_proxy_url(proxy_row)
        request_proxies = {"http": proxy_url, "https": proxy_url}

        if provider == "cloudflare":
            if not sender_account_id:
                return jsonify({
                    "error": "Cloudflare account ID is not configured.",
                    "sender_failed": True,
                    "sender_id": sender_id
                }), 500

            api_url = (
                "https://api.cloudflare.com/client/v4/accounts/"
                f"{sender_account_id}/email/sending/send"
            )

            headers = {
                "Authorization": f"Bearer {sender_credential}",
                "Content-Type": "application/json",
            }

        else:
            api_url = "https://api.resend.com/emails"

            headers = {
                "Authorization": f"Bearer {sender_credential}",
                "Content-Type": "application/json",
            }

        results = []
        sent = 0
        failed = 0

        import random

        shuffled_variants = []

        while len(shuffled_variants) < len(recipients):
            batch = list(
                range(len(cleaned_variants))
            )
            random.shuffle(batch)
            shuffled_variants.extend(batch)

        for index, recipient in enumerate(recipients):
            variant_index = shuffled_variants[index]
            variant = cleaned_variants[variant_index]

            if provider == "cloudflare":
                email_html, email_text = render_email_content(
                    variant["body"],
                    variant.get("buttons", [])
                )

                payload = {
                    "from": {
                        "address": sender_address,
                        "name": sender_name
                    },
                    "to": [recipient],
                    "subject": variant["subject"],
                    "text": email_text,
                    "html": email_html,
                }

            else:
                from_value = (
                    f"{sender_name} "
                    f"<{sender_address}>"
                    if sender_name
                    else sender_address
                )

                email_html, email_text = render_email_content(
                    variant["body"],
                    variant.get("buttons", [])
                )

                payload = {
                    "from": from_value,
                    "to": [recipient],
                    "subject": variant["subject"],
                    "text": email_text,
                    "html": email_html,
                }

            try:
                response = requests.post(
                    api_url,
                    headers=headers,
                    json=payload,
                    timeout=30,
                    proxies=request_proxies,
                )

                try:
                    response_data = response.json()
                except Exception:
                    response_data = {}

                if provider == "cloudflare":
                    provider_success = (
                        response.ok
                        and response_data.get("success") is True
                    )
                else:
                    provider_success = (
                        response.ok
                        and bool(
                            response_data.get("id")
                        )
                    )

                if provider_success:
                    sent += 1

                    if provider == "cloudflare":
                        result_data = (
                            response_data.get(
                                "result",
                                {}
                            )
                        )

                        message_id = (
                            result_data.get(
                                "message_id"
                            )
                        )
                    else:
                        message_id = (
                            response_data.get("id")
                        )

                    results.append({
                        "email": recipient,
                        "status": "Sent",
                        "variant": variant_index + 1,
                        "message_id": message_id,
                        "sender_id": sender_id,
                        "sender": sender_address,
                        "provider": provider,
                        "proxy_number": proxy_row.get("_proxy_number"),
                    })

                else:
                    failed += 1

                    error_data = (
                        response_data.get(
                            "errors"
                        )
                        if provider == "cloudflare"
                        else response_data.get(
                            "message"
                        )
                    )

                    if not error_data:
                        error_data = response.text

                    # Authentication/configuration failures and provider
                    # throttling make this sender unavailable for the
                    # remainder of the current queue. Mark it DEAD so the
                    # frontend automatically skips it while other senders
                    # continue. This does not attempt to bypass provider
                    # limits; it simply removes the failed sender from the
                    # active pool.
                    throttle_error = False
                    if provider == "cloudflare":
                        cloudflare_errors = response_data.get("errors") or []
                        throttle_error = any(
                            str(item.get("code")) == "10004"
                            for item in cloudflare_errors
                            if isinstance(item, dict)
                        )
                    elif provider == "resend":
                        throttle_error = response.status_code == 429

                    sender_failed = (
                        response.status_code in (401, 403, 422, 429)
                        or throttle_error
                    )

                    results.append({
                        "email": recipient,
                        "status": "Failed",
                        "variant": variant_index + 1,
                        "error": error_data,
                        "sender_id": sender_id,
                        "sender": sender_address,
                        "provider": provider,
                        "sender_failed": sender_failed,
                        "proxy_number": proxy_row.get("_proxy_number"),
                    })

                    if sender_failed:
                        mark_sender_dead(sender_id)

                        return jsonify({
                            "success": False,
                            "results": results,
                            "sent": sent,
                            "failed": failed,
                            "total": len(recipients),
                            "sender_failed": True,
                            "sender_id": sender_id,
                            "sender": sender_address,
                            "provider": provider,
                        }), 502

            except requests.RequestException as exc:
                failed += 1
                proxy_error = str(exc)

                try:
                    from datetime import datetime, timezone
                    get_supabase().table("proxies").update({
                        "status": "dead",
                        "last_checked_at": datetime.now(timezone.utc).isoformat(),
                        "last_error": proxy_error,
                    }).eq("id", proxy_row["id"]).execute()
                except Exception:
                    pass

                results.append({
                    "email": recipient,
                    "status": "Failed",
                    "variant": variant_index + 1,
                    "error": proxy_error,
                    "sender_id": sender_id,
                    "sender": sender_address,
                    "provider": provider,
                    "sender_failed": False,
                    "proxy_failed": True,
                    "proxy_id": proxy_row["id"],
                    "proxy_number": proxy_row.get("_proxy_number"),
                })

                return jsonify({
                    "success": False,
                    "results": results,
                    "sent": sent,
                    "failed": failed,
                    "total": len(recipients),
                    "sender_failed": False,
                    "proxy_failed": True,
                    "proxy_id": proxy_row["id"],
                    "sender_id": sender_id,
                    "sender": sender_address,
                    "provider": provider,
                }), 502

            except Exception as exc:
                failed += 1

                results.append({
                    "email": recipient,
                    "status": "Failed",
                    "variant": variant_index + 1,
                    "error": str(exc),
                    "sender_id": sender_id,
                    "sender": sender_address,
                    "provider": provider,
                    "sender_failed": False,
                    "proxy_number": proxy_row.get("_proxy_number"),
                })

        return jsonify({
            "success": failed == 0,
            "results": results,
            "sent": sent,
            "failed": failed,
            "total": len(recipients),
            "sender_failed": False,
            "sender_id": sender_id,
            "sender": sender_address,
            "provider": provider,
        })

    except Exception as exc:
        return jsonify({
            "success": False,
            "error": str(exc),
        }), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000))
    )


# ===== FINAL CTA EMAIL RENDERER =====
def render_email_content(body, buttons=None):
    import re
    import html as _html
    import urllib.parse

    body = str(body or "")
    buttons = buttons or []

    by_id = {}
    for b in buttons:
        if isinstance(b, dict):
            bid = str(b.get("id", "")).strip()
            label = str(b.get("text", "")).strip()
            url = str(b.get("url", "")).strip()
            if bid and label and re.match(r"^https?://\S+$", url, re.I):
                by_id[bid] = (label, url)

    # Supports:
    # [[CTA:id|label|url]]
    # [[CTA:id]]
    # [[CTA_BUTTON:label|url]]
    pattern = re.compile(
        r"\[\[CTA:([^|\]]+)\|([^|\]]*)\|([^\]]*)\]\]"
        r"|\[\[CTA:([A-Za-z0-9_-]+)\]\]"
        r"|\[\[CTA_BUTTON:([^|\]]+)\|([^\]]+)\]\]"
    )

    def decode(v):
        try:
            return urllib.parse.unquote(v or "")
        except Exception:
            return v or ""

    def resolve(m):
        # New self-contained format
        if m.group(1):
            label = decode(m.group(2)).strip()
            url = decode(m.group(3)).strip()
            return label, url

        # Legacy metadata format
        if m.group(4):
            item = by_id.get(m.group(4))
            if item:
                return item
            return None

        # Older CTA_BUTTON format
        label = decode(m.group(5)).strip()
        url = decode(m.group(6)).strip()
        return label, url

    def html_button(m):
        item = resolve(m)
        if not item:
            return ""

        label, url = item

        if not label or not re.match(r"^https?://\S+$", url, re.I):
            return ""

        return (
            '<div style="text-align:center;margin:20px 0;">'
            '<a href="' + _html.escape(url, quote=True) + '" '
            'style="display:inline-block;'
            'background:#3b82f6;'
            'color:#ffffff;'
            'text-decoration:none;'
            'padding:13px 28px;'
            'border-radius:10px;'
            'font-family:Arial,sans-serif;'
            'font-size:15px;'
            'font-weight:700;'
            'line-height:1.2;">'
            + _html.escape(label) +
            '</a>'
            '</div>'
        )

    def text_button(m):
        item = resolve(m)
        if not item:
            return ""

        label, url = item
        return "\n" + label + ": " + url + "\n"

    # Protect CTA markers while escaping normal email text.
    held = []

    def hold(m):
        held.append(m.group(0))
        return f"__CTA_HOLDER_{len(held)-1}__"

    safe_body = pattern.sub(hold, body)
    html_body = _html.escape(safe_body).replace("\n", "<br>")

    for i, marker in enumerate(held):
        placeholder = _html.escape(f"__CTA_HOLDER_{i}__")
        match = pattern.fullmatch(marker)
        html_body = html_body.replace(
            placeholder,
            html_button(match) if match else ""
        )

    text_body = pattern.sub(text_button, body)

    return "<p>" + html_body + "</p>", text_body
