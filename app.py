import re
import os
from pathlib import Path
import time
import html
import requests
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
                cleaned_variants.append({
                    "subject": subject,
                    "body": body
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

        if stored_sender.get("status") == "dead":
            return jsonify({
                "error": "This sender is marked DEAD and cannot be used.",
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
                payload = {
                    "from": {
                        "address": sender_address,
                        "name": sender_name
                    },
                    "to": [recipient],
                    "subject": variant["subject"],
                    "text": variant["body"],
                    "html": (
                        "<p>"
                        + html.escape(
                            variant["body"]
                        ).replace(
                            "\n",
                            "<br>"
                        )
                        + "</p>"
                    ),
                }

            else:
                from_value = (
                    f"{sender_name} "
                    f"<{sender_address}>"
                    if sender_name
                    else sender_address
                )

                payload = {
                    "from": from_value,
                    "to": [recipient],
                    "subject": variant["subject"],
                    "text": variant["body"],
                    "html": (
                        "<p>"
                        + html.escape(
                            variant["body"]
                        ).replace(
                            "\n",
                            "<br>"
                        )
                        + "</p>"
                    ),
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

                    # A provider/authentication/configuration
                    # failure can invalidate the sender.
                    sender_failed = (
                        response.status_code
                        in (401, 403, 422)
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
