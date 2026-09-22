import re
import os
import time
import html
import requests
from flask import Flask, request, jsonify, send_file

app = Flask(__name__)


@app.get("/")
def home():
    return send_file("index.html")


@app.get("/api/send")
def api_status():
    return jsonify({"status": "Mail API is running"})


@app.post("/api/send")
def send_email():
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

        sender_id = str(sender.get("id", "")).strip()
        sender_name = str(sender.get("name", "")).strip()
        sender_address = str(sender.get("email", "")).strip()
        provider = str(sender.get("provider", "")).strip().lower()

        if not sender_id:
            return jsonify({
                "error": "Sender ID is required."
            }), 400

        if not sender_address:
            return jsonify({
                "error": "Sender email address is required."
            }), 400

        if not re.match(
            r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$",
            sender_address
        ):
            return jsonify({
                "error": "Invalid sender email address."
            }), 400

        if provider not in ("cloudflare", "resend"):
            return jsonify({
                "error": "Unsupported sender provider."
            }), 400

        if not recipients:
            return jsonify({
                "error": "At least one recipient is required."
            }), 400

        if not isinstance(variants, list) or not variants:
            return jsonify({
                "error": "At least one email variant is required."
            }), 400

        cleaned_variants = []

        for variant in variants:
            if not isinstance(variant, dict):
                continue

            subject = str(
                variant.get("subject", "")
            ).strip()

            body = str(
                variant.get("body", "")
            )

            if subject and body.strip():
                cleaned_variants.append({
                    "subject": subject,
                    "body": body
                })

        if not cleaned_variants:
            return jsonify({
                "error": (
                    "At least one complete "
                    "subject/body variant is required."
                )
            }), 400

        # Credentials remain server-side in Vercel.
        cloudflare_token = os.environ.get(
            "CLOUDFLARE_API_TOKEN"
        )

        cloudflare_account_id = os.environ.get(
            "CLOUDFLARE_ACCOUNT_ID"
        )

        resend_api_key = os.environ.get(
            "RESEND_API_KEY"
        )

        if provider == "cloudflare":
            if not cloudflare_token:
                return jsonify({
                    "error": (
                        "CLOUDFLARE_API_TOKEN "
                        "is not configured."
                    ),
                    "sender_failed": True,
                    "sender_id": sender_id
                }), 500

            if not cloudflare_account_id:
                return jsonify({
                    "error": (
                        "CLOUDFLARE_ACCOUNT_ID "
                        "is not configured."
                    ),
                    "sender_failed": True,
                    "sender_id": sender_id
                }), 500

            api_url = (
                "https://api.cloudflare.com/client/v4/accounts/"
                f"{cloudflare_account_id}/email/sending/send"
            )

            headers = {
                "Authorization": (
                    f"Bearer {cloudflare_token}"
                ),
                "Content-Type": "application/json",
            }

        else:
            if not resend_api_key:
                return jsonify({
                    "error": (
                        "RESEND_API_KEY "
                        "is not configured."
                    ),
                    "sender_failed": True,
                    "sender_id": sender_id
                }), 500

            api_url = "https://api.resend.com/emails"

            headers = {
                "Authorization": (
                    f"Bearer {resend_api_key}"
                ),
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
