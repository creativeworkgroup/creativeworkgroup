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

        sender = data.get("from", "").strip()
        recipients = data.get("to", [])
        reply_to = data.get("reply_to", "").strip()
        variants = data.get("variants", [])

        if isinstance(recipients, str):
            recipients = [
                x.strip()
                for x in recipients.splitlines()
                if x.strip()
            ]

        api_token = os.environ.get("CLOUDFLARE_API_TOKEN")
        account_id = os.environ.get("CLOUDFLARE_ACCOUNT_ID")

        if not api_token:
            return jsonify({
                "error": "CLOUDFLARE_API_TOKEN is not configured."
            }), 500

        if not account_id:
            return jsonify({
                "error": "CLOUDFLARE_ACCOUNT_ID is not configured."
            }), 500

        if not sender:
            return jsonify({"error": "Send From is required."}), 400

        sender_match = re.match(
            r'^\s*(?:(.*?)\s*)?<([^<>]+)>\s*$',
            sender
        )

        if sender_match:
            sender_name = (sender_match.group(1) or "").strip()
            sender_address = sender_match.group(2).strip()
        else:
            sender_name = ""
            sender_address = sender.strip()

        if not re.match(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$", sender_address):
            return jsonify({"error": "Invalid Send From email address."}), 400

        if not recipients:
            return jsonify({
                "error": "At least one recipient is required."
            }), 400

        if not isinstance(variants, list) or not variants:
            return jsonify({
                "error": "At least one email variant is required."
            }), 400

        cleaned_variants = []

        for variant in variants[:5]:
            subject = str(variant.get("subject", "")).strip()
            body = str(variant.get("body", ""))

            if subject and body.strip():
                cleaned_variants.append({
                    "subject": subject,
                    "body": body
                })

        if not cleaned_variants:
            return jsonify({
                "error": "At least one complete subject/body variant is required."
            }), 400

        cloudflare_url = (
            "https://api.cloudflare.com/client/v4/accounts/"
            f"{account_id}/email/sending/send"
        )

        headers = {
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json",
        }

        results = []
        sent = 0
        failed = 0

        # Shuffle variants independently for each recipient.
        import random

        shuffled_variants = []

        while len(shuffled_variants) < len(recipients):
            batch = list(range(len(cleaned_variants)))
            random.shuffle(batch)
            shuffled_variants.extend(batch)

        for index, recipient in enumerate(recipients):
            variant_index = shuffled_variants[index]
            variant = cleaned_variants[variant_index]

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
                    + html.escape(variant["body"])
                    .replace("\n", "<br>")
                    + "</p>"
                ),
            }

            if reply_to:
                payload["reply_to"] = reply_to

            try:
                response = requests.post(
                    cloudflare_url,
                    headers=headers,
                    json=payload,
                    timeout=30,
                )

                try:
                    response_data = response.json()
                except Exception:
                    response_data = {}

                if response.ok and response_data.get("success") is True:
                    sent += 1

                    result = response_data.get("result", {})

                    results.append({
                        "email": recipient,
                        "status": "Sent",
                        "variant": variant_index + 1,
                        "message_id": result.get("message_id"),
                    })
                else:
                    failed += 1

                    results.append({
                        "email": recipient,
                        "status": "Failed",
                        "variant": variant_index + 1,
                        "error": response_data.get(
                            "errors",
                            response.text
                        ),
                    })

            except Exception as exc:
                failed += 1

                results.append({
                    "email": recipient,
                    "status": "Failed",
                    "variant": variant_index + 1,
                    "error": str(exc),
                })

        return jsonify({
            "success": failed == 0,
            "results": results,
            "sent": sent,
            "failed": failed,
            "total": len(recipients),
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
