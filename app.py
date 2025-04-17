# app.py
import os
import flask
from flask import Flask, redirect, url_for, session, request, render_template
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
import json
import requests
from collections import defaultdict

app = Flask(__name__)
app.secret_key = "your-secret-key"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"  # Only for local dev

GOOGLE_CLIENT_SECRETS_FILE = "client_secret.json"
SCOPES = ["https://www.googleapis.com/auth/gmail.readonly"]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/authorize")
def authorize():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri=url_for("callback", _external=True),
    )
    auth_url, _ = flow.authorization_url(prompt="consent")
    return redirect(auth_url)

@app.route("/callback")
def callback():
    flow = Flow.from_client_secrets_file(
        GOOGLE_CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri="http://localhost:5000/callback",
    )
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    session["credentials"] = credentials_to_dict(credentials)
    return redirect(url_for("dashboard"))

def priority_sort_key(email):
    order = {"High": 0, "Medium": 1, "Low": 2}
    return order.get(email.get("priority", "Low"), 3)

@app.route("/dashboard")
def dashboard():
    if "credentials" not in session:
        return redirect(url_for("index"))
    return render_template("dashboard.html")

@app.route("/scan_contacts")
def scan_contacts():
    creds = session.get("credentials")
    if not creds:
        return redirect(url_for("index"))

    service = build("gmail", "v1", credentials=Credentials(**creds))
    contact_counts = defaultdict(int)

    next_page_token = None
    while True:
        response = service.users().messages().list(
            userId="me", labelIds=["INBOX"], maxResults=100,
            pageToken=next_page_token
        ).execute()

        messages = response.get("messages", [])
        for msg in messages:
            msg_data = service.users().messages().get(userId="me", id=msg["id"], format="metadata").execute()
            headers = msg_data.get("payload", {}).get("headers", [])
            sender = next((h["value"] for h in headers if h["name"] == "From"), "unknown")
            contact_counts[sender] += 1

        next_page_token = response.get("nextPageToken")
        if not next_page_token:
            break

    with open("contacts.json", "w") as f:
        json.dump(contact_counts, f, indent=2)

    return "Contacts indexed!"

@app.route("/summarize", methods=["POST"])
def summarize_emails():
    creds = session.get("credentials")
    if not creds:
        return redirect(url_for("index"))

    email_filter = request.form.get("filter", "unread")
    count = int(request.form.get("count", 10))

    query_map = {
        "unread": "is:unread",
        "read": "is:read",
        "important": "is:important",
        "all": ""  # no filter
    }

    service = build("gmail", "v1", credentials=Credentials(**creds))
    results = service.users().messages().list(
        userId="me",
        labelIds=["INBOX"],
        q=query_map[email_filter]
    ).execute()

    messages = results.get("messages", [])[:count]

    email_infos = []

    for msg in messages[:10]:  # Limit to 10 unread for now
        msg_data = service.users().messages().get(userId="me", id=msg["id"], format="metadata", metadataHeaders=["Subject", "From"]).execute()
        headers = msg_data.get("payload", {}).get("headers", [])
        subject = next((h["value"] for h in headers if h["name"] == "Subject"), "(No subject)")
        sender = next((h["value"] for h in headers if h["name"] == "From"), "(Unknown sender)")
        snippet = msg_data.get("snippet", "")
        email_infos.append(f"From: {sender}\nSubject: {subject}\nContent: {snippet}")

    if not email_infos:
        return render_template("summary.html", summaries=[("No unread messages", "")])

    report_items = generate_report(email_infos)

    # Sort by priority
    if isinstance(report_items, list):
        report_items.sort(key=priority_sort_key)

    return render_template("summary.html", summaries=report_items)


def generate_report(emails):
    prompt = (
        "You are an assistant that analyzes unread emails. "
        "Based on the sender, subject, and content, assign a priority (High, Medium, Low) to each email, "
        "and explain why. Return your response strictly in JSON format like this:\n\n"
        "[\n"
        "  {\n"
        "    \"priority\": \"High\",\n"
        "    \"sender\": \"Alice <alice@example.com>\",\n"
        "    \"subject\": \"Project deadline approaching\",\n"
        "    \"reason\": \"The deadline is this Friday, and the sender needs confirmation.\"\n"
        "  },\n"
        "  ...\n"
        "]\n\n"
        "Now process the following emails:\n\n"
    )
    prompt += "\n\n".join(emails)


    response = requests.post(
        "http://localhost:11434/api/generate",
        json={
            "model": "mistral",
            "prompt": prompt,
            "stream": False
        }
    )

    raw = response.json()["response"]

    # Try to extract valid JSON (strip if model adds text around it)
    try:
        json_start = raw.find('[')
        json_data = raw[json_start:]
        report_items = json.loads(json_data)
    except Exception as e:
        return f"Error parsing LLM response: {e}\n\nRaw output:\n{raw}"

    return report_items

def credentials_to_dict(creds):
    return {
        "token": creds.token,
        "refresh_token": creds.refresh_token,
        "token_uri": creds.token_uri,
        "client_id": creds.client_id,
        "client_secret": creds.client_secret,
        "scopes": creds.scopes,
    }

if __name__ == "__main__":
    app.run(debug=True)
