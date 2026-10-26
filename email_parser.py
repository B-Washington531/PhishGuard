import ipaddress
import re
import sys
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse


def analyze_email(file_path):
    with open(file_path, "rb") as file:
        email_message = BytesParser(
            policy=policy.default
        ).parse(file)

    sender = email_message.get("From")
    recipient = email_message.get("To")
    subject = email_message.get("Subject")
    date = email_message.get("Date")

    body = email_message.get_body(
        preferencelist=("plain",)
    )

    print("===== EMAIL ANALYSIS =====")
    print("From:", sender)
    print("To:", recipient)
    print("Subject:", subject)
    print("Date:", date)

    email_text = body.get_content() if body else ""

    print("Body:", email_text)

    urgency_results = detect_urgency(email_text)

    print("\n===== PHISHING INDICATORS =====")

    if urgency_results:
        for phrase in urgency_results:
            print("Suspicious phrase detected:", phrase)
    else:
        print("No urgency-related phrases detected.")

    print("\n===== URL ANALYSIS =====")

    urls = extract_urls(email_text)

    if urls:
        for url in urls:
            analyze_url(url)
    else:
        print("No URLs detected.")

    risk_score = calculate_risk_score(urgency_results, urls)
    print("\n===== PHISHING RISK ASSESSMENT =====")
    print("Risk Score:", risk_score, "/ 100")

    if risk_score >= 60:
        print("Risk Level: HIGH")
    elif risk_score >= 30:
        print("Risk Level: MEDIUM")
    else:
        print("Risk Level: LOW")


def detect_urgency(email_body):
    suspicious_phrases = [
        "urgent",
        "immediately",
        "account suspended",
        "verify your account",
        "verify your credentials",
        "24 hours"
    ]

    detected_phrases = []

    for phrase in suspicious_phrases:
        if phrase in email_body.lower():
            detected_phrases.append(phrase)

    return detected_phrases


def extract_urls(email_body):
    url_pattern = r"https?://[^\s<>\"']+"

    urls = re.findall(url_pattern, email_body)

    return urls


def is_ip_address(hostname):
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def calculate_risk_score(urgency_results, urls):
    score = 0

    # Add 10 points per suspicious phrase
    score += len(urgency_results) * 10

    for url in urls:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        # Add 25 points for an IP-based URL
        if is_ip_address(hostname):
            score += 25

        # Add 10 points for HTTP
        if parsed_url.scheme == "http":
            score += 10

    return min(score, 100)


def analyze_url(url):
    parsed_url = urlparse(url)

    hostname = parsed_url.hostname

    print("URL:", url)
    print("Hostname:", hostname)
    print("Protocol:", parsed_url.scheme)

    if parsed_url.scheme == "http":
        print("Warning: URL uses unencrypted HTTP")
    else:
        print("No HTTP warning detected")

    if is_ip_address(hostname):
        print("Warning: URL uses an IP address instead of a domain name")
    else:
        print("Hostname is not an IP address")


def get_email_analysis(file_path):
    with open(file_path, "rb") as file:
        email_message = BytesParser(
            policy=policy.default
        ).parse(file)

    body = email_message.get_body(
        preferencelist=("plain",)
    )

    email_text = body.get_content() if body else ""

    urgency_results = detect_urgency(email_text)
    urls = extract_urls(email_text)
    risk_score = calculate_risk_score(urgency_results, urls)
    url_warnings = []

    for url in urls:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname

        if parsed_url.scheme == "http":
            url_warnings.append("Unencrypted HTTP detected")

        if is_ip_address(hostname):
            url_warnings.append("URL uses an IP address")

    return {
        "sender": str(email_message.get("From", "")),
        "subject": str(email_message.get("Subject", "")),
        "body": email_text,
        "urgency_phrases": urgency_results,
        "urls": urls,
        "risk_score": risk_score,
        "url_warnings": url_warnings,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 email_parser.py <email_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    analyze_email(file_path)