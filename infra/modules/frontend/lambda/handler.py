"""Serve the private SPA and securely proxy API requests through one HTTPS URL."""

from __future__ import annotations

import base64
import json
import mimetypes
import os
import urllib.error
import urllib.request

import boto3
from botocore.exceptions import ClientError

S3 = boto3.client("s3")
BUCKET = os.environ["FRONTEND_BUCKET"]
API_ORIGIN = os.environ.get("API_ORIGIN", "").rstrip("/")
ORIGIN_SECRET = os.environ.get("ORIGIN_SECRET", "")
COGNITO_DOMAIN = os.environ.get("COGNITO_DOMAIN", "").rstrip("/")

CONNECT_SOURCES = "'self'" + (f" {COGNITO_DOMAIN}" if COGNITO_DOMAIN else "")

SECURITY_HEADERS = {
    "content-security-policy": (
        "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
        f"img-src 'self' data:; connect-src {CONNECT_SOURCES}; frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'"
    ),
    "referrer-policy": "strict-origin-when-cross-origin",
    "strict-transport-security": "max-age=31536000; includeSubDomains",
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
}


def _response(status: int, body: bytes, headers: dict[str, str] | None = None) -> dict:
    merged = {**SECURITY_HEADERS, **(headers or {})}
    return {
        "statusCode": status,
        "headers": merged,
        "body": base64.b64encode(body).decode("ascii"),
        "isBase64Encoded": True,
    }


def _proxy_api(event: dict, path: str) -> dict:
    if not API_ORIGIN or not ORIGIN_SECRET:
        return _response(503, b'{"detail":"API runtime is unavailable"}', {"content-type": "application/json"})

    query = event.get("rawQueryString", "")
    target = f"{API_ORIGIN}{path}" + (f"?{query}" if query else "")
    headers = {
        key: value
        for key, value in event.get("headers", {}).items()
        if key.lower() not in {"host", "content-length", "connection", "x-clouddetective-origin"}
    }
    headers["X-CloudDetective-Origin"] = ORIGIN_SECRET

    body = event.get("body") or ""
    payload = base64.b64decode(body) if event.get("isBase64Encoded") else body.encode("utf-8")
    method = event["requestContext"]["http"]["method"]
    request = urllib.request.Request(
        target,
        data=payload if payload or method in {"POST", "PUT", "PATCH"} else None,
        headers=headers,
        method=method,
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            response_headers = {
                key.lower(): value
                for key, value in response.headers.items()
                if key.lower() not in {"connection", "content-length", "transfer-encoding"}
            }
            return _response(response.status, response.read(), response_headers)
    except urllib.error.HTTPError as error:
        response_headers = {
            key.lower(): value
            for key, value in error.headers.items()
            if key.lower() not in {"connection", "content-length", "transfer-encoding"}
        }
        return _response(error.code, error.read(), response_headers)
    except urllib.error.URLError:
        return _response(502, b'{"detail":"API origin is unavailable"}', {"content-type": "application/json"})


def _serve_asset(path: str) -> dict:
    requested = path.lstrip("/")
    key = requested if requested and "." in requested.rsplit("/", 1)[-1] else "index.html"
    try:
        item = S3.get_object(Bucket=BUCKET, Key=key)
    except ClientError as error:
        if error.response.get("Error", {}).get("Code") in {"NoSuchKey", "404"}:
            try:
                item = S3.get_object(Bucket=BUCKET, Key="index.html")
                key = "index.html"
            except ClientError:
                return _response(503, b"Dashboard assets have not been published yet.", {"content-type": "text/plain"})
        else:
            raise

    content_type = item.get("ContentType") or mimetypes.guess_type(key)[0] or "application/octet-stream"
    cache_control = "no-cache" if key == "index.html" else "public, max-age=31536000, immutable"
    return _response(200, item["Body"].read(), {"content-type": content_type, "cache-control": cache_control})


def handler(event: dict, _context: object) -> dict:
    path = event.get("rawPath") or "/"
    if path == "/healthz":
        return _response(200, json.dumps({"status": "ok"}).encode(), {"content-type": "application/json"})
    if path == "/api" or path.startswith("/api/"):
        return _proxy_api(event, path)
    if event.get("requestContext", {}).get("http", {}).get("method") not in {"GET", "HEAD"}:
        return _response(405, b"Method not allowed", {"content-type": "text/plain", "allow": "GET, HEAD"})
    return _serve_asset(path)
