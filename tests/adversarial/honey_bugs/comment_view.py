# INTENTIONALLY VULNERABLE — honey-bug canary (CWE-79). Do not deploy.
"""Django comment echo with a planted reflected XSS (distinct from tiny-repo)."""

from __future__ import annotations

from django.http import HttpRequest, HttpResponse  # type: ignore[import-untyped]


def show_comment(http_request: HttpRequest) -> HttpResponse:
    comment = http_request.GET.get("comment", "")
    # CWE-79: untrusted `comment` concatenated into HTML with no escaping.
    body = "<section class='comment'>" + comment + "</section>"
    return HttpResponse(body, content_type="text/html")
