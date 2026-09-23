"""The analyst console.

formatting  display filters; none of them builds markup
charts      SVG geometry, computed here so the CSP never needs relaxing
views       server-rendered pages over the same pipeline as the API
"""

from app.web.views import STATIC_DIR, TEMPLATE_DIR, router, templates

__all__ = ["STATIC_DIR", "TEMPLATE_DIR", "router", "templates"]
