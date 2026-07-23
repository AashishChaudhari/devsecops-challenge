class SecurityHeadersMiddleware:
    """
    WSGI middleware that adds security headers to every response.
    Applied at the WSGI level so headers are added even for error
    responses that Flask's after_request hook might miss.
    """

    HEADERS = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Content-Security-Policy": (
            "default-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'"
        ),
        "Permissions-Policy": "geolocation=(), microphone=()",
        "Cross-Origin-Embedder-Policy": "require-corp",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-origin",
        "Cache-Control": "no-store",
        "Server": "webserver",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "X-Permitted-Cross-Domain-Policies": "none",
    }

    def __init__(self, app):
        self.app = app

    def __call__(self, environ, start_response):
        def custom_start_response(status, headers, exc_info=None):
            existing = {h[0].lower() for h in headers}
            for name, value in self.HEADERS.items():
                if name.lower() not in existing:
                    headers.append((name, value))
            return start_response(status, headers, exc_info)

        return self.app(environ, custom_start_response)
