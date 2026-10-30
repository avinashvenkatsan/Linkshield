import logging
import re
import sys
from typing import Any

try:
    from pythonjsonlogger import jsonlogger
except ImportError:  # pragma: no cover
    from pythonjsonlogger import json as jsonlogger

from app.core.config import get_settings

_SECRET_QUERY_RE = re.compile(r"(token|key|password|passwd|secret|auth|session|access)=([^&]*)", re.I)


def redact(value: str) -> str:
    if not value:
        return value
    redacted = _SECRET_QUERY_RE.sub(lambda m: f"{m.group(1)}=[redacted]", value)
    if "?" in redacted:
        host, _, _rest = redacted.partition("?")
        return f"{host}?[redacted]"
    return redacted


class RedactingFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = redact(record.msg)
        if record.args:
            record.args = tuple(redact(a) if isinstance(a, str) else a for a in record.args)
        return True


def configure_logging() -> None:
    settings = get_settings()
    handler = logging.StreamHandler(sys.stdout)
    formatter = jsonlogger.JsonFormatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    handler.setFormatter(formatter)
    handler.addFilter(RedactingFilter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(settings.log_level.upper())


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)


def extra_safe(**kwargs: Any) -> dict[str, Any]:
    return {k: redact(v) if isinstance(v, str) else v for k, v in kwargs.items()}
