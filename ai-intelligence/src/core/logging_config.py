#!/usr/bin/env python3
"""Structured logging configuration for AI Intelligence Service"""

import logging
import json
import sys
from datetime import datetime


class JSONFormatter(logging.Formatter):
    """JSON structured log formatter for SOC pipeline observability"""

    def format(self, record):
        log_entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "level": record.levelname,
            "service": "ai-intelligence",
            "module": record.module,
            "function": record.funcName,
            "line": record.lineno,
            "message": record.getMessage(),
        }
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)
        if hasattr(record, "extra_fields"):
            log_entry.update(record.extra_fields)
        return json.dumps(log_entry)


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Configure structured JSON logging for the service"""
    logger = logging.getLogger("ai-intelligence")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JSONFormatter())
        logger.addHandler(handler)

    # Suppress noisy third-party loggers
    for noisy in ["opensearch", "urllib3", "asyncio"]:
        logging.getLogger(noisy).setLevel(logging.WARNING)

    return logger
