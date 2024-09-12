#!/usr/bin/env python3
"""
returns the log message obfuscated
"""

import logging
import re
from typing import List


PII_FIELDS = ("email", "phone", "ssn", "password", "date_of_birth")


def filter_datum(
    fields: List[str],
    redaction: str,
    message: str,
    separator: str
) -> str:
    """
    Obfuscates the values of specified fields in a log message.
    """
    pattern = '|'.join([f'{field}=.*?{separator}' for field in fields])
    return re.sub(
        pattern,
        lambda m: f"{m.group(0).split('=')[0]}={redaction}{separator}",
        message
    )


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """ Initialize with a list of fields to redact """
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Filter values in log records using filter_datum """
        record.msg = filter_datum(
            self.fields,
            self.REDACTION,
            record.getMessage(),
            self.SEPARATOR
        )
        return super(RedactingFormatter, self).format(record)


def get_logger() -> logging.Logger:
    """
    Returns a Logger object configured with RedactingFormatter.
    """
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(fields=PII_FIELDS))
    logger.addHandler(stream_handler)

    return logger
