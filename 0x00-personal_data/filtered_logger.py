#!/usr/bin/env python3
"""
obfuscat log message
"""
import re
from typing import List
import logging


def filter_datum(
    fields: List[str],
    redaction: str,
    message: str,
    separator: str
) -> str:
    """
    returns the log message obfuscated
    """
    pattern = '|'.join([
        f'{field}=.*?{separator}' for field in fields
    ])
    return re.sub(
        pattern,
        lambda m: f"{m.group(0).split('=')[0]}={redaction}{separator}",
        message
    )


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

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
            record.msg,
            self.SEPARATOR
        )
        return super(RedactingFormatter, self).format(record)
