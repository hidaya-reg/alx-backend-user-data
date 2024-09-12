#!/usr/bin/env python3
"""
returns the log message obfuscated
"""

import re


def filter_datum(fields, redaction, message, separator):
    """
    Obfuscates the values of specified fields in a log message.
    """
    pattern = '|'.join([f'{field}=.*?{separator}' for field in fields])
    return re.sub(
        pattern,
        lambda m: f"{m.group(0).split('=')[0]}={redaction}{separator}",
        message
        )
