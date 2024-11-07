#!/usr/bin/env python3
"""
obfuscat log message
"""
import re


def filter_datum(fields, redaction, message, separator):
    pattern = '|'.join([
        f'{field}=.*?{separator}' for field in fields
    ])
    return re.sub(
        pattern,
        lambda m: f"{m.group(0).split('=')[0]}={redaction}{separator}",
        message
    )
