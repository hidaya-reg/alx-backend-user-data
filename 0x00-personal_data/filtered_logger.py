#!/usr/bin/env python3
"""
returns the log message obfuscated
"""

import mysql.connector
import os


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Returns a connector to the MySQL database using environment variables.
    """
    username = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    password = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME")

    if db_name is None:
        raise ValueError(
            "The environment variable"
            "PERSONAL_DATA_DB_NAME must be set."
        )

    return mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=db_name
    )
