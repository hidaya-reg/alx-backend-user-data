# 0x00. Personal data
## Resources
- [What Is PII, non-PII, and Personal Data?](https://piwik.pro/blog/what-is-pii-personal-data/)
- [logging documentation](https://docs.python.org/3/library/logging.html)
- [bcrypt package](https://github.com/pyca/bcrypt/)
- [Logging to Files, Setting Levels, and Formatting](https://www.youtube.com/watch?v=-ARI4Cz-awo&ab_channel=CoreySchafer)

## Learning Objectives
<details>
<summary>Examples of Personally Identifiable Information (PII)</summary>

### 1. Personally Identifiable Information (PII)
#### Definition:
PII refers to any information that can be used to directly or indirectly identify an individual. It typically includes details that, when combined with other data or by itself, uniquely identify a person.

#### Examples of PII:
- **Direct Identifiers** (uniquely identify an individual on their own):
    + Full name
    + Social Security Number (SSN) or other government ID numbers (e.g., driver’s license, passport)
    + Email address (personal or work)
    + Phone number
    + Physical address (home, work)
    + Financial account numbers (bank accounts, credit card numbers)
- **Indirect Identifiers** (when combined with other data, can help identify an individual):
    + Date of birth
    + Zip code or partial address
    + IP address (in some cases, if it can be linked to a person)
    + Cookies or device IDs used in tracking

**Use in Practice:** PII is a key focus for data privacy regulations such as the GDPR (General Data Protection Regulation) and CCPA (California Consumer Privacy Act), which aim to protect individuals' data from misuse and unauthorized access.

### 2. Non-PII
#### Definition:
Non-PII includes data that, by itself, cannot be used to identify an individual. Non-PII data often consists of generalized, aggregated, or anonymized data points that do not reveal any specific person.

#### Examples of Non-PII:
- Aggregated statistics (e.g., "25% of our users prefer dark mode")
- De-identified or anonymized data (after sufficient processing to prevent re-identification)
- Generalized geographic data (e.g., country or city-level location data without specific addresses)
- Browsing behavior data without identifying cookies (e.g., pageviews without IP addresses or device IDs)

**Use in Practice:** Non-PII data is commonly used in analytics and research, as it poses minimal privacy risk if handled correctly. However, organizations must be cautious since re-identification techniques could sometimes reveal individuals if non-PII data is combined with other datasets.

### 3. Personal Data
#### Definition:
The term "personal data" is broader than PII and is used in regulations like GDPR. Personal data includes any information that relates to an identifiable person, whether directly or indirectly. This can encompass both PII and certain types of non-PII, depending on the context in which it’s used.

#### Examples of Personal Data:
- Any PII (as outlined above)
- Online identifiers (e.g., IP addresses, cookie identifiers)
- Behavioral data (e.g., browsing history or purchase history tied to an individual)
- Location data (e.g., GPS location if it reveals patterns tied to a person)
- Biometric data (e.g., fingerprints, facial recognition data)

**Use in Practice:** Under GDPR, personal data includes a wide range of information that can indirectly identify a person, making it broader than PII. This is why it’s essential to understand both definitions, as some data points that don’t qualify as PII may still be considered personal data under privacy regulations.

### Summary of Differences

|                | PII                                    | Non-PII                                 | Personal Data                            |
|----------------|----------------------------------------|-----------------------------------------|------------------------------------------|
| **Can Identify an Individual** | Yes                                    | No                                      | Yes                                      |
| **Examples**   | Name, SSN, email, phone number         | Aggregated statistics, anonymized data  | PII + indirect data like IP or cookies   |
| **Usage**      | Regulated by privacy laws              | Common in analytics, lower privacy risk | Broad scope under GDPR, regulated data   |

</details>
<details>
<summary>Basic Usage of Logging in Python</summary>

### Basic Usage of Logging in Python
The ``logging`` module provides several log levels to indicate the severity of events. Here are the default levels, from lowest to highest severity:
- **DEBUG**: Detailed information, useful for diagnosing problems.
- **INFO**: Confirmation that things are working as expected.
- **WARNING:** An indication that something unexpected happened, but the software is still working as expected.
- **ERROR:** A serious problem, indicating that the software has not been able to perform some function.
- **CRITICAL:** A very serious error, indicating that the program may be unable to continue running.

#### Setting Up Basic Logging
```python
import logging

# Configure logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Usage
logging.debug('This is a debug message')
logging.info('This is an info message')
logging.warning('This is a warning message')
logging.error('This is an error message')
logging.critical('This is a critical message')
```
This setup will print log messages to the console with a timestamp, the log level, and the message.

#### Advanced Logging: Writing to a File
To write logs to a file instead of the console, you can configure a file handler:
```python
logging.basicConfig(filename='app.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
```
</details>
<details>
<summary>How to implement a log filter that will obfuscate PII fields</summary>

### Obfuscating PII with Log Filters
To protect Personally Identifiable Information (PII), you can implement a log filter that detects and obfuscates sensitive data before it’s written to the log file.

#### Example: Implementing a Log Filter for PII
In this example, we’ll use a custom log filter to mask email addresses and phone numbers.
**1. Create the PII filter:**
The filter will use regular expressions to search for common PII fields and replace them with obfuscated versions.
**2. Add the filter to the logger:**
Attach this filter to the logging configuration.

```python
import logging
import re

class PIIFilter(logging.Filter):
    def filter(self, record):
        # Obfuscate email addresses
        record.msg = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', '[EMAIL]', record.msg)
        # Obfuscate phone numbers (simple pattern for demonstration)
        record.msg = re.sub(r'\b\d{3}[-.]?\d{3}[-.]?\d{4}\b', '[PHONE]', record.msg)
        return True

# Configure logging with PII filter
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

# Set up console handler and add PII filter to it
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)
console_handler.addFilter(PIIFilter())
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Sample log messages with PII
logger.info('User email: user@example.com')
logger.info('User phone: 123-456-7890')
```
**Explanation of the Filter**
- The `PIIFilter` class inherits from `logging.Filter`. Inside the `filter` method:
    + We use regular expressions to identify email addresses and phone numbers in the log message and replace them with placeholders (`[EMAIL]` and `[PHONE]`).
- We then add this filter to our console handler, ensuring that any log passing through this handler will have PII obfuscated.
**Output Example**
With this setup, the output might look like this:
```
2024-11-07 10:00:00 - INFO - User email: [EMAIL]
2024-11-07 10:00:01 - INFO - User phone: [PHONE]
```

| **Method**                         | **Description**                                                                 | **Example**                                                                                                                  |
|------------------------------------|---------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------------------------|
| `logging.getLogger(name)`          | Retrieves a logger instance, often with a module name (or `__name__`), which can be used to log messages. | `logger = logging.getLogger(__name__)`                                                                                       |
| `logger.setLevel(level)`           | Sets the logging level for the logger, which determines the severity of messages it will handle. | `logger.setLevel(logging.DEBUG)` — Captures messages of level `DEBUG` and higher (`INFO`, `WARNING`, etc.).                 |
| `logging.StreamHandler()`          | Creates a handler that sends log messages to the console (standard output).       | `console_handler = logging.StreamHandler()`                                                                                  |
| `console_handler.setLevel(level)`  | Sets the logging level for the specific handler. Messages with a lower level are ignored by the handler. | `console_handler.setLevel(logging.DEBUG)` — Will process messages of level `DEBUG` and higher for this handler.             |
| `console_handler.addFilter(filter)`| Adds a filter to the handler to control which messages get passed through.       | `console_handler.addFilter(PIIFilter())` — Adds a custom filter (e.g., to obfuscate PII in logs).                           |
| `logging.Formatter(fmt)`           | Defines the format of the log messages, such as timestamp, level, and message.   | `formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')` — Formats log messages with timestamp, level, and message itself. |
| `console_handler.setFormatter(formatter)` | Applies the formatter to the handler to specify the format of log messages.    | `console_handler.setFormatter(formatter)` — Applies the defined `formatter` to the `console_handler`.                       |
| `logger.addHandler(handler)`       | Adds a handler to the logger, which determines where the log messages are output. | `logger.addHandler(console_handler)` — Adds the console handler to the logger, so log messages will be output to the console. |
| `logger.info(msg)`                 | Logs an `INFO` level message, which provides general information.                 | `logger.info('User email: user@example.com')` — Logs a message with user email information.                                 |
| `logger.warning(msg)`              | Logs a `WARNING` level message, used for potential issues that do not stop execution. | `logger.warning('Potential issue detected in user data')` — Logs a warning message.                                       |
| `logger.error(msg)`                | Logs an `ERROR` level message, used when an error occurs.                        | `logger.error('Error processing user data')` — Logs an error message indicating a problem in processing data.               |

**Explanation:**
- **Logger:** `getLogger` retrieves a logger instance which can be used throughout the codebase to log messages.
- **Level Settings:** The `setLevel` methods specify the minimum level of severity for both the logger and handler.
- **Handler:** A `StreamHandler` outputs log messages to the console.
- **Formatter:** The formatter determines how the log messages will appear.
- **Filter:** A filter (e.g., `PIIFilter`) is used to modify or exclude specific log messages, such as obfuscating PII.

The above setup captures log messages at `DEBUG` level or higher, filters out sensitive information (like email addresses or phone numbers), and outputs them to the console in a formatted way.
</details>
<details>
<summary>How to encrypt a password and check the validity of an input password</summary>

### Encrypt a password and check the validity of an input password
To encrypt a password and check the validity of an input password in Python, you can use libraries like `bcrypt` or `hashlib`.

#### 1. Install the `bcrypt` library:
If you don't have `bcrypt` installed, you can install it via pip: `pip install bcrypt`

#### 2. Hashing the password:
- You’ll hash the password before storing it in a database. This way, the password is never stored in plaintext.
- `bcrypt` uses a salt (random data) to ensure that even if two users have the same password, their hashes will be different.

#### 3. Checking the password:
When a user logs in, you’ll compare the hashed version of the input password to the stored hashed password.

#### Example Code:
```python
import bcrypt

# Step 1: Hash the password (when the user registers)
def hash_password(password):
    # Generate a salt
    salt = bcrypt.gensalt()
    # Hash the password with the salt
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password

# Step 2: Check the validity of the input password (during login)
def check_password(input_password, stored_hashed_password):
    # Compare the input password (hashed) with the stored hash
    if bcrypt.checkpw(input_password.encode('utf-8'), stored_hashed_password):
        return True  # Password matches
    else:
        return False  # Password does not match

# Example Usage:

# Hash the password (this would be done during registration)
password = "my_secure_password"
stored_hashed_password = hash_password(password)
print(f"Stored Hashed Password: {stored_hashed_password}")

# Check the password (this would be done during login)
input_password = "my_secure_password"
if check_password(input_password, stored_hashed_password):
    print("Password is correct!")
else:
    print("Password is incorrect!")
```
**Explanation:**
- `bcrypt.gensalt()`: Generates a salt. The salt ensures that the hash is unique even if two users have the same password.
- `bcrypt.hashpw()`: Hashes the password with the salt.
- `bcrypt.checkpw()`: Compares the hashed version of the input password with the stored hash to check if they match.

#### Advantages of using bcrypt:
- **Security:** bcrypt is designed for securely hashing passwords, and it automatically handles the complexity of salting and hashing for you.
- **Time-Delay Factor:** bcrypt includes a work factor that makes hashing slower to thwart brute-force attacks. The higher the work factor, the slower the hashing process.
</details>
<details>
<summary>How to authenticate to a database using environment variables</summary>

### Authenticate to a database using environment variables

To authenticate to a database using environment variables in Python, you can store sensitive information such as database credentials (username, password, host, database name, etc.) in environment variables. This way, you don't have to hard-code sensitive data directly in your code, which is a security best practice.

#### 1. Set up the environment variables:
You need to set environment variables for the database connection. You can do this in several ways:
- **Locally:** You can define environment variables in your shell or within an `.env` file.
- **In production:** Use your hosting service's interface to set environment variables.

**On Linux/MacOS (bash shell):**
```bash
Copy code
export DB_HOST='localhost'
export DB_USER='your_username'
export DB_PASSWORD='your_password'
export DB_NAME='your_database_name'
```
**On Windows (Command Prompt):**
```cmd
set DB_HOST=localhost
set DB_USER=your_username
set DB_PASSWORD=your_password
set DB_NAME=your_database_name
```
Alternatively, you can create a `.env` file in your project directory:

**.env file:**
```env
DB_HOST=localhost
DB_USER=your_username
DB_PASSWORD=your_password
DB_NAME=your_database_name
```
#### 2. Use a library to interact with environment variables:
In Python, the `os` library is used to read environment variables. You can also use a package like `python-dotenv` to load environment variables from a `.env` file.

Install `python-dotenv` (if using `.env` files)
You can use the `python-dotenv` package to load the variables from the `.env` file into your environment.
```bash
pip install python-dotenv
```
#### 3. Use the environment variables in your database connection string:
Once the environment variables are set, you can use them to authenticate to the database.

**Example Code**
Connect to the Database using Environment Variables
Here’s an example of how to use these environment variables in a Python application with the `psycopg2` library (for PostgreSQL):
```python
import os
from dotenv import load_dotenv
import psycopg2

# Load environment variables from a .env file (if present)
load_dotenv()

# Retrieve database credentials from environment variables
db_host = os.getenv('DB_HOST')
db_user = os.getenv('DB_USER')
db_password = os.getenv('DB_PASSWORD')
db_name = os.getenv('DB_NAME')

# Establish a database connection using the environment variables
try:
    connection = psycopg2.connect(
        host=db_host,
        user=db_user,
        password=db_password,
        dbname=db_name
    )
    print("Database connection successful!")

    # You can now execute queries here
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM some_table;")
    result = cursor.fetchall()
    print(result)

except Exception as error:
    print("Error while connecting to database:", error)

finally:
    # Clean up
    if connection:
        cursor.close()
        connection.close()
        print("Connection closed.")
```
Explanation:
- **`load_dotenv()`:** This function loads environment variables from the `.env` file into the environment. You can skip this if you're setting the environment variables manually in the shell.
- **`os.getenv()`:** This function retrieves the value of the environment variable. If the environment variable is not set, it returns `None`. You can provide a default value as a second argument to `os.getenv()` if needed.
- **Database Connection:** We use the `psycopg2.connect()` function (for PostgreSQL) to authenticate to the database using the environment variables.
- **Error handling:** If the database connection fails (e.g., wrong credentials or unreachable server), it raises an exception, and we handle it using a `try-except` block.

#### Advantages of using environment variables for authentication:
- **Security:** Sensitive data such as usernames and passwords are not hard-coded into your codebase, reducing the risk of exposure.
- **Flexibility:** Environment variables allow you to easily change configuration values without modifying your code.
- **Separation of concerns:** The application logic is decoupled from sensitive data, making your code cleaner and easier to maintain.

#### Things to Keep in Mind:
- Ensure your `.env` file is not included in your version control system (e.g., by adding it to `.gitignore`).
- Always handle database credentials securely, especially in production environments (e.g., using a secrets manager).
</details>

## Tasks
### 0. Regex-ing
Write a function called ``filter_datum`` that returns the log message obfuscated:
- Arguments:
    + ``fields``: a list of strings representing all fields to obfuscate
    + ``redaction``: a string representing by what the field will be obfuscated
    + ``message``: a string representing the log line
    + ``separator``: a string representing by which character is separating all fields in the log line (``message``)
- The function should use a regex to replace occurrences of certain field values.
- ``filter_datum`` should be less than 5 lines long and use ``re.sub`` to perform the substitution with a single regex.
```bash
$ cat main.py
#!/usr/bin/env python3
"""
Main file
"""

filter_datum = __import__('filtered_logger').filter_datum

fields = ["password", "date_of_birth"]
messages = ["name=egg;email=eggmin@eggsample.com;password=eggcellent;date_of_birth=12/12/1986;", "name=bob;email=bob@dylan.com;password=bobbycool;date_of_birth=03/04/1993;"]

for message in messages:
    print(filter_datum(fields, 'xxx', message, ';'))

$
$ ./main.py
name=egg;email=eggmin@eggsample.com;password=xxx;date_of_birth=xxx;
name=bob;email=bob@dylan.com;password=xxx;date_of_birth=xxx;
``` 
### 1. Log formatter
Copy the following code into ``filtered_logger.py``.
```python
import logging


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self):
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        NotImplementedError
```
Update the class to accept a list of strings ``fields`` constructor argument.
Implement the ``format`` method to filter values in incoming log records using ``filter_datum``. Values for fields in ``fields`` should be filtered.

DO NOT extrapolate ``FORMAT`` manually. The ``format`` method should be less than 5 lines long.
```bash
$ cat main.py
#!/usr/bin/env python3
"""
Main file
"""

import logging
import re

RedactingFormatter = __import__('filtered_logger').RedactingFormatter

message = "name=Bob;email=bob@dylan.com;ssn=000-123-0000;password=bobby2019;"
log_record = logging.LogRecord("my_logger", logging.INFO, None, None, message, None, None)
formatter = RedactingFormatter(fields=("email", "ssn", "password"))
print(formatter.format(log_record))

$
$ ./main.py
[HOLBERTON] my_logger INFO 2019-11-19 18:24:25,105: name=Bob; email=***; ssn=***; password=***;
```
### 2. Create logger
Use [user_data.csv](https://s3.amazonaws.com/alx-intranet.hbtn.io/uploads/misc/2019/11/a2e00974ce6b41460425.csv?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIARDDGGGOUSBVO6H7D%2F20241107%2Fus-east-1%2Fs3%2Faws4_request&X-Amz-Date=20241107T092546Z&X-Amz-Expires=86400&X-Amz-SignedHeaders=host&X-Amz-Signature=5cc84ec417dacbdb692e5235c63eac6872c0768bcd4e80d299c1248669638f0c) for this task

Implement a ``get_logger`` function that takes no arguments and returns a ``logging.Logger`` object.

The logger should be named ``"user_data"`` and only log up to ``logging.INFO`` level. It should not propagate messages to other loggers. It should have a ``StreamHandler`` with ``RedactingFormatter`` as formatter.

Create a tuple ``PII_FIELDS`` constant at the root of the module containing the fields from ``user_data.csv`` that are considered PII. ``PII_FIELDS`` can contain only 5 fields - choose the right list of fields that can are considered as “important” PIIs or information that you **must hide** in your logs. Use it to parameterize the formatter.

**Tips:**
- [What Is PII, non-PII, and personal data?](https://piwik.pro/blog/what-is-pii-personal-data/)
- [Uncovering Password Habits](https://www.digitalguardian.com/blog/uncovering-password-habits-are-users%E2%80%99-password-security-habits-improving-infographic)
```bash
$ cat main.py
#!/usr/bin/env python3
"""
Main file
"""

import logging

get_logger = __import__('filtered_logger').get_logger
PII_FIELDS = __import__('filtered_logger').PII_FIELDS

print(get_logger.__annotations__.get('return'))
print("PII_FIELDS: {}".format(len(PII_FIELDS)))

$
$ ./main.py
<class 'logging.Logger'>
PII_FIELDS: 5
```
### 3. Connect to secure database
Database credentials should NEVER be stored in code or checked into version control. One secure option is to store them as environment variable on the application server.

In this task, you will connect to a secure ``holberton`` database to read a ``users`` table. The database is protected by a username and password that are set as environment variables on the server named ``PERSONAL_DATA_DB_USERNAME`` (set the default as “root”), ``PERSONAL_DATA_DB_PASSWORD`` (set the default as an empty string) and ``PERSONAL_DATA_DB_HOST`` (set the default as “localhost”).

The database name is stored in ``PERSONAL_DATA_DB_NAME``.

Implement a ``get_db`` function that returns a connector to the database (``mysql.connector.connection.MySQLConnection`` object).
- Use the ``os`` module to obtain credentials from the environment
- Use the module ``mysql-connector-python`` to connect to the MySQL database (``pip3 install mysql-connector-python``)
```bash
$ cat main.sql
-- setup mysql server
-- configure permissions
CREATE DATABASE IF NOT EXISTS my_db;
CREATE USER IF NOT EXISTS root@localhost IDENTIFIED BY 'root';
GRANT ALL PRIVILEGES ON my_db.* TO 'root'@'localhost';

USE my_db;

DROP TABLE IF EXISTS users;
CREATE TABLE users (
    email VARCHAR(256)
);

INSERT INTO users(email) VALUES ("bob@dylan.com");
INSERT INTO users(email) VALUES ("bib@dylan.com");

$ 
$ cat main.sql | mysql -uroot -p
Enter password: 
$ 
$ echo "SELECT COUNT(*) FROM users;" | mysql -uroot -p my_db
Enter password: 
2
$ 
$ cat main.py
#!/usr/bin/env python3
"""
Main file
"""

get_db = __import__('filtered_logger').get_db

db = get_db()
cursor = db.cursor()
cursor.execute("SELECT COUNT(*) FROM users;")
for row in cursor:
    print(row[0])
cursor.close()
db.close()

$
$ PERSONAL_DATA_DB_USERNAME=root PERSONAL_DATA_DB_PASSWORD=root PERSONAL_DATA_DB_HOST=localhost PERSONAL_DATA_DB_NAME=my_db ./main.py
2
```
### 4. Read and filter data
Implement a ``main`` function that takes no arguments and returns nothing.

The function will obtain a database connection using ``get_db`` and retrieve all rows in the ``users`` table and display each row under a filtered format like this:
```
[HOLBERTON] user_data INFO 2019-11-19 18:37:59,596: name=***; email=***; phone=***; ssn=***; password=***; ip=e848:e856:4e0b:a056:54ad:1e98:8110:ce1b; last_login=2019-11-14T06:16:24; user_agent=Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; WOW64; Trident/5.0; KTXN);
```
Filtered fields:
- name
- email
- phone
- ssn
- password

Only your ``main`` function should run when the module is executed.
```bash
$ cat main.sql
-- setup mysql server
-- configure permissions
CREATE DATABASE IF NOT EXISTS my_db;
CREATE USER IF NOT EXISTS root@localhost IDENTIFIED BY 'root';
GRANT ALL PRIVILEGES ON my_db.* TO root@localhost;

USE my_db;

DROP TABLE IF EXISTS users;
CREATE TABLE users (
    name VARCHAR(256), 
        email VARCHAR(256), 
        phone VARCHAR(16),
    ssn VARCHAR(16), 
        password VARCHAR(256),
    ip VARCHAR(64), 
        last_login TIMESTAMP,
    user_agent VARCHAR(512)
);

INSERT INTO users(name, email, phone, ssn, password, ip, last_login, user_agent) VALUES ("Marlene Wood","hwestiii@att.net","(473) 401-4253","261-72-6780","K5?BMNv","60ed:c396:2ff:244:bbd0:9208:26f2:93ea","2019-11-14 06:14:24","Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Safari/537.36");
INSERT INTO users(name, email, phone, ssn, password, ip, last_login, user_agent) VALUES ("Belen Bailey","bcevc@yahoo.com","(539) 233-4942","203-38-5395","^3EZ~TkX","f724:c5d1:a14d:c4c5:bae2:9457:3769:1969","2019-11-14 06:16:19","Mozilla/5.0 (Linux; U; Android 4.1.2; de-de; GT-I9100 Build/JZO54K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30");

$ 
$ cat main.sql | mysql -uroot -p
Enter password: 
$ 
$ echo "SELECT COUNT(*) FROM users;" | mysql -uroot -p my_db
Enter password: 
2
$ 
$ PERSONAL_DATA_DB_USERNAME=root PERSONAL_DATA_DB_PASSWORD=root PERSONAL_DATA_DB_HOST=localhost PERSONAL_DATA_DB_NAME=my_db ./filtered_logger.py
[HOLBERTON] user_data INFO 2019-11-19 18:37:59,596: name=***; email=***; phone=***; ssn=***; password=***; ip=60ed:c396:2ff:244:bbd0:9208:26f2:93ea; last_login=2019-11-14 06:14:24; user_agent=Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.157 Safari/537.36;
[HOLBERTON] user_data INFO 2019-11-19 18:37:59,621: name=***; email=***; phone=***; ssn=***; password=***; ip=f724:c5d1:a14d:c4c5:bae2:9457:3769:1969; last_login=2019-11-14 06:16:19; user_agent=Mozilla/5.0 (Linux; U; Android 4.1.2; de-de; GT-I9100 Build/JZO54K) AppleWebKit/534.30 (KHTML, like Gecko) Version/4.0 Mobile Safari/534.30;
```
### 5. Encrypting passwords
User passwords should NEVER be stored in plain text in a database.
Implement a ``hash_password`` function that expects one string argument name ``password`` and returns a salted, hashed password, which is a byte string.
Use the ``bcrypt`` package to perform the hashing (with ``hashpw``).
```bash
$ cat main.py
#!/usr/bin/env python3
"""
Main file
"""

hash_password = __import__('encrypt_password').hash_password

password = "MyAmazingPassw0rd"
print(hash_password(password))
print(hash_password(password))

$
$ ./main.py
b'$2b$12$Fnjf6ew.oPZtVksngJjh1.vYCnxRjPm2yt18kw6AuprMRpmhJVxJO'
b'$2b$12$xSAw.bxfSTAlIBglPMXeL.SJnzme3Gm0E7eOEKOVV2OhqOakyUN5m'
```
### 6. Check valid password
Implement an ``is_valid`` function that expects 2 arguments and returns a boolean.

Arguments:
- ``hashed_password``: bytes type
- ``password``: string type

Use ``bcrypt`` to validate that the provided password matches the hashed password.
```bash
$ cat main.py
#!/usr/bin/env python3
"""
Main file
"""

hash_password = __import__('encrypt_password').hash_password
is_valid = __import__('encrypt_password').is_valid

password = "MyAmazingPassw0rd"
encrypted_password = hash_password(password)
print(encrypted_password)
print(is_valid(encrypted_password, password))

$
$ ./main.py
b'$2b$12$Fnjf6ew.oPZtVksngJjh1.vYCnxRjPm2yt18kw6AuprMRpmhJVxJO'
True
```