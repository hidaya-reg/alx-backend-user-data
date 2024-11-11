# 0x01. Basic authentication
## Background Context
In this project, you will learn what the authentication process means and implement a Basic Authentication on a simple API.

In the industry, you should not implement your own Basic authentication system and use a module or framework that doing it for you (like in Python-Flask: [Flask-HTTPAuth](https://flask-httpauth.readthedocs.io/en/latest/)). Here, for the learning purpose, we will walk through each step of this mechanism to understand it by doing.
## Resources
- [REST API Authentication Mechanisms](https://www.youtube.com/watch?v=501dpx2IjGY&ab_channel=JavaBrains)
- [Base64 in Python](https://docs.python.org/3.7/library/base64.html)
- [HTTP header Authorization](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Authorization)
- [Flask](https://palletsprojects.com/projects/flask/)
- [Base64 - concept](https://en.wikipedia.org/wiki/Base64)

## Learning Objectives
<details>
<summary>What authentication means</summary>
Authentication is the process of verifying the identity of a user or system, ensuring that they are who they claim to be. It's an essential security measure that helps restrict access to sensitive resources, data, or services. During authentication, the user provides credentials, such as a password, biometric data (fingerprint, facial recognition), security token, or digital certificate, which the system checks against stored data.
</details>
<details>
<summary>What Base64 is</summary>

### Base64
Base64 is an encoding scheme that converts binary data (like images, files, or other binary content) into a string of ASCII characters. This makes it suitable for transmitting binary data over systems that handle only text, like email or JSON APIs. In Base64, binary data is split into 6-bit groups and mapped to 64 characters, including `A-Z`, `a-z`, `0-9`, `+`, and `/`, making it safe to use in text formats. It pads the encoded output with `=` characters when needed to keep the length consistent.

In Python, Base64 encoding and decoding can be done using the `base64` module.

#### Example: Encoding and Decoding in Python
Here's a basic example of how to use Base64 in Python:
```python
import base64

# Example binary data (string encoded in UTF-8 bytes)
original_data = "Hello, Base64 encoding!".encode("utf-8")

# Encoding data to Base64
encoded_data = base64.b64encode(original_data)
print("Encoded data:", encoded_data.decode("utf-8"))

# Decoding data from Base64
decoded_data = base64.b64decode(encoded_data)
print("Decoded data:", decoded_data.decode("utf-8"))
```
**Explanation**
1. Encoding (`b64encode`):
Converts binary data to Base64 by encoding it to bytes, which can then be safely stored or transmitted.
2. Decoding (`b64decode`):
Takes Base64-encoded data and converts it back to its original binary form.
**Example Output**
```plaintext
Encoded data: SGVsbG8sIEJhc2U2NCBlbmNvZGluZyE=
Decoded data: Hello, Base64 encoding!
```
#### Note
Base64 is not an encryption method; it’s simply an encoding technique. While Base64 converts data into a different format, it does not offer any security benefits or protect data in any meaningful way. It only makes binary data compatible with text-based formats, making it easier to store or transmit over systems that handle only text.

#### UTF-8 vs. Base64
Base64 and UTF-8 serve different purposes, though both deal with data encoding:

- **UTF-8** is a character encoding standard used to represent text data, especially Unicode characters, in bytes. It efficiently encodes text for storage, display, and processing by representing each character in 1 to 4 bytes. UTF-8 is ideal for representing textual data, like letters and symbols, but it’s not designed for handling arbitrary binary data.

- **Base64**, on the other hand, is designed to encode arbitrary binary data (like images, files, or other non-text data) into an ASCII-compatible string format. It’s often used to make binary data compatible with text-based protocols and formats, such as email (SMTP), URLs, JSON, or XML, which are primarily designed to handle text.

#### Why We Need Base64 in Addition to UTF-8
- **Binary Data in Text-Only Systems:** Many communication systems and protocols handle only text data or might alter binary data. Base64 encoding makes it possible to transmit binary files (like images or PDFs) over such systems by converting them into a text-compatible format.
- **Avoiding Corruption in Text Formats:** Text-based formats, such as JSON and XML, may not support arbitrary binary data directly or may alter special binary bytes. Encoding binary data in Base64 ensures that it remains intact, as it’s transformed into plain ASCII text.
- **Embedding Binary Data in URLs:** URLs and some other text-based protocols often can’t handle raw binary data because it can include control characters or reserved characters. Base64 encoding provides a safe, URL-friendly string representation.

#### Example Scenarios
- **Email Attachments:** Email protocols like SMTP are text-based and can’t handle binary attachments directly. By encoding attachments with Base64, emails can safely include files.
- **Data URIs in HTML/CSS:** Web applications may use Base64 to embed small images or fonts directly within HTML/CSS, simplifying asset management by removing extra HTTP requests.
- **APIs and JSON:** APIs often return data in JSON format, which can only handle text. If an API needs to return binary data (like an image or a file), encoding it as Base64 makes it compatible with JSON.

#### Examples
##### 1. Embedding an Image in HTML or CSS as a Data URI
If you want to embed a small image directly in an HTML or CSS file (instead of linking to an external file), you can convert the image to a Base64 string. This can be helpful for single-page applications or reducing HTTP requests for small assets.
```python
import base64

# Read the image file in binary mode
with open("image.jpg", "rb") as image_file:
    # Encode the image to Base64
    encoded_image = base64.b64encode(image_file.read()).decode("utf-8")

# Generate the Data URI
data_uri = f"data:image/jpeg;base64,{encoded_image}"
print("Data URI:", data_uri)  # You can now embed this in an HTML <img> tag
```
1. **`base64.b64encode()` Output:** The `base64.b64encode()` function returns a **bytes object**, not a string. This means that the encoded data is in a binary format (like `b'SGVsbG8gd29ybGQ='`), which is fine for certain operations but not suitable for all text-based systems or formats (like JSON or HTML).

2. **Converting to a String:** To make the Base64-encoded data usable in text-based contexts (such as embedding in HTML or JSON), we need to convert it from bytes to a plain string. This is where `.decode("utf-8")` comes in. It interprets the bytes as a UTF-8 string and converts them to a regular string that looks like `SGVsbG8gd29ybGQ=`.

3. **UTF-8 Decoding:** Since Base64 encoding uses only ASCII characters, decoding with UTF-8 is safe and straightforward, as all characters in the Base64 alphabet fall within ASCII (a subset of UTF-8).

##### 2. Sending an Image in a JSON API Response
APIs that respond with JSON format cannot directly include binary data. Encoding the image in Base64 allows you to embed the image data as a text string within the JSON.
```python
import base64
import json

# Read and encode the image
with open("image.jpg", "rb") as image_file:
    encoded_image = base64.b64encode(image_file.read()).decode("utf-8")

# Prepare JSON response with encoded image data
json_response = json.dumps({
    "image": encoded_image,
    "description": "A sample image"
})

print("JSON with encoded image:", json_response)
```
**Use Case:** This is useful for web or mobile applications that retrieve images via API and display them directly without saving the image as a file on the server.

##### 3. Storing an Image in a Text-Based Database
In some cases, you might want to store images in a text-based database, like SQLite, without using a `BLOB` field. Encoding the image as Base64 allows you to store it as a regular text entry.
```python
import base64
import sqlite3

# Open and encode image
with open("image.jpg", "rb") as image_file:
    encoded_image = base64.b64encode(image_file.read()).decode("utf-8")

# Connect to SQLite database and insert image data
conn = sqlite3.connect("example.db")
cursor = conn.cursor()
cursor.execute("CREATE TABLE IF NOT EXISTS images (id INTEGER PRIMARY KEY, image TEXT)")
cursor.execute("INSERT INTO images (image) VALUES (?)", (encoded_image,))
conn.commit()
conn.close()
```
Use Case: This is particularly useful for small images in projects where you prefer not to handle binary data or if you have constraints with storage formats.

##### 4. Transmitting an Image via Email
When sending an email with an image attachment, especially when using email clients that support only ASCII characters, Base64 encoding the image ensures it can be sent inline or as an attachment without issues.

```python
import base64
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders

# Read the image file
with open("image.jpg", "rb") as image_file:
    encoded_image = base64.b64encode(image_file.read()).decode("utf-8")

# Set up the email
msg = MIMEMultipart()
msg["From"] = "sender@example.com"
msg["To"] = "recipient@example.com"
msg["Subject"] = "Sample Image Email"

# Attach the Base64-encoded image
part = MIMEBase("application", "octet-stream")
part.set_payload(encoded_image)
encoders.encode_base64(part)
part.add_header("Content-Disposition", "attachment; filename=image.jpg")
msg.attach(part)

# Send the email
with smtplib.SMTP("smtp.example.com", 587) as server:
    server.login("username", "password")
    server.send_message(msg)
```
**Use Case:** This helps when attaching images to emails that may be processed or displayed in text-only email clients, where Base64 ensures compatibility across systems.

</details>
<details>
<summary>How to encode a string in Base64</summary>

### Encode a string in Base64
We often need to convert a string to bytes in Python when dealing with encoding processes like Base64 because **Base64 works on binary data, not on text**. Here’s why this conversion is necessary and some common scenarios where it applies:

#### Why Use Base64 for Text?:
Even though your string may be in ASCII (which is already text), the Base64 encoding process converts the string into a different format that might be necessary for certain applications. The key reasons for doing this, even for simple strings, are:
- **Uniform Format for All Types of Data:** Base64 can represent all kinds of data—whether binary or text—as a simple ASCII string. By encoding everything into Base64, you ensure that all data is handled uniformly, regardless of whether it's originally binary or text.
- **Compatibility with Systems That Require ASCII:** Some systems (like email protocols, HTTP headers, or JSON files) need to ensure that the data being transmitted is 100% ASCII-safe. Special characters, even within text (like newlines, non-ASCII symbols, etc.), can be problematic. Base64 ensures no special characters cause issues.

#### Why Convert a String to Bytes?
1. **Base64 Requires Bytes:**
- The `base64.b64encode()` function works with byte data, not with strings. Encoding and decoding processes like Base64 operate at the binary level because they handle data as a stream of bytes.
- When you pass a string to `base64.b64encode()`, you must first encode it to bytes (e.g., UTF-8) to convert the characters into binary format.

2. **Encoding Standards:**
- Different systems or platforms may require data in byte form rather than as a text string. For instance, network protocols, file operations, and certain APIs often work with raw bytes for consistency.
- Encoding a string to bytes ensures that you preserve data integrity across platforms, especially if you’re sending or storing data that might include special characters.

#### Example Scenarios
- **Sending Data Over a Network:**
When transmitting data, such as via HTTP or email, you often need a standardized binary format. Encoding to bytes and then Base64 ensures data can be sent as text while maintaining its integrity.
- **Storing Binary Data in Text-Based Systems:**
Some systems, like JSON or databases, work only with text data. If you need to store binary data (e.g., images or files), converting it to Base64 makes it possible to save it in a compatible format.
- **Interfacing with APIs:**
APIs that transmit sensitive information (e.g., passwords or tokens) or that accept multimedia (like image uploads) may require data in bytes or Base64-encoded format. Converting the data to bytes ensures it’s compatible with the API.
- **File I/O Operations:**
When reading or writing files, especially binary files (like images or executables), you work with bytes. Encoding a string as bytes helps ensure proper handling of file content without corruption.

#### Step-by-Step Example
- **Import the `base64` module.**
- **Convert the string to bytes** (Base64 encoding requires binary data).
- **Use `base64.b64encode()`** to encode the bytes.
- **Convert the encoded bytes back to a string** if you need a text representation.

```python
import base64

# Step 1: Define your string
original_string = "Hello, world!"

# Step 2: Convert the string to bytes
string_bytes = original_string.encode("utf-8")

# Step 3: Encode the bytes in Base64
base64_bytes = base64.b64encode(string_bytes)

# Step 4: Convert the Base64 bytes back to a string
base64_string = base64_bytes.decode("utf-8")

print("Original string:", original_string)
print("Base64 encoded string:", base64_string)
```
**Explanation**
- `encode("utf-8")`: Converts the original string to bytes, required by b64encode.
- `b64encode()`: Encodes the bytes to Base64.
- `decode("utf-8")`: Converts the Base64-encoded bytes back into a regular string for easier readability.

**Example Output**
```plaintext
Original string: Hello, world!
Base64 encoded string: SGVsbG8sIHdvcmxkIQ==
```
**Decoding the Base64 String**
To decode it back to the original string, you can reverse the process:
```python
# Step 1: Convert the Base64 string to bytes
base64_bytes = base64_string.encode("utf-8")

# Step 2: Decode the bytes from Base64
decoded_bytes = base64.b64decode(base64_bytes)

# Step 3: Convert the bytes back to a string
decoded_string = decoded_bytes.decode("utf-8")

print("Decoded string:", decoded_string)
```
This will output:
```plaintext
Decoded string: Hello, world!
```
</details>
<details>
<summary>What Basic authentication means</summary>

### Basic Authentication
**Basic Authentication** is a simple authentication scheme where the client sends a **username and password** to the server in the HTTP request header. The username and password are encoded using **Base64** and passed in the `Authorization` header.

**Security:** Basic Authentication is considered **not secure** by itself, because the credentials are sent as plaintext (even though encoded in Base64, it's easily decoded). It is typically used with **HTTPS** to ensure the credentials are encrypted during transmission.

#### How Basic Authentication Works
1. **Request without Authentication:** The client sends an HTTP request to a server without any authentication credentials.

2. **401 Unauthorized Response:** The server responds with a `401 Unauthorized` status code and an `WWW-Authenticate` header asking for authentication.
    Example:
    ```mathematica
    HTTP/1.1 401 Unauthorized
    WWW-Authenticate: Basic realm="Restricted"
    ```
3. **Request with Authentication:** The client resends the request with the `Authorization` header containing the **Base64-encoded username and password** in the form of:
    ```makefile
    Authorization: Basic <Base64-encoded-credentials>
    ```
    The server then decodes the credentials, checks if they are correct, and if they are, grants access to the requested resource.

    ```makefile
    Authorization: Basic dXNlcm5hbWU6cGFzc3dvcmQ=
    ```
    The above is the Base64 encoding of `username:password`.

#### Example of Implementing Basic Authentication in Python
You can use the `requests` module to implement Basic Authentication in a Python client or create a simple server using Flask that supports Basic Authentication.

##### 1. Client-side: Sending Basic Authentication
Using the `requests` library in Python, you can send Basic Authentication headers easily.
```python
import requests
from requests.auth import HTTPBasicAuth

# Define the username and password
username = 'user'
password = 'pass'

# Send the request with Basic Authentication
response = requests.get('https://example.com/protected', auth=HTTPBasicAuth(username, password))

# Check the response
if response.status_code == 200:
    print('Access granted!')
    print(response.text)
else:
    print('Authentication failed!')
```
- Here, `requests.get()` sends the `Authorization` header automatically when you use `HTTPBasicAuth`.
- If authentication is successful (status code `200`), it will print the response text. Otherwise, it will indicate authentication failure.
##### 2. Server-side: Basic Authentication in Flask
```python
from flask import Flask, request, jsonify
from functools import wraps
import base64

app = Flask(__name__)

# Hardcoded credentials (username:password)
VALID_USERNAME = 'user'
VALID_PASSWORD = 'pass'

# Decorator to enforce Basic Authentication
def check_auth(username, password):
    return username == VALID_USERNAME and password == VALID_PASSWORD

def authenticate():
    return jsonify({'message': 'Authentication required'}), 401, {
        'WWW-Authenticate': 'Basic realm="Login Required"'
    }

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated

@app.route('/protected')
@requires_auth
def protected_resource():
    return jsonify({'message': 'This is a protected resource!'})

if __name__ == '__main__':
    app.run(debug=True)
```
**Breakdown of the Code:**
1. Check Authentication:
`check_auth(username, password)`: This function compares the provided credentials to valid ones (in this case, hardcoded as `user` and `pass`).
2. Authentication Header:
`authenticate()`: If the credentials are missing or incorrect, the server responds with a `401` `Unauthorized` status and an authentication challenge (`WWW-Authenticate` header).
3. Decorator:
`requires_auth(f)`: This is a custom Flask decorator that ensures Basic Authentication is applied to any route you decorate with it. It checks the `Authorization` header of incoming requests.
4. Protected Route:
`@requires_auth`: The route `/protected` is protected by Basic Authentication. If the correct credentials aren’t provided, the user will be prompted to authenticate.
##### Testing the Flask Application
1. Run the Flask app.
2. Try accessing `http://127.0.0.1:5000/protected` in a browser. You'll be prompted for a username and password.
- Enter `user` for the username and `pass` for the password.
- If correct, you'll see the message: `This is a protected resource!`.
3. If you enter wrong credentials, you'll see a `401 Unauthorized` error.
#### Why Use Basic Authentication?
- **Simple and Easy to Implement:** Basic Authentication is very simple and doesn't require complex setups. It's good for applications where high security isn't a priority.
- **Standardized:** Many APIs and services use Basic Authentication due to its simplicity and standardization.
#### Security Considerations
- **Not Secure on Its Own:** As mentioned, Base64 encoding is not encryption. Credentials can be easily decoded if intercepted. **Always use HTTPS** to encrypt the connection.
- **Better Alternatives:** For production environments, consider using more secure authentication methods, such as **OAuth**, **JWT (JSON Web Tokens)**, or **API Keys**. These methods provide better security and are harder to exploit.

</details>
<details>
<summary>How to send the Authorization header</summary>

### How to send the Authorization header
To send the `Authorization` header in an HTTP request, you need to include it in the request headers. The exact method of sending the `Authorization` header depends on the tool or library you're using. 
#### 1. Using requests in Python
The easiest way to send the `Authorization` header in Python is to use the `requests` library.
```python
import requests
from requests.auth import HTTPBasicAuth

# Your credentials
username = 'user'
password = 'pass'

# URL you want to request
url = 'https://example.com/protected'

# Send the request with the Basic Authorization header
response = requests.get(url, auth=HTTPBasicAuth(username, password))

# Check the response
if response.status_code == 200:
    print('Access granted!')
    print(response.text)
else:
    print('Authentication failed!')
```
- `HTTPBasicAuth(username, password)` automatically adds the `Authorization` header in the form `Basic <Base64-encoded-credentials>`.
- This will send the request with the `Authorization` header to the server.

#### 2. Using cURL
You can also use the command-line tool `curl` to send HTTP requests with the `Authorization` header.

```bash
curl -u user:pass https://example.com/protected
```
The `-u` flag automatically adds the `Authorization` header using Basic Authentication.

</details>

## Tasks
### 0. Simple-basic-API
Download and start your project from this [archive.zip](https://intranet.alxswe.com/rltoken/2o4gAozNufil_KjoxKI5bA)

In this archive, you will find a simple API with one model: `User`. Storage of these users is done via a serialization/deserialization in files.
**Setup and start server**
```bash
$ pip3 install -r requirements.txt
...
$
$ API_HOST=0.0.0.0 API_PORT=5000 python3 -m api.v1.app
 * Serving Flask app "app" (lazy loading)
...
```
**Use the API (in another tab or in your browser)**
```bash
$ curl "http://0.0.0.0:5000/api/v1/status" -vvv
*   Trying 0.0.0.0...
* TCP_NODELAY set
* Connected to 0.0.0.0 (127.0.0.1) port 5000 (#0)
> GET /api/v1/status HTTP/1.1
> Host: 0.0.0.0:5000
> User-Agent: curl/7.54.0
> Accept: */*
> 
* HTTP 1.0, assume close after body
< HTTP/1.0 200 OK
< Content-Type: application/json
< Content-Length: 16
< Access-Control-Allow-Origin: *
< Server: Werkzeug/1.0.1 Python/3.7.5
< Date: Mon, 18 May 2020 20:29:21 GMT
< 
{"status":"OK"}
* Closing connection 0
```

### 1. Error handler: Unauthorized
What the HTTP status code for a request unauthorized? `401` of course!

Edit `api/v1/app.py`:
- Add a new error handler for this status code, the response must be:
    + a JSON: `{"error": "Unauthorized"}`
    + status code `401`
    + you must use `jsonify` from Flask
For testing this new error handler, add a new endpoint in `api/v1/views/index.py`:
- Route: `GET /api/v1/unauthorized`
- This endpoint must raise a 401 error by using `abort` - [Custom Error Pages](https://flask.palletsprojects.com/en/stable/patterns/errorpages/)
By calling `abort(401)`, the error handler for 401 will be executed.

In the first terminal:
```bash
$ API_HOST=0.0.0.0 API_PORT=5000 python3 -m api.v1.app
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
....
```
In a second terminal:
```bash
$ curl "http://0.0.0.0:5000/api/v1/unauthorized"
{
  "error": "Unauthorized"
}
$
$ curl "http://0.0.0.0:5000/api/v1/unauthorized" -vvv
*   Trying 0.0.0.0...
* TCP_NODELAY set
* Connected to 0.0.0.0 (127.0.0.1) port 5000 (#0)
> GET /api/v1/unauthorized HTTP/1.1
> Host: 0.0.0.0:5000
> User-Agent: curl/7.54.0
> Accept: */*
> 
* HTTP 1.0, assume close after body
< HTTP/1.0 401 UNAUTHORIZED
< Content-Type: application/json
< Content-Length: 30
< Server: Werkzeug/0.12.1 Python/3.4.3
< Date: Sun, 24 Sep 2017 22:50:40 GMT
< 
{
  "error": "Unauthorized"
}
* Closing connection 0
```

### 2. Error handler: Forbidden
What the HTTP status code for a request where the user is authenticate but not allowed to access to a resource? `403` of course!

Edit `api/v1/app.py`:
- Add a new error handler for this status code, the response must be:
    + a JSON: `{"error": "Forbidden"}`
    + status code `403`
    + you must use `jsonify` from Flask
For testing this new error handler, add a new endpoint in `api/v1/views/index.py`:
- Route: `GET /api/v1/forbidden`
- This endpoint must raise a `403` error by using `abort` - Custom Error Pages
By calling `abort(403)`, the error handler for 403 will be executed.

In the first terminal:
```bash
$ API_HOST=0.0.0.0 API_PORT=5000 python3 -m api.v1.app
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
....
```
In a second terminal:
```bash
$ curl "http://0.0.0.0:5000/api/v1/forbidden"
{
  "error": "Forbidden"
}
$
$ curl "http://0.0.0.0:5000/api/v1/forbidden" -vvv
*   Trying 0.0.0.0...
* TCP_NODELAY set
* Connected to 0.0.0.0 (127.0.0.1) port 5000 (#0)
> GET /api/v1/forbidden HTTP/1.1
> Host: 0.0.0.0:5000
> User-Agent: curl/7.54.0
> Accept: */*
> 
* HTTP 1.0, assume close after body
< HTTP/1.0 403 FORBIDDEN
< Content-Type: application/json
< Content-Length: 27
< Server: Werkzeug/0.12.1 Python/3.4.3
< Date: Sun, 24 Sep 2017 22:54:22 GMT
< 
{
  "error": "Forbidden"
}
* Closing connection 0
```

### 3. Auth class
Now you will create a class to manage the API authentication.
- Create a folder `api/v1/auth`
- Create an empty file `api/v1/auth/__init__.py`
- Create the class `Auth`:
    + in the file `api/v1/auth/auth.py`
    + import `request` from `flask`
    + class name `Auth`
    + public method `def require_auth(self, path: str, excluded_paths: List[str]) -> bool:` that returns `False` - `path` and `excluded_paths` will be used later, now, you don’t need to take care of them
    + public method `def authorization_header(self, request=None) -> str:` that returns `None` - `request` will be the Flask request object
    + public method `def current_user(self, request=None) -> TypeVar('User'):` that returns `None` - `request` will be the Flask request object

This class is the template for all authentication system you will implement.
```bash
$ cat main_0.py
#!/usr/bin/env python3
""" Main 0
"""
from api.v1.auth.auth import Auth

a = Auth()

print(a.require_auth("/api/v1/status/", ["/api/v1/status/"]))
print(a.authorization_header())
print(a.current_user())

$ 
$ API_HOST=0.0.0.0 API_PORT=5000 ./main_0.py
False
None
None
```

### 4. Define which routes don't need authentication
Update the method `def require_auth(self, path: str, excluded_paths: List[str]) -> bool:` in `Auth` that returns `True` if the `path` is not in the list of strings excluded_paths:
- Returns `True` if `path` is `None`
- Returns `True` if `excluded_paths` is `None` or empty
- Returns `False` if `path` is in `excluded_paths`
- You can assume `excluded_paths` contains string path always ending by a `/`
- This method must be slash tolerant: `path=/api/v1/status` and `path=/api/v1/status/` must be returned `False` if `excluded_paths` contains `/api/v1/status/`
```bash
$ cat main_1.py
#!/usr/bin/env python3
""" Main 1
"""
from api.v1.auth.auth import Auth

a = Auth()

print(a.require_auth(None, None))
print(a.require_auth(None, []))
print(a.require_auth("/api/v1/status/", []))
print(a.require_auth("/api/v1/status/", ["/api/v1/status/"]))
print(a.require_auth("/api/v1/status", ["/api/v1/status/"]))
print(a.require_auth("/api/v1/users", ["/api/v1/status/"]))
print(a.require_auth("/api/v1/users", ["/api/v1/status/", "/api/v1/stats"]))

$
$ API_HOST=0.0.0.0 API_PORT=5000 ./main_1.py
True
True
True
False
False
True
True
```

### 5. Request validation!
Now you will validate all requests to secure the API:

Update the method `def authorization_header(self, request=None) -> str:` in `api/v1/auth/auth.py`:
- If `request` is `None`, returns `None`
- If `request` doesn’t contain the header key `Authorization`, returns `None`
- Otherwise, return the value of the header request `Authorization`

Update the file `api/v1/app.py`:
- Create a variable `auth` initialized to `None` after the `CORS` definition
- Based on the environment variable `AUTH_TYPE`, load and assign the right instance of authentication to `auth`
    + if `auth`:
        - import `Auth` from `api.v1.auth.auth`
        - create an instance of `Auth` and assign it to the variable `auth`

Now the biggest piece is the filtering of each request. For that you will use the Flask method before_request
- Add a method in `api/v1/app.py` to handler `before_request`
    + if `auth` is `None`, do nothing
    + if request.path is not part of this list `['/api/v1/status/', '/api/v1/unauthorized/', '/api/v1/forbidden/']`, do nothing - you must use the method `require_auth` from the auth instance
    + if auth.authorization_header(request) returns None, raise the error 401 - you must use abort
    + if `auth.current_user(request)` returns `None`, raise the error `403` - you must use `abort`

In the first terminal:
```bash
$ API_HOST=0.0.0.0 API_PORT=5000 AUTH_TYPE=auth python3 -m api.v1.app
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
....
```
In a second terminal:
```bash
$ curl "http://0.0.0.0:5000/api/v1/status"
{
  "status": "OK"
}
$ 
$ curl "http://0.0.0.0:5000/api/v1/status/"
{
  "status": "OK"
}
$ 
$ curl "http://0.0.0.0:5000/api/v1/users"
{
  "error": "Unauthorized"
}
$
$ curl "http://0.0.0.0:5000/api/v1/users" -H "Authorization: Test"
{
  "error": "Forbidden"
}
```

### 6. Basic auth
Create a class `BasicAuth` that inherits from `Auth`. For the moment this class will be empty.

Update `api/v1/app.py` for using `BasicAuth` class instead of Auth depending of the value of the environment variable `AUTH_TYPE`, If AUTH_TYPE is equal to basic_auth:
- import `BasicAuth` from `api.v1.auth.basic_auth`
- create an instance of `BasicAuth` and assign it to the variable `auth`

Otherwise, keep the previous mechanism with `auth` an instance of `Auth`.

In the first terminal:
```bash
$ API_HOST=0.0.0.0 API_PORT=5000 AUTH_TYPE=basic_auth python3 -m api.v1.app
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
....
```
In a second terminal:
```bash
$ curl "http://0.0.0.0:5000/api/v1/status"
{
  "status": "OK"
}
$
$ curl "http://0.0.0.0:5000/api/v1/status/"
{
  "status": "OK"
}
$
$ curl "http://0.0.0.0:5000/api/v1/users"
{
  "error": "Unauthorized"
}
$
$ curl "http://0.0.0.0:5000/api/v1/users" -H "Authorization: Test"
{
  "error": "Forbidden"
}
```

### 7. Basic - Base64 part
Add the method `def extract_base64_authorization_header(self, authorization_header: str) -> str:` in the class `BasicAuth` that returns the Base64 part of the `Authorization` header for a Basic Authentication:
- Return `None` if `authorization_header` is `None`
- Return `None` if `authorization_header` is not a string
- Return `None` if `authorization_header` doesn’t start by `Basic` (with a space at the end)
- Otherwise, return the value after `Basic` (after the space)
- You can assume `authorization_header` contains only one `Basic`
```bash
$ cat main_2.py
#!/usr/bin/env python3
""" Main 2
"""
from api.v1.auth.basic_auth import BasicAuth

a = BasicAuth()

print(a.extract_base64_authorization_header(None))
print(a.extract_base64_authorization_header(89))
print(a.extract_base64_authorization_header("Holberton School"))
print(a.extract_base64_authorization_header("Basic Holberton"))
print(a.extract_base64_authorization_header("Basic SG9sYmVydG9u"))
print(a.extract_base64_authorization_header("Basic SG9sYmVydG9uIFNjaG9vbA=="))
print(a.extract_base64_authorization_header("Basic1234"))

$
$ API_HOST=0.0.0.0 API_PORT=5000 ./main_2.py
None
None
None
Holberton
SG9sYmVydG9u
SG9sYmVydG9uIFNjaG9vbA==
None
```
### 8. Basic - Base64 decode
Add the method `def decode_base64_authorization_header(self, base64_authorization_header: str) -> str:` in the class `BasicAuth` that returns the decoded value of a Base64 string `base64_authorization_header`:
- Return `None` if `base64_authorization_header` is `None`
- Return `None` if `base64_authorization_header` is not a string
- Return `None` if `base64_authorization_header` is not a valid Base64 - you can use `try/except`
- Otherwise, return the decoded value as UTF8 string - you can use `decode('utf-8')`
```bash
$ cat main_3.py
#!/usr/bin/env python3
""" Main 3
"""
from api.v1.auth.basic_auth import BasicAuth

a = BasicAuth()

print(a.decode_base64_authorization_header(None))
print(a.decode_base64_authorization_header(89))
print(a.decode_base64_authorization_header("Holberton School"))
print(a.decode_base64_authorization_header("SG9sYmVydG9u"))
print(a.decode_base64_authorization_header("SG9sYmVydG9uIFNjaG9vbA=="))
print(a.decode_base64_authorization_header(a.extract_base64_authorization_header("Basic SG9sYmVydG9uIFNjaG9vbA==")))

$
$ API_HOST=0.0.0.0 API_PORT=5000 ./main_3.py
None
None
None
Holberton
Holberton School
Holberton School
```

### 9. Basic - User credentials
Add the method `def extract_user_credentials(self, decoded_base64_authorization_header: str) -> (str, str)` in the class `BasicAuth` that returns the user email and password from the Base64 decoded value.
- This method must return 2 values
- Return `None`, `None` if `decoded_base64_authorization_header` is `None`
- Return `None`, `None` if `decoded_base64_authorization_header` is not a string
- Return `None`, `None` if `decoded_base64_authorization_header` doesn’t contain `:`
- Otherwise, return the user email and the user password - these 2 values must be separated by a `:`
- You can assume `decoded_base64_authorization_header` will contain only one :
```bash
$ cat main_4.py
#!/usr/bin/env python3
""" Main 4
"""
from api.v1.auth.basic_auth import BasicAuth

a = BasicAuth()

print(a.extract_user_credentials(None))
print(a.extract_user_credentials(89))
print(a.extract_user_credentials("Holberton School"))
print(a.extract_user_credentials("Holberton:School"))
print(a.extract_user_credentials("bob@gmail.com:toto1234"))

$
$ API_HOST=0.0.0.0 API_PORT=5000 ./main_4.py
(None, None)
(None, None)
(None, None)
('Holberton', 'School')
('bob@gmail.com', 'toto1234')
```

### 10. Basic - User object
Add the method `def user_object_from_credentials(self, user_email: str, user_pwd: str) -> TypeVar('User'):` in the class `BasicAuth` that returns the `User` instance based on his email and password.
- Return `None` if `user_email` is `None` or not a string
- Return `None` if user_pwd is `None` or not a string
- Return `None` if your database (file) doesn’t contain any `User` instance with email equal to `user_email` - you should use the class method `search` of the `User` to lookup the list of users based on their email. Don’t forget to test all cases: “what if there is no user in DB?”, etc.
- Return `None` if `user_pwd` is not the password of the `User` instance found - you must use the method `is_valid_password` of `User`
- Otherwise, return the `User` instance
```bash
$ cat main_5.py
#!/usr/bin/env python3
""" Main 5
"""
import uuid
from api.v1.auth.basic_auth import BasicAuth
from models.user import User

""" Create a user test """
user_email = str(uuid.uuid4())
user_clear_pwd = str(uuid.uuid4())
user = User()
user.email = user_email
user.first_name = "Bob"
user.last_name = "Dylan"
user.password = user_clear_pwd
print("New user: {}".format(user.display_name()))
user.save()

""" Retreive this user via the class BasicAuth """

a = BasicAuth()

u = a.user_object_from_credentials(None, None)
print(u.display_name() if u is not None else "None")

u = a.user_object_from_credentials(89, 98)
print(u.display_name() if u is not None else "None")

u = a.user_object_from_credentials("email@notfound.com", "pwd")
print(u.display_name() if u is not None else "None")

u = a.user_object_from_credentials(user_email, "pwd")
print(u.display_name() if u is not None else "None")

u = a.user_object_from_credentials(user_email, user_clear_pwd)
print(u.display_name() if u is not None else "None")

$
$ API_HOST=0.0.0.0 API_PORT=5000 ./main_5.py 
New user: Bob Dylan
None
None
None
None
Bob Dylan
```

### 11. Basic - Overload current_user - and BOOM!
Now, you have all pieces for having a complete Basic authentication.
Add the method `def current_user(self, request=None) -> TypeVar('User')` in the class `BasicAuth` that overloads `Auth` and retrieves the `User` instance for a request:
- You must use `authorization_header`
- You must use `extract_base64_authorization_header`
- You must use `decode_base64_authorization_header`
- You must use `extract_user_credentials`
- You must use `user_object_from_credentials`

With this update, now your API is fully protected by a Basic Authentication. Enjoy!

In the first terminal:
```bash
$ cat main_6.py
#!/usr/bin/env python3
""" Main 6
"""
import base64
from api.v1.auth.basic_auth import BasicAuth
from models.user import User

""" Create a user test """
user_email = "bob@hbtn.io"
user_clear_pwd = "H0lbertonSchool98!"
user = User()
user.email = user_email
user.password = user_clear_pwd
print("New user: {} / {}".format(user.id, user.display_name()))
user.save()

basic_clear = "{}:{}".format(user_email, user_clear_pwd)
print("Basic Base64: {}".format(base64.b64encode(basic_clear.encode('utf-8')).decode("utf-8")))

$
$ API_HOST=0.0.0.0 API_PORT=5000 ./main_6.py 
New user: 9375973a-68c7-46aa-b135-29f79e837495 / bob@hbtn.io
Basic Base64: Ym9iQGhidG4uaW86SDBsYmVydG9uU2Nob29sOTgh
$
$ API_HOST=0.0.0.0 API_PORT=5000 AUTH_TYPE=basic_auth python3 -m api.v1.app
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
....
```
In a second terminal:
```bash
$ curl "http://0.0.0.0:5000/api/v1/status"
{
  "status": "OK"
}
$ 
$ curl "http://0.0.0.0:5000/api/v1/users"
{
  "error": "Unauthorized"
}
$ 
$ curl "http://0.0.0.0:5000/api/v1/users" -H "Authorization: Test"
{
  "error": "Forbidden"
}
$ 
$ curl "http://0.0.0.0:5000/api/v1/users" -H "Authorization: Basic test"
{
  "error": "Forbidden"
}
$
$ curl "http://0.0.0.0:5000/api/v1/users" -H "Authorization: Basic Ym9iQGhidG4uaW86SDBsYmVydG9uU2Nob29sOTgh"
[
  {
    "created_at": "2017-09-25 01:55:17", 
    "email": "bob@hbtn.io", 
    "first_name": null, 
    "id": "9375973a-68c7-46aa-b135-29f79e837495", 
    "last_name": null, 
    "updated_at": "2017-09-25 01:55:17"
  }
]
```

### 12. Basic - Allow password with ":"
#advanced
Improve the method `def extract_user_credentials(self, decoded_base64_authorization_header)` to allow password with `:`.

In the first terminal:
```bash
$ cat main_100.py
#!/usr/bin/env python3
""" Main 100
"""
import base64
from api.v1.auth.basic_auth import BasicAuth
from models.user import User

""" Create a user test """
user_email = "bob100@hbtn.io"
user_clear_pwd = "H0lberton:School:98!"

user = User()
user.email = user_email
user.password = user_clear_pwd
print("New user: {}".format(user.id))
user.save()

basic_clear = "{}:{}".format(user_email, user_clear_pwd)
print("Basic Base64: {}".format(base64.b64encode(basic_clear.encode('utf-8')).decode("utf-8")))

$ 
$ API_HOST=0.0.0.0 API_PORT=5000 ./main_100.py 
New user: 5891469b-d2d5-4d33-b05d-02617d665368
Basic Base64: Ym9iMTAwQGhidG4uaW86SDBsYmVydG9uOlNjaG9vbDo5OCE=
$
$ API_HOST=0.0.0.0 API_PORT=5000 AUTH_TYPE=basic_auth python3 -m api.v1.app
 * Running on http://0.0.0.0:5000/ (Press CTRL+C to quit)
....
```
In a second terminal:
```bash
$ curl "http://0.0.0.0:5000/api/v1/status"
{
  "status": "OK"
}
$
$ curl "http://0.0.0.0:5000/api/v1/users"
{
  "error": "Unauthorized"
}
$ 
$ curl "http://0.0.0.0:5000/api/v1/users" -H "Authorization: Test"
{
  "error": "Forbidden"
}
$
$ curl "http://0.0.0.0:5000/api/v1/users" -H "Authorization: Basic test"
{
  "error": "Forbidden"
}
$
$ curl "http://0.0.0.0:5000/api/v1/users" -H "Authorization: Basic Ym9iMTAwQGhidG4uaW86SDBsYmVydG9uOlNjaG9vbDo5OCE="
[
  {
    "created_at": "2017-09-25 01:55:17", 
    "email": "bob@hbtn.io", 
    "first_name": null, 
    "id": "9375973a-68c7-46aa-b135-29f79e837495", 
    "last_name": null, 
    "updated_at": "2017-09-25 01:55:17"
  },
  {
    "created_at": "2017-09-25 01:59:42", 
    "email": "bob100@hbtn.io", 
    "first_name": null, 
    "id": "5891469b-d2d5-4d33-b05d-02617d665368", 
    "last_name": null, 
    "updated_at": "2017-09-25 01:59:42"
  }
]
```
### 13. Require auth with stars
#advanced
Improve `def require_auth(self, path, excluded_paths)` by allowing `*` at the end of excluded paths.

Example for `excluded_paths = ["/api/v1/stat*"]`:
- `/api/v1/users` will return `True`
- `/api/v1/status` will return `False`
- `/api/v1/stats` will return `False`