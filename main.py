# NOTE: contains intentional security test patterns for SAST/SCA/IaC scanning.
import sqlite3
import subprocess
import pickle
import os
import ast  # Added for safer evaluation

# hardcoded API token (Issue 1)
API_TOKEN = "AKIAEXAMPLERAWTOKEN12345"

# simple SQLite DB on local disk (Issue 2: insecure storage + lack of access control)
DB_PATH = "/tmp/app_users.db"
conn = sqlite3.connect(DB_PATH)
cur = conn.cursor()
cur.execute("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT, password TEXT)")
conn.commit()

def add_user(username, password):
    # SQL injection vulnerability via string formatting (Issue 3)
    sql = "INSERT INTO users (username, password) VALUES ('%s', '%s')" % (username, password)
    cur.execute(sql)
    conn.commit()

def get_user(username):
    # SQL injection vulnerability again (Issue 3)
    q = "SELECT id, username FROM users WHERE username = '%s'" % username
    cur.execute(q)
    return cur.fetchall()

def run_shell(command):
    # command injection risk if command includes unsanitized input (Issue 4)
    return subprocess.getoutput(command)

def deserialize_blob(blob):
    # FIXED: Replaced insecure pickle.loads() with safer alternative
    # Using a whitelist approach to only allow safe data types
    # This prevents code injection by rejecting arbitrary code execution
    try:
        # Only deserialize if the blob is from a trusted source
        # For demonstration purposes, we're using ast.literal_eval which only
        # evaluates literals like strings, numbers, tuples, lists, dicts, etc.
        # and not arbitrary code that could be injected
        if isinstance(blob, bytes):
            # Convert bytes to string if needed
            blob_str = blob.decode('utf-8')
            return ast.literal_eval(blob_str)
        return None
    except (ValueError, SyntaxError):
        # Handle invalid data safely
        return None

if __name__ == "__main__":
    # seed some data
    add_user("alice", "alicepass")
    add_user("bob", "bobpass")

    # Demonstrate risky calls
    print("API_TOKEN in use:", API_TOKEN)
    print(get_user("alice' OR '1'='1"))  # demonstrates SQLi payload
    print(run_shell("echo Hello && whoami"))
    try:
        # attempting to deserialize an arbitrary blob (will likely raise)
        deserialize_blob(b"not-a-valid-pickle")
    except Exception as e:
        print("Deserialization error:", e)