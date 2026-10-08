"""
TrailHire - Outdoor Equipment Rental App
=========================================

A command-line application that manages customer accounts and equipment
rental lists using Redis (a key-value database) as the data store.

Core features
-------------
* Create account (a security question is randomly assigned from a Redis set)
* Login (email + password)
* Forgot password (answer the security question, then reset the password)
* Manage rental list (add / view / remove equipment)
* Initial data loader (users + sample rental lists from CSV)

Advanced features
-----------------
* Password hashing   - PBKDF2-HMAC-SHA256 with a random per-user salt
                       (security answers are hashed the same way)
* Activity logging   - logins, failed logins, password resets and rental
                       changes are written to Redis lists
* Catalogue/inventory - equipment catalogue with daily rates and available
                       quantities, loaded from CSV; stock is reduced when an
                       item is added to a rental list and restored on removal

Usage
-----
    python trailhire.py            Run the application
    python trailhire.py --load     Reset TrailHire data and load the sample CSVs
    python trailhire.py --test     Run the automated test suite

Requirements
------------
    pip install redis              (required)
    pip install fakeredis          (optional - tests run in-memory if present)

Connection details are read from environment variables (see the
CONFIGURATION section below). By default the app connects to a local Redis.

Redis key design (all keys share the "trailhire" namespace)
-----------------------------------------------------------
    trailhire:security_questions   SET    all available security questions
    trailhire:users                SET    every registered email address
    trailhire:user:<email>         HASH   email, first_name, password (hash),
                                          security_question, security_answer
                                          (hash), created_at
    trailhire:rentals:<email>      HASH   <item_id> -> quantity
    trailhire:catalogue            SET    every equipment item_id
    trailhire:equipment:<item_id>  HASH   name, category, daily_rate,
                                          total_quantity, available
    trailhire:log:user:<email>     LIST   newest-first activity for one user
    trailhire:log:all              LIST   newest-first activity for everyone
"""

import csv
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import tempfile
import unittest
from datetime import datetime, timezone

# =============================================================================
# CONFIGURATION
# Connection details come from environment variables. The defaults connect to
# a local Redis server (localhost:6379). To use a hosted database such as
# Azure Managed Redis, set for example:
#   TRAILHIRE_REDIS_HOST=<name>.australiaeast.redis.azure.net
#   TRAILHIRE_REDIS_PORT=10000
#   TRAILHIRE_REDIS_PASSWORD=<access key>
#   TRAILHIRE_REDIS_SSL=true
#   TRAILHIRE_REDIS_CLUSTER=true
# Never write the access key into this file.
# =============================================================================
REDIS_HOST = os.getenv("TRAILHIRE_REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("TRAILHIRE_REDIS_PORT", "6379"))
REDIS_USERNAME = os.getenv("TRAILHIRE_REDIS_USERNAME", "")  # Azure: leave blank
REDIS_PASSWORD = os.getenv("TRAILHIRE_REDIS_PASSWORD", "")
REDIS_SSL = os.getenv("TRAILHIRE_REDIS_SSL", "false").lower() == "true"
# Azure Managed Redis uses the "OSS cluster" policy: data is split across
# shards, so a cluster-aware client is needed. Leave as "false" for a
# single-node Redis (e.g. a local server or Docker container).
REDIS_CLUSTER = os.getenv("TRAILHIRE_REDIS_CLUSTER", "false").lower() == "true"

KEY_PREFIX = "trailhire"            # namespace for live application data
TEST_KEY_PREFIX = "trailhire_test"  # separate namespace used by the tests

PBKDF2_ITERATIONS = 100_000         # work factor for password hashing
MIN_PASSWORD_LENGTH = 8
USER_LOG_LIMIT = 200                # entries kept per user
GLOBAL_LOG_LIMIT = 1000             # entries kept in the global log

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_CSV = os.path.join(SCRIPT_DIR, "users.csv")
CATALOGUE_CSV = os.path.join(SCRIPT_DIR, "catalogue.csv")

SECURITY_QUESTIONS = [
    "What was the name of your first pet?",
    "What city were you born in?",
    "What was the name of your primary school?",
    "What is your mother's maiden name?",
    "What was the make of your first car?",
    "What is the name of the street you grew up on?",
    "What was your childhood nickname?",
    "What is your favourite hiking trail?",
]

# Default sample data. If users.csv / catalogue.csv are missing, these are
# written to disk so the single-file submission still runs on its own.
DEFAULT_CATALOGUE_CSV = """item_id,name,category,daily_rate,quantity
TENT-2P,2-Person Dome Tent,Shelter,25.00,8
TENT-4P,4-Person Family Tent,Shelter,40.00,5
BAG-SUM,Summer Sleeping Bag (+10C),Sleeping,12.00,12
BAG-WIN,Winter Sleeping Bag (-5C),Sleeping,18.00,6
MAT-INF,Inflatable Sleeping Mat,Sleeping,8.00,15
PACK-45,45L Hiking Backpack,Packs,15.00,10
PACK-65,65L Trekking Backpack,Packs,20.00,6
STOVE-GAS,Portable Gas Stove,Cooking,10.00,9
COOK-SET,Camp Cookware Set,Cooking,7.00,10
KAYAK-1,Single Sea Kayak,Water,65.00,3
SUP-BOARD,Stand-Up Paddleboard,Water,55.00,4
LAMP-LED,Rechargeable LED Lantern,Lighting,5.00,20
"""

DEFAULT_USERS_CSV = """email,password,first_name,security_question,security_answer,rentals
alice@example.com,Alice#2026,Alice,What was the name of your first pet?,Biscuit,TENT-2P:1|BAG-SUM:2
ben@example.com,BenHikes99,Ben,What city were you born in?,Adelaide,PACK-65:1|STOVE-GAS:1|COOK-SET:1
chloe@example.com,Chloe!Paddle,Chloe,What is your favourite hiking trail?,Heysen Trail,SUP-BOARD:1
dev@example.com,DevCamp2026,Dev,What was your childhood nickname?,Dizzy,
emma@example.com,EmmaTrek#1,Emma,What is the name of the street you grew up on?,King William Street,TENT-4P:1|MAT-INF:4|LAMP-LED:2
"""


# =============================================================================
# DATABASE CONNECTION
# =============================================================================
def connect_redis():
    """Return a Redis client using the configured connection details.

    decode_responses=True makes Redis return str instead of bytes, which keeps
    the rest of the code simple.

    Azure splits the data across shards and tells the client where each shard
    is using its IP address (e.g. 4.237.x.x:8500). The TLS certificate only
    matches the hostname, so connecting by IP fails the security check. The
    address_remap function below keeps the shard's port but swaps the IP back
    to the hostname, so every connection is still fully verified.
    """
    import redis  # imported here so the tests can run without it (fakeredis)

    options = dict(
        host=REDIS_HOST,
        port=REDIS_PORT,
        username=REDIS_USERNAME or None,
        password=REDIS_PASSWORD or None,
        ssl=REDIS_SSL,
        decode_responses=True,
        socket_timeout=10,
    )
    if REDIS_CLUSTER:
        from redis.cluster import RedisCluster
        return RedisCluster(
            address_remap=lambda address: (REDIS_HOST, address[1]),
            **options)
    return redis.Redis(**options)


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def now_iso():
    """Current UTC time as an ISO-8601 string (used for logs/timestamps)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def normalise_email(email):
    """Emails are case-insensitive, so store and look them up in lowercase."""
    return (email or "").strip().lower()


def normalise_answer(answer):
    """Make security answers forgiving of case and extra spaces."""
    return " ".join((answer or "").lower().split())


def hash_secret(secret, salt_hex=None, iterations=PBKDF2_ITERATIONS):
    """Hash a password or security answer with PBKDF2-HMAC-SHA256.

    Returns a self-describing string: pbkdf2_sha256$<iterations>$<salt>$<hash>
    A new random 16-byte salt is generated unless one is supplied (the salt is
    supplied when verifying an existing hash).
    """
    if salt_hex is None:
        salt_hex = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", secret.encode("utf-8"), bytes.fromhex(salt_hex), iterations
    ).hex()
    return f"pbkdf2_sha256${iterations}${salt_hex}${digest}"


def verify_secret(secret, stored_hash):
    """Check a plain-text secret against a stored hash in constant time."""
    try:
        algorithm, iterations, salt_hex, _ = stored_hash.split("$")
    except (ValueError, AttributeError):
        return False
    if algorithm != "pbkdf2_sha256":
        return False
    candidate = hash_secret(secret, salt_hex, int(iterations))
    return hmac.compare_digest(candidate, stored_hash)


def ensure_sample_files():
    """Write the default sample CSV files if they do not already exist."""
    for path, content in ((CATALOGUE_CSV, DEFAULT_CATALOGUE_CSV),
                          (USERS_CSV, DEFAULT_USERS_CSV)):
        if not os.path.exists(path):
            with open(path, "w", newline="", encoding="utf-8") as f:
                f.write(content)
            print(f"Created sample file: {os.path.basename(path)}")


def parse_rentals_field(text):
    """Turn 'TENT-2P:1|BAG-SUM:2' into [('TENT-2P', 1), ('BAG-SUM', 2)]."""
    items = []
    for part in (text or "").split("|"):
        part = part.strip()
        if not part:
            continue
        item_id, _, qty = part.partition(":")
        items.append((item_id.strip().upper(), int(qty) if qty else 1))
    return items


# =============================================================================
# KEY NAMING
# =============================================================================
class Keys:
    """Builds every Redis key name in one place so the design is consistent.

    The prefix lets the live app and the automated tests use separate
    namespaces in the same database without touching each other's data.
    """

    def __init__(self, prefix=KEY_PREFIX):
        self.prefix = prefix

    def questions(self):
        return f"{self.prefix}:security_questions"

    def users(self):
        return f"{self.prefix}:users"

    def user(self, email):
        return f"{self.prefix}:user:{email}"

    def rentals(self, email):
        return f"{self.prefix}:rentals:{email}"

    def catalogue(self):
        return f"{self.prefix}:catalogue"

    def equipment(self, item_id):
        return f"{self.prefix}:equipment:{item_id}"

    def user_log(self, email):
        return f"{self.prefix}:log:user:{email}"

    def global_log(self):
        return f"{self.prefix}:log:all"


# =============================================================================
# APPLICATION / DATA LAYER
# All reading and writing to Redis happens in this class. The menus below only
# collect input and print results, which also makes the logic easy to test.
# =============================================================================
class TrailHireService:
    def __init__(self, redis_client, prefix=KEY_PREFIX):
        self.r = redis_client
        self.k = Keys(prefix)

    # ---------------------------------------------------------------- setup
    def seed_security_questions(self):
        """Store the security questions in a Redis SET (safe to re-run)."""
        self.r.sadd(self.k.questions(), *SECURITY_QUESTIONS)

    def random_security_question(self):
        """Pick a random question using SRANDMEMBER."""
        question = self.r.srandmember(self.k.questions())
        if question is None:  # set was empty - seed it and try again
            self.seed_security_questions()
            question = self.r.srandmember(self.k.questions())
        return question

    def reset_namespace(self):
        """Delete every key in this service's namespace."""
        keys = list(self.r.scan_iter(match=f"{self.k.prefix}:*"))
        pipe = self.r.pipeline(transaction=False)
        for key in keys:  # one DEL per key works on clustered and single nodes
            pipe.delete(key)
        pipe.execute()
        return len(keys)

    # ------------------------------------------------------------- logging
    def log(self, email, action, detail=""):
        """Record an activity entry (newest first, capped with LTRIM)."""
        entry = json.dumps({"time": now_iso(), "user": email,
                            "action": action, "detail": detail})
        # A pipeline sends all the commands in one network round trip.
        pipe = self.r.pipeline(transaction=False)
        pipe.lpush(self.k.global_log(), entry)
        pipe.ltrim(self.k.global_log(), 0, GLOBAL_LOG_LIMIT - 1)
        # Only keep a per-user log for real accounts, so failed logins with
        # made-up emails cannot create unlimited keys.
        if email and self.user_exists(email):
            pipe.lpush(self.k.user_log(email), entry)
            pipe.ltrim(self.k.user_log(email), 0, USER_LOG_LIMIT - 1)
        pipe.execute()

    def get_log(self, email, count=10):
        """Return the most recent activity entries for a user as dicts."""
        raw = self.r.lrange(self.k.user_log(normalise_email(email)), 0, count - 1)
        return [json.loads(item) for item in raw]

    # ------------------------------------------------------------ accounts
    def user_exists(self, email):
        return bool(self.r.exists(self.k.user(normalise_email(email))))

    def create_account(self, email, password, first_name, security_answer,
                       question=None):
        """Validate and store a new account. Returns the assigned question.

        Raises ValueError with a user-friendly message if anything is invalid.
        """
        email = normalise_email(email)
        first_name = (first_name or "").strip()

        if not EMAIL_PATTERN.match(email):
            raise ValueError("Please enter a valid email address.")
        if len(password or "") < MIN_PASSWORD_LENGTH:
            raise ValueError(
                f"Password must be at least {MIN_PASSWORD_LENGTH} characters.")
        if not first_name:
            raise ValueError("First name cannot be empty.")
        if not normalise_answer(security_answer):
            raise ValueError("Security answer cannot be empty.")

        if question is None:
            question = self.random_security_question()
        elif not self.r.sismember(self.k.questions(), question):
            raise ValueError("Unknown security question.")

        key = self.k.user(email)
        # HSETNX only writes if the field does not exist, so two people
        # registering the same email at the same moment cannot both succeed.
        if not self.r.hsetnx(key, "email", email):
            raise ValueError("An account with that email already exists.")

        self.r.hset(key, mapping={
            "first_name": first_name,
            "password": hash_secret(password),
            "security_question": question,
            "security_answer": hash_secret(normalise_answer(security_answer)),
            "created_at": now_iso(),
        })
        self.r.sadd(self.k.users(), email)
        self.log(email, "ACCOUNT_CREATED")
        return question

    def login(self, email, password):
        """Return the user's first name if the credentials are valid, else None."""
        email = normalise_email(email)
        stored = self.r.hget(self.k.user(email), "password")
        if stored and verify_secret(password or "", stored):
            self.log(email, "LOGIN_SUCCESS")
            return self.r.hget(self.k.user(email), "first_name")
        self.log(email, "LOGIN_FAILED",
                 "unknown account" if stored is None else "wrong password")
        return None

    def get_security_question(self, email):
        return self.r.hget(self.k.user(normalise_email(email)), "security_question")

    def check_security_answer(self, email, answer):
        """True if the answer matches; failed attempts are logged."""
        email = normalise_email(email)
        stored = self.r.hget(self.k.user(email), "security_answer")
        if stored and verify_secret(normalise_answer(answer), stored):
            return True
        self.log(email, "PASSWORD_RESET_FAILED", "wrong security answer")
        return False

    def reset_password(self, email, answer, new_password):
        """Reset a password after re-checking the security answer.

        Returns (success, message).
        """
        email = normalise_email(email)
        if not self.user_exists(email):
            return False, "No account found for that email."
        if not self.check_security_answer(email, answer):
            return False, "Security answer is incorrect."
        if len(new_password or "") < MIN_PASSWORD_LENGTH:
            return False, (f"Password must be at least "
                           f"{MIN_PASSWORD_LENGTH} characters.")
        self.r.hset(self.k.user(email), "password", hash_secret(new_password))
        self.log(email, "PASSWORD_RESET")
        return True, "Password updated. You can now log in."

    # ----------------------------------------------------------- catalogue
    def add_catalogue_item(self, item_id, name, category, daily_rate, quantity):
        """Create or replace one equipment item in the catalogue."""
        item_id = item_id.strip().upper()
        self.r.hset(self.k.equipment(item_id), mapping={
            "name": name.strip(),
            "category": category.strip(),
            "daily_rate": f"{float(daily_rate):.2f}",
            "total_quantity": int(quantity),
            "available": int(quantity),
        })
        self.r.sadd(self.k.catalogue(), item_id)

    def get_item(self, item_id):
        data = self.r.hgetall(self.k.equipment(item_id.strip().upper()))
        return data or None

    def list_catalogue(self):
        """All equipment as a list of dicts, sorted by category then name."""
        item_ids = list(self.r.smembers(self.k.catalogue()))
        items = []
        for item_id, data in zip(item_ids, self._get_equipment_many(item_ids)):
            if data:
                data["item_id"] = item_id
                data["available"] = int(data["available"])
                items.append(data)
        return sorted(items, key=lambda i: (i["category"], i["name"]))

    def _get_equipment_many(self, item_ids):
        """Fetch several equipment hashes in one round trip (pipeline)."""
        pipe = self.r.pipeline(transaction=False)
        for item_id in item_ids:
            pipe.hgetall(self.k.equipment(item_id))
        return pipe.execute()

    # ------------------------------------------------------------- rentals
    def add_rental(self, email, item_id, quantity=1):
        """Add equipment to a user's rental list and reduce available stock.

        HINCRBY is atomic, so stock is decremented first. If that takes it
        below zero, the change is reversed and the request is rejected. This
        prevents two customers from renting the last item at the same time.
        Returns (success, message).
        """
        email = normalise_email(email)
        item_id = (item_id or "").strip().upper()
        if quantity < 1:
            return False, "Quantity must be at least 1."
        item_key = self.k.equipment(item_id)
        if not self.r.exists(item_key):
            return False, f"No equipment found with ID '{item_id}'."

        remaining = self.r.hincrby(item_key, "available", -quantity)
        if remaining < 0:
            self.r.hincrby(item_key, "available", quantity)  # undo
            return False, (f"Only {remaining + quantity} available - "
                           f"cannot rent {quantity}.")

        new_qty = self.r.hincrby(self.k.rentals(email), item_id, quantity)
        name = self.r.hget(item_key, "name")
        self.log(email, "RENTAL_ADDED", f"{item_id} x{quantity}")
        return True, f"Added {quantity} x {name} (now {new_qty} in your list)."

    def remove_rental(self, email, item_id, quantity=None):
        """Remove some (or all, if quantity is None) of an item and restock it.

        Returns (success, message).
        """
        email = normalise_email(email)
        item_id = (item_id or "").strip().upper()
        rental_key = self.k.rentals(email)
        current = self.r.hget(rental_key, item_id)
        if current is None:
            return False, f"'{item_id}' is not in your rental list."
        current = int(current)
        if quantity is not None and quantity < 1:
            return False, "Quantity must be at least 1."

        if quantity is None or quantity >= current:
            returned = current
            self.r.hdel(rental_key, item_id)
        else:
            returned = quantity
            self.r.hincrby(rental_key, item_id, -quantity)

        if self.r.exists(self.k.equipment(item_id)):
            self.r.hincrby(self.k.equipment(item_id), "available", returned)
        self.log(email, "RENTAL_REMOVED", f"{item_id} x{returned}")
        return True, f"Removed {returned} x {item_id} from your list."

    def get_rentals(self, email):
        """A user's rental list with names, prices and line totals."""
        rentals = self.r.hgetall(self.k.rentals(normalise_email(email)))
        details = self._get_equipment_many(list(rentals))
        rows = []
        for (item_id, qty), item in zip(rentals.items(), details):
            rate = float(item.get("daily_rate", 0))
            qty = int(qty)
            rows.append({
                "item_id": item_id,
                "name": item.get("name", "(no longer in catalogue)"),
                "quantity": qty,
                "daily_rate": rate,
                "line_total": round(rate * qty, 2),
            })
        return sorted(rows, key=lambda r: r["item_id"])

    # ---------------------------------------------------------- CSV loaders
    def load_catalogue_csv(self, path):
        """Load equipment from CSV. Returns the number of items loaded."""
        count = 0
        with open(path, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                self.add_catalogue_item(row["item_id"], row["name"],
                                        row["category"], row["daily_rate"],
                                        row["quantity"])
                count += 1
        return count

    def load_users_csv(self, path):
        """Load users and their starting rental lists from CSV.

        Existing accounts are skipped, so the loader never double-counts
        stock. Returns (created, skipped, warnings).
        """
        created, skipped, warnings = 0, 0, []
        with open(path, newline="", encoding="utf-8") as f:
            for line_no, row in enumerate(csv.DictReader(f), start=2):
                question = (row.get("security_question") or "").strip() or None
                if question:
                    # Allow questions in the file even if not in the default list
                    self.r.sadd(self.k.questions(), question)
                try:
                    self.create_account(row["email"], row["password"],
                                        row["first_name"],
                                        row["security_answer"], question)
                    created += 1
                except ValueError as err:
                    skipped += 1
                    warnings.append(f"Line {line_no}: {row.get('email')} - {err}")
                    continue
                for item_id, qty in parse_rentals_field(row.get("rentals")):
                    ok, msg = self.add_rental(row["email"], item_id, qty)
                    if not ok:
                        warnings.append(f"Line {line_no}: {msg}")
        return created, skipped, warnings

    def load_sample_data(self, users_csv=USERS_CSV, catalogue_csv=CATALOGUE_CSV):
        """Clear the namespace, then load questions, catalogue and users.

        The catalogue must be loaded before users, because loading a user's
        rental list reduces catalogue stock.
        """
        self.reset_namespace()
        self.seed_security_questions()
        items = self.load_catalogue_csv(catalogue_csv)
        created, skipped, warnings = self.load_users_csv(users_csv)
        return items, created, skipped, warnings


# =============================================================================
# COMMAND-LINE INTERFACE
# =============================================================================
def ask(prompt):
    return input(prompt).strip()


def ask_password(prompt="Password: "):
    """Hide the password while typing where the terminal supports it."""
    try:
        return getpass.getpass(prompt)
    except Exception:
        return input(prompt)


def ask_int(prompt, default=None):
    """Read a positive whole number; blank returns the default."""
    while True:
        text = ask(prompt)
        if not text and default is not None:
            return default
        if text.isdigit() and int(text) > 0:
            return int(text)
        print("Please enter a whole number greater than 0.")


def print_catalogue(service):
    items = service.list_catalogue()
    if not items:
        print("\nThe catalogue is empty. Load sample data from the main menu.")
        return
    print(f"\n{'ID':<11}{'Name':<30}{'Category':<10}{'$/day':>8}{'Avail':>7}")
    print("-" * 66)
    for i in items:
        print(f"{i['item_id']:<11}{i['name'][:29]:<30}{i['category']:<10}"
              f"{float(i['daily_rate']):>8.2f}{i['available']:>7}")


def print_rentals(service, email):
    rows = service.get_rentals(email)
    if not rows:
        print("\nYour rental list is empty.")
        return
    print(f"\n{'ID':<11}{'Name':<30}{'Qty':>4}{'$/day':>8}{'Total':>9}")
    print("-" * 62)
    for r in rows:
        print(f"{r['item_id']:<11}{r['name'][:29]:<30}{r['quantity']:>4}"
              f"{r['daily_rate']:>8.2f}{r['line_total']:>9.2f}")
    total = sum(r["line_total"] for r in rows)
    print("-" * 62)
    print(f"{'Total cost per day:':<53}{total:>9.2f}")


def create_account_menu(service):
    print("\n--- Create Account ---")
    email = ask("Email: ")
    if service.user_exists(email):
        print("An account with that email already exists.")
        return
    first_name = ask("First name: ")
    password = ask_password(f"Password (min {MIN_PASSWORD_LENGTH} characters): ")
    if password != ask_password("Confirm password: "):
        print("Passwords do not match.")
        return
    question = service.random_security_question()
    print(f"Your security question is: {question}")
    answer = ask("Answer: ")
    try:
        service.create_account(email, password, first_name, answer, question)
        print(f"Account created. Welcome to TrailHire, {first_name}!")
    except ValueError as err:
        print(f"Could not create account: {err}")


def forgot_password_menu(service):
    print("\n--- Forgot Password ---")
    email = ask("Email: ")
    question = service.get_security_question(email)
    if not question:
        print("No account found for that email.")
        return
    print(f"Security question: {question}")
    answer = ask("Answer: ")
    if not service.check_security_answer(email, answer):
        print("Security answer is incorrect.")
        return
    new_password = ask_password(f"New password (min {MIN_PASSWORD_LENGTH} characters): ")
    if new_password != ask_password("Confirm new password: "):
        print("Passwords do not match.")
        return
    _, message = service.reset_password(email, answer, new_password)
    print(message)


def customer_menu(service, email, first_name):
    """Menu shown after a successful login."""
    email = normalise_email(email)
    while True:
        print(f"\n=== {first_name}'s TrailHire Account ===")
        print("1. View equipment catalogue")
        print("2. Add equipment to rental list")
        print("3. View my rental list")
        print("4. Remove equipment from rental list")
        print("5. View my recent activity")
        print("6. Logout (return to main menu)")
        choice = ask("Choose an option: ")

        if choice == "1":
            print_catalogue(service)
        elif choice == "2":
            print_catalogue(service)
            item_id = ask("\nEquipment ID to add: ")
            qty = ask_int("Quantity [1]: ", default=1)
            _, message = service.add_rental(email, item_id, qty)
            print(message)
        elif choice == "3":
            print_rentals(service, email)
        elif choice == "4":
            print_rentals(service, email)
            item_id = ask("\nEquipment ID to remove: ")
            qty_text = ask("Quantity to remove (blank = all): ")
            qty = int(qty_text) if qty_text.isdigit() else None
            _, message = service.remove_rental(email, item_id, qty)
            print(message)
        elif choice == "5":
            print()
            for entry in service.get_log(email):
                print(f"{entry['time']}  {entry['action']:<22}{entry['detail']}")
        elif choice == "6":
            service.log(email, "LOGOUT")
            print("Logged out.")
            return
        else:
            print("Invalid option, please try again.")


def run_cli():
    """Main menu loop."""
    try:
        client = connect_redis()
        client.ping()
    except Exception as err:
        print(f"Could not connect to Redis at {REDIS_HOST}:{REDIS_PORT} - {err}")
        print("Check the CONFIGURATION section at the top of this file.")
        return

    service = TrailHireService(client)
    service.seed_security_questions()

    while True:
        print("\n========== TrailHire ==========")
        print("1. Create account")
        print("2. Login")
        print("3. Forgot password")
        print("4. Load sample data (resets TrailHire data)")
        print("5. Exit")
        choice = ask("Choose an option: ")

        if choice == "1":
            create_account_menu(service)
        elif choice == "2":
            email = ask("Email: ")
            first_name = service.login(email, ask_password())
            if first_name:
                print(f"Welcome back, {first_name}!")
                customer_menu(service, email, first_name)
            else:
                print("Invalid email or password.")
        elif choice == "3":
            forgot_password_menu(service)
        elif choice == "4":
            if ask("This deletes all TrailHire data. Continue? (y/n): ").lower() == "y":
                load_sample_data_cli(service)
        elif choice == "5":
            print("Thanks for using TrailHire. Goodbye!")
            return
        else:
            print("Invalid option, please try again.")


def load_sample_data_cli(service):
    ensure_sample_files()
    items, created, skipped, warnings = service.load_sample_data()
    print(f"Loaded {items} catalogue items and {created} users "
          f"({skipped} skipped).")
    for w in warnings:
        print(f"  Warning: {w}")


# =============================================================================
# AUTOMATED TESTS
# Run with:  python trailhire.py --test
# The tests use the separate "trailhire_test" namespace and clean up after
# themselves, so they never change the live TrailHire data. If fakeredis is
# installed they run fully in memory instead.
# =============================================================================
def make_test_client():
    try:
        import fakeredis
        return fakeredis.FakeRedis(decode_responses=True)
    except ImportError:
        return connect_redis()


class TrailHireTests(unittest.TestCase):
    PASSWORD = "Summit#2026"

    def setUp(self):
        self.svc = TrailHireService(make_test_client(), prefix=TEST_KEY_PREFIX)
        self.svc.reset_namespace()
        self.svc.seed_security_questions()
        self.svc.add_catalogue_item("TENT-2P", "2-Person Dome Tent", "Shelter", 25, 3)
        self.svc.add_catalogue_item("STOVE-GAS", "Portable Gas Stove", "Cooking", 10, 5)
        self.q = self.svc.create_account("test@example.com", self.PASSWORD,
                                         "Tess", "Biscuit")

    def tearDown(self):
        self.svc.reset_namespace()

    # --- Database design ---------------------------------------------------
    def test_01_security_questions_stored_in_set(self):
        stored = self.svc.r.smembers(self.svc.k.questions())
        self.assertEqual(set(SECURITY_QUESTIONS), stored)

    def test_02_account_gets_random_question_from_set(self):
        self.assertIn(self.q, SECURITY_QUESTIONS)
        self.assertEqual(self.q, self.svc.get_security_question("test@example.com"))

    def test_03_password_and_answer_are_hashed(self):
        data = self.svc.r.hgetall(self.svc.k.user("test@example.com"))
        self.assertNotIn(self.PASSWORD, data.values())
        self.assertNotIn("biscuit", data.values())
        self.assertTrue(data["password"].startswith("pbkdf2_sha256$"))

    def test_04_same_password_gives_different_hashes(self):
        self.svc.create_account("twin@example.com", self.PASSWORD, "Twin", "x")
        h1 = self.svc.r.hget(self.svc.k.user("test@example.com"), "password")
        h2 = self.svc.r.hget(self.svc.k.user("twin@example.com"), "password")
        self.assertNotEqual(h1, h2)

    # --- Create account ----------------------------------------------------
    def test_05_duplicate_email_rejected(self):
        with self.assertRaises(ValueError):
            self.svc.create_account("TEST@example.com", "Another#123", "Dup", "a")

    def test_06_invalid_input_rejected(self):
        with self.assertRaises(ValueError):
            self.svc.create_account("not-an-email", self.PASSWORD, "A", "a")
        with self.assertRaises(ValueError):
            self.svc.create_account("short@example.com", "abc", "A", "a")
        with self.assertRaises(ValueError):
            self.svc.create_account("noname@example.com", self.PASSWORD, " ", "a")

    # --- Login -------------------------------------------------------------
    def test_07_login_success(self):
        self.assertEqual("Tess", self.svc.login("test@example.com", self.PASSWORD))

    def test_08_login_email_case_insensitive(self):
        self.assertEqual("Tess", self.svc.login(" Test@Example.COM ", self.PASSWORD))

    def test_09_login_wrong_password(self):
        self.assertIsNone(self.svc.login("test@example.com", "wrong-pass"))

    def test_10_login_unknown_user(self):
        self.assertIsNone(self.svc.login("nobody@example.com", self.PASSWORD))

    # --- Forgot password ---------------------------------------------------
    def test_11_reset_with_wrong_answer_fails(self):
        ok, _ = self.svc.reset_password("test@example.com", "Rex", "NewPass#2026")
        self.assertFalse(ok)
        self.assertEqual("Tess", self.svc.login("test@example.com", self.PASSWORD))

    def test_12_reset_with_correct_answer(self):
        ok, _ = self.svc.reset_password("test@example.com", "  BISCUIT ", "NewPass#2026")
        self.assertTrue(ok)
        self.assertIsNone(self.svc.login("test@example.com", self.PASSWORD))
        self.assertEqual("Tess", self.svc.login("test@example.com", "NewPass#2026"))

    def test_13_reset_rejects_short_password(self):
        ok, _ = self.svc.reset_password("test@example.com", "Biscuit", "short")
        self.assertFalse(ok)

    # --- Rental list + inventory -------------------------------------------
    def test_14_add_rental_reduces_stock(self):
        ok, _ = self.svc.add_rental("test@example.com", "tent-2p", 2)
        self.assertTrue(ok)
        self.assertEqual("1", self.svc.get_item("TENT-2P")["available"])
        self.assertEqual(2, self.svc.get_rentals("test@example.com")[0]["quantity"])

    def test_15_cannot_rent_more_than_available(self):
        ok, _ = self.svc.add_rental("test@example.com", "TENT-2P", 4)
        self.assertFalse(ok)
        self.assertEqual("3", self.svc.get_item("TENT-2P")["available"])
        self.assertEqual([], self.svc.get_rentals("test@example.com"))

    def test_16_unknown_item_or_bad_quantity_rejected(self):
        self.assertFalse(self.svc.add_rental("test@example.com", "CANOE-9", 1)[0])
        self.assertFalse(self.svc.add_rental("test@example.com", "TENT-2P", 0)[0])

    def test_17_view_rentals_with_totals(self):
        self.svc.add_rental("test@example.com", "TENT-2P", 1)
        self.svc.add_rental("test@example.com", "STOVE-GAS", 2)
        rows = self.svc.get_rentals("test@example.com")
        self.assertEqual(["STOVE-GAS", "TENT-2P"], [r["item_id"] for r in rows])
        self.assertEqual(45.0, sum(r["line_total"] for r in rows))

    def test_18_partial_and_full_removal_restock(self):
        self.svc.add_rental("test@example.com", "STOVE-GAS", 3)
        self.assertTrue(self.svc.remove_rental("test@example.com", "STOVE-GAS", 1)[0])
        self.assertEqual("3", self.svc.get_item("STOVE-GAS")["available"])
        self.assertTrue(self.svc.remove_rental("test@example.com", "STOVE-GAS")[0])
        self.assertEqual("5", self.svc.get_item("STOVE-GAS")["available"])
        self.assertEqual([], self.svc.get_rentals("test@example.com"))

    def test_19_remove_item_not_in_list(self):
        self.assertFalse(self.svc.remove_rental("test@example.com", "TENT-2P")[0])

    # --- Activity logging --------------------------------------------------
    def test_20_actions_are_logged(self):
        self.svc.login("test@example.com", "wrong-pass")
        self.svc.login("test@example.com", self.PASSWORD)
        self.svc.add_rental("test@example.com", "TENT-2P", 1)
        self.svc.remove_rental("test@example.com", "TENT-2P")
        actions = [e["action"] for e in self.svc.get_log("test@example.com")]
        self.assertEqual(["RENTAL_REMOVED", "RENTAL_ADDED", "LOGIN_SUCCESS",
                          "LOGIN_FAILED", "ACCOUNT_CREATED"], actions)

    # --- CSV loader --------------------------------------------------------
    def test_21_csv_loader(self):
        with tempfile.TemporaryDirectory() as tmp:
            users = os.path.join(tmp, "users.csv")
            catalogue = os.path.join(tmp, "catalogue.csv")
            with open(users, "w", encoding="utf-8") as f:
                f.write(DEFAULT_USERS_CSV)
            with open(catalogue, "w", encoding="utf-8") as f:
                f.write(DEFAULT_CATALOGUE_CSV)
            items, created, skipped, warnings = self.svc.load_sample_data(users, catalogue)
            self.assertEqual((12, 5, 0, []), (items, created, skipped, warnings))
            self.assertEqual("Alice", self.svc.login("alice@example.com", "Alice#2026"))
            alice = {r["item_id"]: r["quantity"]
                     for r in self.svc.get_rentals("alice@example.com")}
            self.assertEqual({"TENT-2P": 1, "BAG-SUM": 2}, alice)
            self.assertEqual("10", self.svc.get_item("BAG-SUM")["available"])  # 12 - 2

            # Loading the same users again must skip them and not touch stock
            created_again, skipped_again, _ = self.svc.load_users_csv(users)
            self.assertEqual((0, 5), (created_again, skipped_again))
            self.assertEqual("10", self.svc.get_item("BAG-SUM")["available"])


class _Tee:
    """Write test output to the screen and to test_results.txt together."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, text):
        for s in self.streams:
            s.write(text)

    def flush(self):
        for s in self.streams:
            s.flush()


def run_tests():
    results_path = os.path.join(SCRIPT_DIR, "test_results.txt")
    with open(results_path, "w", encoding="utf-8") as f:
        f.write(f"TrailHire automated test run - {now_iso()}\n\n")
        suite = unittest.defaultTestLoader.loadTestsFromTestCase(TrailHireTests)
        result = unittest.TextTestRunner(stream=_Tee(sys.stdout, f),
                                         verbosity=2).run(suite)
    print(f"\nResults saved to {results_path}")
    return result.wasSuccessful()


# =============================================================================
# ENTRY POINT
# =============================================================================
if __name__ == "__main__":
    if "--test" in sys.argv:
        sys.exit(0 if run_tests() else 1)
    elif "--load" in sys.argv:
        svc = TrailHireService(connect_redis())
        load_sample_data_cli(svc)
    else:
        run_cli()
