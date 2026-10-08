# TrailHire: Design Notes

## Assumptions

- **The username is the email.** Emails are trimmed and stored in lowercase, so `Alice@Example.com` and `alice@example.com` are the same account.
- **A rental list is a shortlist, not a booking.** It holds equipment IDs and quantities. Rental dates and payment are out of scope, so cost is shown per day.
- **Adding an item reserves stock.** Available quantity drops when an item is added and comes back when it's removed.
- **Each user has one security question,** chosen at random when the account is created. Answers ignore case and extra spaces.
- **Passwords must be at least 8 characters,** and that also applies to resets.
- **The sample loader is for testing.** It clears TrailHire data first and loads the catalogue before users, because loading users' rental lists reduces stock.

## Key design

| Key pattern | Type | Purpose |
|-------------|------|---------|
| `trailhire:security_questions` | SET | All questions; `SRANDMEMBER` picks one at random |
| `trailhire:user:<email>` | HASH | Account fields; password and answer are stored as hashes |
| `trailhire:users` | SET | All emails, so accounts can be listed without scanning keys |
| `trailhire:rentals:<email>` | HASH | Equipment ID → quantity |
| `trailhire:catalogue` | SET | All equipment IDs |
| `trailhire:equipment:<id>` | HASH | name, category, daily_rate, total_quantity, available |
| `trailhire:log:user:<email>` | LIST | Per-user activity, newest first, capped at 200 |
| `trailhire:log:all` | LIST | Global activity, newest first, capped at 1,000 |

The `trailhire:` prefix keeps keys readable and avoids collisions with other data. The tests use a separate `trailhire_test:` prefix so they never touch live data.

## Security decisions

- **PBKDF2-HMAC-SHA256** from Python's built-in `hashlib`, with a random 16-byte salt and 100,000 iterations, so no extra package is needed. Hashes are stored as `pbkdf2_sha256$<iterations>$<salt>$<hash>`, which means the work factor can be raised later without breaking existing hashes.
- **`hmac.compare_digest`** compares hashes in constant time, which prevents timing attacks.
- **Security answers are normalised** (lowercased, with spaces collapsed) before they're hashed.
- **Failed logins for unknown emails** are written only to the global log, so nobody can create unlimited per-user keys.

## Pseudocode

**Create account**
```
READ email, first name, password, confirm password
IF email invalid OR password < 8 chars OR name blank OR passwords differ: SHOW error, STOP
question ← SRANDMEMBER security_questions; SHOW question; READ answer
IF HSETNX user:<email> email fails: SHOW "account exists", STOP
HSET user:<email> first_name, hash(password), question, hash(answer)
SADD users email; LOG ACCOUNT_CREATED
```

**Login**
```
READ email, password
stored ← HGET user:<email> password
IF stored exists AND verify(password, stored): LOG LOGIN_SUCCESS, OPEN customer menu
ELSE: LOG LOGIN_FAILED, SHOW "invalid email or password"
```

**Forgot password**
```
READ email; question ← HGET user:<email> security_question
IF no question: SHOW "no account", STOP
SHOW question; READ answer
IF NOT verify(normalise(answer), stored answer hash): LOG failure, STOP
READ new password twice; IF valid: HSET password hash(new); LOG PASSWORD_RESET
```

**Add equipment**
```
READ item ID, quantity
IF item not in catalogue OR quantity < 1: SHOW error, STOP
remaining ← HINCRBY equipment:<id> available -quantity
IF remaining < 0: HINCRBY equipment:<id> available +quantity (undo), SHOW "not enough stock", STOP
HINCRBY rentals:<email> <id> quantity; LOG RENTAL_ADDED
```

**Remove equipment**
```
READ item ID, quantity (blank = all)
current ← HGET rentals:<email> <id>; IF none: SHOW error, STOP
IF quantity blank OR quantity ≥ current: HDEL item ELSE HINCRBY item -quantity
HINCRBY equipment:<id> available +returned; LOG RENTAL_REMOVED
```

## Hosting

The database ran on **Azure Managed Redis** in Australia East, close to the Adelaide-based users. Azure requires TLS on port 10000 and uses the OSS cluster policy, so the app connects with `RedisCluster` and remaps each shard's IP back to the hostname to keep TLS verification working. Multi-key work goes through pipelines to cut network round trips.
