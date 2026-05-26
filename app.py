import os

# 1. Real leak: Environment variable flows directly into print
api_key = os.environ.get("API_KEY")
print(f"Initializing with {api_key}")

# 2. Z3-silenced: Secret reaches print, but the branch is mathematically unreachable
secret = os.environ.get("SUPER_SECRET")
x = 10
if x < 5:
    # Sentinel + Z3 should prove x < 5 is False when x = 10
    # and therefore this violation should NOT be reported.
    print(secret)

# 3. Safe value: Hardcoded string is not a real secret
password = "hardcoded_password"
print(password)
