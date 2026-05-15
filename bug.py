import os

# real env-var secret → should flag
api_key = os.environ.get("API_KEY")
print(api_key)

# hardcoded literal → safe, no flag
password = "abc"
print(password)

# propagation chain → flags via Derived
token = os.environ.get("TOKEN")
copy = token
log(copy)

# file source → flags
contents = open("config").read()
send(contents)

# Z3: dead code → safe despite secret reaching sink
debug_key = os.environ.get("DEBUG")
if False:
    print(debug_key)

# Z3: impossible compound → safe
secret_val = os.environ.get("S")
x = 5
if x > 10 and x < 100:
    print(secret_val)

# Z3: reachable path → flags
y = 5
leak = os.environ.get("LEAK")
if y > 0:
    print(leak)

# function-param taint via IR
def handler(api_key):
    print(api_key)

# reorder: same name, two states
import os
v = "safe"
print(v)
v = os.environ.get("V")
print(v)
