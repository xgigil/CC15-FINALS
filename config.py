import bcrypt

# Pre-compute hashed passwords once
EXEC_HASH = bcrypt.hashpw(b"EXEC_PASS", bcrypt.gensalt())
MEM_HASH = bcrypt.hashpw(b"MEM_PASS", bcrypt.gensalt())
ADMIN_HASH = bcrypt.hashpw(b"AD_PASS", bcrypt.gensalt())

# Store hashed passwords in a dictionary
ROLE_PASSWORDS = {
    "Executive": EXEC_HASH,
    "Member": MEM_HASH,
    "Admin": ADMIN_HASH
}

def verify_role_password(role, input_password):
    try:
        return bcrypt.checkpw(input_password.encode(), ROLE_PASSWORDS[role])
    except Exception:
        return False