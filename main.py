import re

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from security import hash_password


app = FastAPI(
    title="test-public-api",
    description="A simple demo API built as test",
    version="0.1.0"
)


# Temporary in-memory storage

users = {}

# Health check

@app.get("/")
def health_check():
    return {
        "status": "ok",
        "message": "Public User API is running"
    }

# ---------------------------------------
# Signup validation
# ---------------------------------------

def validate_signup(user_id, password):

    # Required field validation
    if (
        not isinstance(user_id, str)
        or not user_id
        or not isinstance(password, str)
        or not password
    ):
        return "Required user_id and password"

    # Input length validation
    if not (6 <= len(user_id) <= 20):
        return "Input length is incorrect"

    if not (8 <= len(password) <= 20):
        return "Input length is incorrect"

    # Character pattern validation
    if not re.fullmatch(r"[a-zA-Z0-9]+", user_id):
        return "Incorrect character pattern"

    if not re.fullmatch(r"[!-~]+", password):
        return "Incorrect character pattern"

    return None


# ---------------------------------------
# POST /signup
# ---------------------------------------

@app.post("/signup")
async def signup(request: Request):

    # Parse request body
    try:
        data = await request.json()

        if not isinstance(data, dict):
            raise ValueError("Invalid JSON structure")

    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Account creation failed",
                "cause": "Required user_id and password"
            }
        )

    user_id = data.get("user_id")
    password = data.get("password")

    # Validate input
    validation_error = validate_signup(
        user_id,
        password
    )

    if validation_error:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Account creation failed",
                "cause": validation_error
            }
        )

    # Check duplicate user_id
    if user_id in users:
        return JSONResponse(
            status_code=400,
            content={
                "message": "Account creation failed",
                "cause": "Already same user_id is used"
            }
        )

    # Hash password
    salt, password_hash = hash_password(password)

    # Create account
    users[user_id] = {
        "user_id": user_id,
        "password_salt": salt,
        "password_hash": password_hash,
        "nickname": user_id
    }

    # Return success response
    return {
        "message": "Account successfully created",
        "user": {
            "user_id": user_id,
            "nickname": user_id
        }
    }
