import re

from fastapi import FastAPI, Request, Header
from fastapi.responses import JSONResponse

from security import hash_password, verify_password

import base64
import binascii


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

@app.get("/users/{user_id}")
async def get_user(
    user_id: str,
    authorization: str | None = Header(
        default=None,
        alias="Authorization"
    )
):
    # 1. Check whether the requested user exists
    if user_id not in users:
        return JSONResponse(
            status_code=404,
            content={"message": "No user found"}
        )

    # 2. Check whether the Authorization header exists
    if not authorization:
        return JSONResponse(
            status_code=401,
            content={"message": "Authentication failed"}
        )

    # 3. Decode Basic Authentication credentials
    try:
        scheme, encoded_credentials = authorization.split(" ", 1)

        if scheme.lower() != "basic":
            raise ValueError("Invalid authentication scheme")

        decoded_credentials = base64.b64decode(
            encoded_credentials,
            validate=True
        ).decode("utf-8")

        credential_user_id, password = decoded_credentials.split(":", 1)

    except (ValueError, UnicodeDecodeError, binascii.Error):
        return JSONResponse(
            status_code=401,
            content={"message": "Authentication failed"}
        )

    # 4. Ensure the credentials belong to the requested user
    if credential_user_id != user_id:
        return JSONResponse(
            status_code=401,
            content={"message": "Authentication failed"}
        )

    # 5. Verify the password
    user = users[user_id]

    if not verify_password(
        password,
        user["salt"],
        user["password_hash"]
    ):
        return JSONResponse(
            status_code=401,
            content={"message": "Authentication failed"}
        )

    # 6. Construct the response
    user_details = {
        "user_id": user_id,
        "nickname": user.get("nickname") or user_id
    }

    # Include comment only when configured
    if user.get("comment") is not None:
        user_details["comment"] = user["comment"]

    return {
        "message": "User details by user_id",
        "user": user_details
    }

@app.post("/close")
async def close_account(
    authorization: str | None = Header(
        default=None,
        alias="Authorization"
    )
):
    # 1. Check Authorization header
    if not authorization:
        return JSONResponse(
            status_code=401,
            content={"message": "Authentication failed"}
        )

    # 2. Decode Basic Authentication credentials
    try:
        scheme, encoded_credentials = authorization.split(" ", 1)

        if scheme.lower() != "basic":
            raise ValueError("Invalid authentication scheme")

        decoded_credentials = base64.b64decode(
            encoded_credentials,
            validate=True
        ).decode("utf-8")

        user_id, password = decoded_credentials.split(":", 1)

    except (ValueError, UnicodeDecodeError, binascii.Error):
        return JSONResponse(
            status_code=401,
            content={"message": "Authentication failed"}
        )

    # 3. Check whether the account exists
    if user_id not in users:
        return JSONResponse(
            status_code=401,
            content={"message": "Authentication failed"}
        )

    # 4. Verify password
    user = users[user_id]

    if not verify_password(
        password,
        user["salt"],
        user["password_hash"]
    ):
        return JSONResponse(
            status_code=401,
            content={"message": "Authentication failed"}
        )

    # 5. Remove the account
    del users[user_id]

    return {
        "message": "Account and user successfully removed"
    }