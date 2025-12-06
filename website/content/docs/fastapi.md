---
title: FastAPI Integration
description: Complete guide to integrating Cross Auth with FastAPI
section: Framework Guides
order: 1
---

# FastAPI Integration

Cross Auth is built specifically for FastAPI with native async support.

## Complete Example

```python
import os
from fastapi import FastAPI, Request
from cross_auth.router import AuthRouter
from cross_auth.social_providers.github import GitHubProvider
from cross_auth.social_providers.discord import DiscordProvider

# Implement storage (see Storage docs for full implementation)
from .storage import RedisSecondaryStorage, DatabaseAccountsStorage
from .auth import get_current_user, create_jwt_token

# Initialize providers
github = GitHubProvider(
    client_id=os.getenv("GITHUB_CLIENT_ID"),
    client_secret=os.getenv("GITHUB_CLIENT_SECRET"),
)

discord = DiscordProvider(
    client_id=os.getenv("DISCORD_CLIENT_ID"),
    client_secret=os.getenv("DISCORD_CLIENT_SECRET"),
)

# Create auth router
auth_router = AuthRouter(
    providers=[github, discord],
    secondary_storage=RedisSecondaryStorage(redis_client),
    accounts_storage=DatabaseAccountsStorage(db),
    get_user_from_request=get_current_user,
    create_token=create_jwt_token,
    trusted_origins=["https://your-app.com"],
    base_url=os.getenv("BASE_URL", "https://your-app.com"),
)

app = FastAPI()

# Mount the auth router
app.include_router(auth_router, prefix="/auth")

# Protected route example
@app.get("/api/me")
async def get_current_user_endpoint(request: Request):
    user = get_current_user(request)
    if not user:
        return {"error": "Not authenticated"}, 401
    return {"user": {"id": user.id, "email": user.email}}
```

## Helper Functions

### get_user_from_request

Extract the current user from the request (e.g., from JWT token):

```python
from lia import AsyncHTTPRequest
from .models import User

def get_current_user(request: AsyncHTTPRequest) -> User | None:
    # Extract JWT from Authorization header
    auth_header = request.headers.get("authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None

    token = auth_header[7:]

    try:
        payload = decode_jwt(token)
        user_id = payload.get("sub")
        return db.query(User).filter_by(id=user_id).first()
    except Exception:
        return None
```

### create_token

Generate JWT tokens for authenticated users:

```python
import jwt
from datetime import datetime, timedelta

def create_jwt_token(user_id: str) -> tuple[str, int]:
    expires_in = 3600  # 1 hour
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(seconds=expires_in),
        "iat": datetime.utcnow(),
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token, expires_in
```

## OpenAPI Documentation

The AuthRouter automatically adds OpenAPI documentation for all OAuth endpoints. View it at `/docs` in your FastAPI application.

## Environment Variables

Store sensitive configuration in environment variables:

```bash
GITHUB_CLIENT_ID=your_github_client_id
GITHUB_CLIENT_SECRET=your_github_client_secret
DISCORD_CLIENT_ID=your_discord_client_id
DISCORD_CLIENT_SECRET=your_discord_client_secret
BASE_URL=https://your-app.com
SECRET_KEY=your_jwt_secret_key
```
