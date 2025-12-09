# auth-api-jwt

Simple **JWT-based authentication API** built with **FastAPI**.  
This demo project shows how to implement register, login, and a protected `/me` endpoint using hashed passwords and JSON Web Tokens.

## Features
- `/register` — create a new user with a hashed password (demo in-memory store).
- `/login` — authenticate with username and password to receive a JWT access token.
- `/me` — protected endpoint that returns the current user based on the Bearer token.
- `/health` — basic health check endpoint.
- Uses OAuth2 password flow and standard `Authorization: Bearer <token>` headers.

---

## Tech Stack
- Python 3.11+
- FastAPI
- Uvicorn (ASGI server)
- python-jose (JWT)
- passlib[bcrypt] (password hashing)

---

## Project Structure
```text
auth-api-jwt/
│
├── app/
│   ├── main.py
│   └── auth.py
│
├── requirements.txt
└── README.md
```

---

## Run Locally

```bash
# 1. Clone the repository
git clone https://github.com/mirzamuhammaddaniyal-eng/auth-api-jwt.git
cd auth-api-jwt
```

```bash
# 2. Create a virtual environment
python3 -m venv venv
source venv/bin/activate      # On Windows: venv\Scripts\activate
```

 ```bash
# 3. Install dependencies
pip install -r requirements.txt
```

```bash
# 4. Start the FastAPI server
uvicorn app.main:app --reload
```

Visit:
```
http://127.0.0.1:8000/docs
```

---

## Example usage

### 1. Register a user

In Swagger UI (`/docs`):

- Endpoint: `POST /register`
- Body:
```json
{
  "username": "testuser",
  "password": "secret123"
}
```

### 2. Login

- `Endpoint`: `POST /login`
- `grant_type`: `password`
- `username`: `testuser`
- `password`: `secret123`

Copy the `access_token` from the response.

### 3. Call `/me`

- Endpoint: `GET /me`
- Click **Authorize** in Swagger UI and paste:
  - `Bearer <your_access_token>`

You should see:
```json
{
  "username": "testuser"
}
```
