# auth-service

Authentication service in Go using Gin, Postgres, Redis, and JWT.

## Features

- User registration and login
- JWT access/refresh tokens (cookie-based)
- Token blacklist using Redis
- Password reset via email (SMTP)
- Password reset with time-limited token
- Configurable CORS policy

## Quick Start

### 1. Clone the repository

```sh
git clone https://github.com/IITESLAII/auth-service.git
cd auth-service
```

### 2. Create a `.env` file from the example

```sh
cp .env.example .env
```
Edit `.env` with your own values.

### 3. Run Postgres and Redis

Example using Docker:

```sh
docker run --name some-postgres -e POSTGRES_PASSWORD=yourpassword -e POSTGRES_DB=auth -p 5432:5432 -d postgres
docker run --name some-redis -p 6379:6379 -d redis
```

### 4. Run migrations to create the `users` table

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    hashed_password TEXT NOT NULL
);
```

### 5. Install dependencies

```sh
go mod tidy
```

### 6. Start the service

```sh
go run main.go
```

The service will start on the port specified by the `HOST` environment variable (default: `localhost:8080`).

## Example .env

See the [.env.example](./.env.example) file.

## Main Endpoints

- `POST /register` — registration
- `POST /login` — login
- `POST /refresh` — refresh access token using refresh token
- `POST /logout` — logout (blacklist tokens)
- `POST /reset-password` — send password reset code to email
- `POST /reset-password-code` — check code, get cookie for password reset
- `POST /change-password` — change password using resetToken from cookie

## Environment Variables

See the section below and `.env.example`.

## License

MIT or your preferred license.
