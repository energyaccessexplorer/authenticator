# Go Server with Resource Watch API Integration

This server is written in Go and allows users to sign up and log in via the Resource Watch API. The server uses JWT for authentication and is built with the Gorilla Mux router, handling CORS configurations for cross-origin requests.

## Features

- **Sign Up**: Creates a new user on the Resource Watch platform.
- **Log In**: Authenticates a user and generates a JWT token for session management.

## Requirements

- [Go](https://golang.org/) installed
- [Gorilla Mux](https://github.com/gorilla/mux) for routing
- [GoDotEnv](https://github.com/joho/godotenv) for environment variable management
- [JWT-Go](https://github.com/golang-jwt/jwt) for JWT handling

## Setup

1. **Clone the repository** and navigate to the project directory.

2. **Environment Variables**: Create a copy of `.env.example` into a `.env` file in the project root to store environment variables. It should contain the following keys:

    ```plaintext
    PORT=":5003"
    APP_NAME=resource_watch_app_name
    PGREST_SECRET=your_jwt_secret_shared_with_postgREST
    CALLBACK_URL=website_url
    RW_API_KEY=resource_watch_API_key
    DATABASE_URI=postgresql://
    ```

3. **Install Dependencies**:

   Run the following commands to install necessary dependencies.

   ```bash
   go get
   ```
## Running

```
go run main.go
```

## Building & hacking

Assumptions made:

- Standard Unix-like environment (cat, sed, echo, rsync, bmake...)
- Energy Access Explorer infrastructure:
  [database](https://github.com/energyaccessexplorer/database),
  [tool](https://github.com/energyaccessexplorer/tool),
  [API](https://github.com/energyaccessexplorer/api) and
  [website](https://github.com/energyaccessexplorer/website)
  should be up and running.
