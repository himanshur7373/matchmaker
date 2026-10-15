[README.md](https://github.com/user-attachments/files/33505282/README.md)
# MatchMaker 💘

A free dating / matchmaking website with a **C++17 backend** (no external libraries) and a plain **HTML/CSS/JavaScript frontend**.

The C++ program is both the web server and the application logic: it speaks HTTP over raw sockets, handles accounts and sessions, computes compatibility scores and stores data in text files.

## Features

- **Free registration** with 18+ age check
- **Secure login**: salted, multi-round SHA-256 password hashing; random session cookies (`HttpOnly`, `SameSite=Strict`)
- **Profiles**: name, age, gender, city, interests, bio
- **Search and filter** by city, interest and age range
- **Compatibility score** between you and every profile (see below), with results ranked best-first
- **Likes and mutual matches**
- **Chat** available only between matched users
- **Persistent storage** in simple `.tsv` files (survives restarts)

## How the compatibility score works

Each user lists interests as comma-separated tags. The score is the **Jaccard similarity** of the two tag sets:

```
score = shared interests / total unique interests x 100
```

Example:

| User  | Interests               |
|-------|-------------------------|
| Alice | music, travel, cricket  |
| Bob   | travel, cricket, food   |

Shared = {travel, cricket} = 2, unique together = {music, travel, cricket, food} = 4, so the score is 2 / 4 = **50%**.

Tags are lowercased and trimmed, so `Travel` and `travel ` count as the same interest. Profiles are sorted by score using `std::sort`.

## Architecture

```
Browser (HTML/CSS/JS)  <--HTTP, form-encoded-->  C++ server (sockets, one thread per request)
                                                    |
                                                    +-- data/users.tsv, likes.tsv, messages.tsv
```

A global mutex protects the in-memory data, and every change is saved to disk.

## Project structure

```
matchmaker/
  server.cpp         backend: HTTP server, auth, matching, storage
  public/index.html  frontend: single-page UI
  data/              created automatically at runtime (git-ignored)
  README.md  LICENSE  .gitignore
```

## Run it

Requires a C++17 compiler (g++ or clang) on Linux or macOS. On Windows use WSL.

```bash
g++ -std=c++17 -O2 -pthread server.cpp -o server
./server
```

Open **http://localhost:8080**. To use another port: `PORT=3000 ./server`.

## API

| Method | Endpoint        | Purpose                                            |
|--------|-----------------|----------------------------------------------------|
| POST   | `/api/register` | Create account and log in                          |
| POST   | `/api/login`    | Log in                                             |
| POST   | `/api/logout`   | Log out                                            |
| GET    | `/api/me`       | Current user                                       |
| GET    | `/api/browse`   | Ranked profiles (`city`, `interest`, `min`, `max`) |
| POST   | `/api/like`     | Like a profile; reports if it is a match           |
| GET    | `/api/matches`  | List mutual matches                                |
| GET    | `/api/messages` | Chat history with a match (`with=<id>`)            |
| POST   | `/api/message`  | Send a message to a match                          |

## Security notes

- Passwords are never stored in plain text (random salt + 2000 SHA-256 rounds)
- All user text is HTML-escaped on the frontend to prevent XSS
- Input length limits and validation on the server; only logged-in users can reach member endpoints
- Chat is restricted to mutual matches

## Limitations

This is a learning project, not production software:

- No HTTPS (put it behind nginx or Caddy for real use)
- No rate limiting, block/report, or email verification
- Text-file storage instead of a database
- Use fake test data only

## Ideas for future work

- Profile photos, edit profile, forgot password
- Block and report users
- SQLite storage
- Smarter matching (age/location weighting)
- WebSockets for real-time chat

## License

MIT
