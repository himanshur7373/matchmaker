# MatchMaker (C++ backend + HTML frontend)

Free dating/matchmaking demo (no payment).

## Run
    g++ -std=c++17 -O2 -pthread server.cpp -o server
    ./server
Open http://localhost:8080 

## Files
- server.cpp      : whole backend (HTTP server, SHA-256 salted hashing, sessions, matching, storage)
- public/index.html : frontend (HTML/CSS/JS)
- data/           : created automatically (users.tsv, likes.tsv, messages.tsv)

## Notes
- Compatibility score = Jaccard similarity of interests (shared / total unique).
- Passwords: salted, 2000-round SHA-256. All output is HTML-escaped.
- Demo-grade: no HTTPS, no rate limiting, no block/report. Run behind HTTPS (nginx/Caddy) and use test data only.
