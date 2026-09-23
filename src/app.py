"""High School Management System API."""

from datetime import datetime, timedelta, timezone
import hashlib
import os
from pathlib import Path
import secrets
import sqlite3

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse
from pydantic import BaseModel

app = FastAPI(title="Mergington High School API",
              description="API for viewing and signing up for extracurricular activities")

current_dir = Path(__file__).parent
database_path = Path(os.getenv("DATABASE_PATH", current_dir / "activities.db"))
security = HTTPBearer(auto_error=False)

initial_activities = {
    "Chess Club": ("Learn strategies and compete in chess tournaments", "Fridays, 3:30 PM - 5:00 PM", 12, ["michael@mergington.edu", "daniel@mergington.edu"]),
    "Programming Class": ("Learn programming fundamentals and build software projects", "Tuesdays and Thursdays, 3:30 PM - 4:30 PM", 20, ["emma@mergington.edu", "sophia@mergington.edu"]),
    "Gym Class": ("Physical education and sports activities", "Mondays, Wednesdays, Fridays, 2:00 PM - 3:00 PM", 30, ["john@mergington.edu", "olivia@mergington.edu"]),
    "Soccer Team": ("Join the school soccer team and compete in matches", "Tuesdays and Thursdays, 4:00 PM - 5:30 PM", 22, ["liam@mergington.edu", "noah@mergington.edu"]),
    "Basketball Team": ("Practice and play basketball with the school team", "Wednesdays and Fridays, 3:30 PM - 5:00 PM", 15, ["ava@mergington.edu", "mia@mergington.edu"]),
    "Art Club": ("Explore your creativity through painting and drawing", "Thursdays, 3:30 PM - 5:00 PM", 15, ["amelia@mergington.edu", "harper@mergington.edu"]),
    "Drama Club": ("Act, direct, and produce plays and performances", "Mondays and Wednesdays, 4:00 PM - 5:30 PM", 20, ["ella@mergington.edu", "scarlett@mergington.edu"]),
    "Math Club": ("Solve challenging problems and participate in math competitions", "Tuesdays, 3:30 PM - 4:30 PM", 10, ["james@mergington.edu", "benjamin@mergington.edu"]),
    "Debate Team": ("Develop public speaking and argumentation skills", "Fridays, 4:00 PM - 5:30 PM", 12, ["charlotte@mergington.edu", "henry@mergington.edu"]),
}


class Credentials(BaseModel):
    username: str
    password: str


def connect_database():
    connection = sqlite3.connect(database_path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 120_000)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    salt_hex, digest_hex = stored_hash.split("$", 1)
    candidate = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), 120_000)
    return secrets.compare_digest(candidate.hex(), digest_hex)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def initialize_database():
    with connect_database() as connection:
        connection.executescript("""
            CREATE TABLE IF NOT EXISTS activities (
                name TEXT PRIMARY KEY,
                description TEXT NOT NULL,
                schedule TEXT NOT NULL,
                max_participants INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('student', 'teacher', 'admin'))
            );
            CREATE TABLE IF NOT EXISTS participants (
                activity_name TEXT NOT NULL REFERENCES activities(name) ON DELETE CASCADE,
                email TEXT NOT NULL,
                PRIMARY KEY (activity_name, email)
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                username TEXT NOT NULL REFERENCES users(username) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            );
        """)
        for name, (description, schedule, maximum, participants) in initial_activities.items():
            connection.execute(
                "INSERT OR IGNORE INTO activities VALUES (?, ?, ?, ?)",
                (name, description, schedule, maximum),
            )
            for email in participants:
                connection.execute(
                    "INSERT OR IGNORE INTO participants VALUES (?, ?)", (name, email)
                )

        teacher_username = os.getenv("TEACHER_USERNAME")
        teacher_password = os.getenv("TEACHER_PASSWORD")
        if teacher_username and teacher_password:
            connection.execute(
                "INSERT OR IGNORE INTO users VALUES (?, ?, 'teacher')",
                (teacher_username, hash_password(teacher_password)),
            )


def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
):
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authentication required")

    with connect_database() as connection:
        session = connection.execute(
            """
            SELECT users.username, users.role FROM sessions
            JOIN users ON users.username = sessions.username
            WHERE sessions.token_hash = ? AND sessions.expires_at > ?
            """,
            (token_hash(credentials.credentials), datetime.now(timezone.utc).isoformat()),
        ).fetchone()
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return session


def require_teacher(user=Depends(current_user)):
    if user["role"] not in {"teacher", "admin"}:
        raise HTTPException(status_code=403, detail="Teacher role required")
    return user


initialize_database()
app.mount("/static", StaticFiles(directory=os.path.join(current_dir, "static")), name="static")


@app.get("/")
def root():
    return RedirectResponse(url="/static/index.html")


@app.get("/activities")
def get_activities():
    with connect_database() as connection:
        rows = connection.execute(
            """
            SELECT activities.*, GROUP_CONCAT(participants.email) AS participant_emails
            FROM activities LEFT JOIN participants ON activities.name = participants.activity_name
            GROUP BY activities.name ORDER BY activities.name
            """
        ).fetchall()
    return {
        row["name"]: {
            "description": row["description"],
            "schedule": row["schedule"],
            "max_participants": row["max_participants"],
            "participants": row["participant_emails"].split(",") if row["participant_emails"] else [],
        }
        for row in rows
    }


@app.post("/auth/register", status_code=201)
def register(credentials: Credentials):
    if len(credentials.password) < 8:
        raise HTTPException(status_code=400, detail="Password must contain at least 8 characters")
    with connect_database() as connection:
        try:
            connection.execute(
                "INSERT INTO users VALUES (?, ?, 'student')",
                (credentials.username, hash_password(credentials.password)),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=409, detail="Username already exists")
    return {"message": "Student account created"}


@app.post("/auth/login")
def login(credentials: Credentials):
    with connect_database() as connection:
        user = connection.execute(
            "SELECT username, password_hash FROM users WHERE username = ?",
            (credentials.username,),
        ).fetchone()
        if user is None or not verify_password(credentials.password, user["password_hash"]):
            raise HTTPException(status_code=401, detail="Invalid username or password")
        token = secrets.token_urlsafe(32)
        connection.execute(
            "INSERT INTO sessions VALUES (?, ?, ?)",
            (token_hash(token), user["username"], (datetime.now(timezone.utc) + timedelta(hours=8)).isoformat()),
        )
    return {"access_token": token, "token_type": "bearer"}


@app.post("/activities/{activity_name}/signup")
def signup_for_activity(activity_name: str, email: str, user=Depends(require_teacher)):
    with connect_database() as connection:
        activity = connection.execute(
            "SELECT max_participants FROM activities WHERE name = ?", (activity_name,)
        ).fetchone()
        if activity is None:
            raise HTTPException(status_code=404, detail="Activity not found")
        try:
            connection.execute(
                "INSERT INTO participants VALUES (?, ?)", (activity_name, email)
            )
        except sqlite3.IntegrityError:
            raise HTTPException(status_code=400, detail="Student is already signed up")
        count = connection.execute(
            "SELECT COUNT(*) FROM participants WHERE activity_name = ?", (activity_name,)
        ).fetchone()[0]
        if count > activity["max_participants"]:
            raise HTTPException(status_code=409, detail="Activity is full")
    return {"message": f"Signed up {email} for {activity_name}", "updated_by": user["username"]}


@app.delete("/activities/{activity_name}/unregister")
def unregister_from_activity(activity_name: str, email: str, user=Depends(require_teacher)):
    with connect_database() as connection:
        result = connection.execute(
            "DELETE FROM participants WHERE activity_name = ? AND email = ?",
            (activity_name, email),
        )
        if result.rowcount == 0:
            raise HTTPException(status_code=400, detail="Student is not signed up for this activity")
    return {"message": f"Unregistered {email} from {activity_name}", "updated_by": user["username"]}
