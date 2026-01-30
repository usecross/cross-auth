from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Pre-computed dummy hash for constant-time password verification
# This prevents timing attacks that could enumerate valid users
DUMMY_PASSWORD_HASH = "$2b$12$K6qGJzUzL5H0yQKqVZKZFuJ9aZqZ5qH0yQKqVZKZFuJ9aZqZ5qH0y"
