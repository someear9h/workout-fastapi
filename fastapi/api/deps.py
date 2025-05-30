from typing import Annotated
from sqlalchemy.orm import Session
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from dotenv import load_dotenv
from jose import JWTError, jwt
import os
from .database import SessionLocal

# Load environment variables from a .env file (e.g. secret keys)
load_dotenv()

# Secret key and algorithm used to encode/decode JWT tokens
SECRET_KEY = os.getenv('AUTH_SECRET_KEY')
ALGORITHM = os.getenv('AUTH_ALGORITHM')


# Dependency function to get a database session
def get_db():
    db = SessionLocal()  # Create a new database session
    try:
        yield db  # Yield it for use in path operations
    finally:
        db.close()  # Close the session after request is done


# Annotated type to use database session as a dependency in FastAPI routes
db_dependency = Annotated[Session, Depends(get_db)]

# CryptContext to handle password hashing (bcrypt algorithm)
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

# OAuth2 scheme which expects a token in requests' Authorization header
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

# Annotated type for the token dependency extracted from OAuth2 scheme
oauth2_bearer_dependency = Annotated[str, Depends(oauth2_bearer)]


# Function to get the current authenticated user from the JWT token
async def get_current_user(token: oauth2_bearer_dependency):
    try:
        # Decode the JWT token using secret key and algorithm
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        # Extract username and user ID from the token payload
        username: str = payload.get('sub')
        user_id: int = payload.get('id')

        # If username or user_id is missing, raise Unauthorized error
        if username is None or user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail='Could not validate user'
            )

        # Return a simple dict representing the current user
        return {'username': username, 'id': user_id}

    # If decoding fails or token is invalid, raise Unauthorized error
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail='Could not validate user'
        )
