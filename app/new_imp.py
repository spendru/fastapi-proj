# Project Structure
.
├── Dockerfile
├── requirements.txt
├── app
│   ├── __init__.py
│   ├── main.py
│   ├── config
│   │   ├── __init__.py
│   │   └── settings.py
│   ├── core
│   │   ├── __init__.py
│   │   ├── aws_clients.py
│   │   ├── database.py
│   │   └── security.py
│   ├── api
│   │   ├── __init__.py
│   │   ├── v1
│   │   │   ├── __init__.py
│   │   │   ├── endpoints
│   │   │   │   ├── __init__.py
│   │   │   │   ├── health.py
│   │   │   │   └── users.py
│   │   │   └── router.py
│   ├── models
│   │   ├── __init__.py
│   │   └── user.py
│   ├── schemas
│   │   ├── __init__.py
│   │   └── user.py
│   └── services
│       ├── __init__.py
│       └── cognito.py

# requirements.txt
fastapi==0.68.1
uvicorn==0.15.0
python-jose==3.3.0
boto3==1.26.137
sqlalchemy==1.4.41
psycopg2-binary==2.9.3
pydantic==1.10.7
tenacity==8.2.2
python-multipart==0.0.6
passlib==1.7.4
bcrypt==3.2.0
email-validator==1.1.3

# app/__init__.py
from .config.settings import settings

__version__ = "1.0.0"

# app/config/__init__.py
from .settings import Settings, settings

__all__ = ["Settings", "settings"]

# app/config/settings.py
from pydantic import BaseSettings
import boto3
import json
from tenacity import retry, stop_after_attempt, wait_exponential
import logging

logger = logging.getLogger(__name__)

class Settings(BaseSettings):
    APP_NAME: str = "FastAPI AWS App"
    API_V1_STR: str = "/api/v1"
    
    # AWS Settings
    AWS_REGION: str = "us-east-1"
    SECRETS_NAME: str = "fastapi-app-secrets"
    
    # Database settings (loaded from secrets)
    DB_HOST: str = None
    DB_PORT: str = None
    DB_USER: str = None
    DB_PASSWORD: str = None
    DB_NAME: str = None
    
    # Cognito settings (loaded from secrets)
    COGNITO_USER_POOL_ID: str = None
    COGNITO_APP_CLIENT_ID: str = None
    
    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
    def load_secrets(self):
        try:
            session = boto3.session.Session()
            client = session.client(
                service_name='secretsmanager',
                region_name=self.AWS_REGION
            )
            
            secret_value = client.get_secret_value(SecretId=self.SECRETS_NAME)
            secrets = json.loads(secret_value['SecretString'])
            
            # Update settings from secrets
            self.DB_HOST = secrets.get('db_host')
            self.DB_PORT = secrets.get('db_port')
            self.DB_USER = secrets.get('db_username')
            self.DB_PASSWORD = secrets.get('db_password')
            self.DB_NAME = secrets.get('db_name')
            self.COGNITO_USER_POOL_ID = secrets.get('cognito_user_pool_id')
            self.COGNITO_APP_CLIENT_ID = secrets.get('cognito_app_client_id')
            
        except Exception as e:
            logger.error(f"Error loading secrets: {str(e)}")
            raise

settings = Settings()

# app/core/__init__.py
from .database import get_db, Base, engine
from .aws_clients import get_cognito_client
from .security import get_password_hash, verify_password

__all__ = [
    "get_db",
    "Base",
    "engine",
    "get_cognito_client",
    "get_password_hash",
    "verify_password"
]

# app/core/aws_clients.py
import boto3
from ..config.settings import settings

def get_cognito_client():
    return boto3.client('cognito-idp', region_name=settings.AWS_REGION)

# app/core/database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from ..config.settings import settings
from tenacity import retry, stop_after_attempt, wait_exponential

DATABASE_URL = f"postgresql://{settings.DB_USER}:{settings.DB_PASSWORD}@{settings.DB_HOST}:{settings.DB_PORT}/{settings.DB_NAME}"

@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=4, max=10))
def create_db_engine():
    return create_engine(DATABASE_URL)

engine = create_db_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# app/core/security.py
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# app/api/__init__.py
from .v1.router import api_router

__all__ = ["api_router"]

# app/api/v1/__init__.py
from .router import api_router

__all__ = ["api_router"]

# app/api/v1/router.py
from fastapi import APIRouter
from .endpoints import health, users

api_router = APIRouter()

# Add health check endpoint
api_router.include_router(health.router, tags=["health"])

# Add user-related endpoints
api_router.include_router(users.router, prefix="/users", tags=["users"])

# app/api/v1/endpoints/__init__.py
from .health import router as health_router
from .users import router as users_router

__all__ = ["health_router", "users_router"]

# app/api/v1/endpoints/health.py
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from ....core.database import get_db

router = APIRouter()

@router.get("/health")
async def health_check(db: Session = Depends(get_db)):
    try:
        # Test database connection
        db.execute("SELECT 1")
        return {
            "status": "healthy",
            "database": "connected",
            "details": {
                "database_host": "connected",
                "api_version": "v1"
            }
        }
    except Exception as e:
        return {
            "status": "unhealthy",
            "database": "disconnected",
            "error": str(e)
        }

# app/api/v1/endpoints/users.py
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from ....core.database import get_db
from ....services.cognito import CognitoService
from ....schemas.user import UserCreate, UserResponse
from ....models.user import User

router = APIRouter()
cognito_service = CognitoService()

@router.post("/", response_model=UserResponse)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    # Create user in Cognito
    cognito_response = await cognito_service.create_user(
        email=user.email,
        password=user.password
    )
    
    # Create user in database
    db_user = User(
        cognito_id=cognito_response['User']['Username'],
        email=user.email
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    
    return db_user

@router.delete("/{user_id}")
async def delete_user(user_id: int, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.id == user_id).first()
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Delete from Cognito
    await cognito_service.delete_user(db_user.cognito_id)
    
    # Delete from database
    db.delete(db_user)
    db.commit()
    
    return {"message": "User deleted successfully"}

# app/models/__init__.py
from .user import User

__all__ = ["User"]

# app/models/user.py
from sqlalchemy import Column, Integer, String, DateTime
from ..core.database import Base
import datetime

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    cognito_id = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

# app/schemas/__init__.py
from .user import UserCreate, UserResponse

__all__ = ["UserCreate", "UserResponse"]

# app/schemas/user.py
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional

class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int
    cognito_id: str
    created_at: datetime
    updated_at: datetime

    class Config:
        orm_mode = True

# app/services/__init__.py
from .cognito import CognitoService

__all__ = ["CognitoService"]

# app/services/cognito.py
from ..core.aws_clients import get_cognito_client
from ..config.settings import settings
from fastapi import HTTPException

class CognitoService:
    def __init__(self):
        self.client = get_cognito_client()
        self.user_pool_id = settings.COGNITO_USER_POOL_ID
        
    async def create_user(self, email: str, password: str):
        try:
            response = self.client.admin_create_user(
                UserPoolId=self.user_pool_id,
                Username=email,
                TemporaryPassword=password,
                UserAttributes=[
                    {'Name': 'email', 'Value': email},
                    {'Name': 'email_verified', 'Value': 'true'}
                ]
            )
            return response
        except self.client.exceptions.UsernameExistsException:
            raise HTTPException(status_code=400, detail="User already exists")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))
    
    async def delete_user(self, username: str):
        try:
            response = self.client.admin_delete_user(
                UserPoolId=self.user_pool_id,
                Username=username
            )
            return response
        except self.client.exceptions.UserNotFoundException:
            raise HTTPException(status_code=404, detail="User not found")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

# app/main.py
from fastapi import FastAPI
from .config.settings import settings
from .api.v1.router import api_router
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title=settings.APP_NAME)

@app.on_event("startup")
async def startup_event():
    # Load secrets at startup
    settings.load_secrets()
    logger.info("Application started, secrets loaded")

# Include API router
app.include_router(api_router, prefix=settings.API_V1_STR)

# Dockerfile
FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "80"]
