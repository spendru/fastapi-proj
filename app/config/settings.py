from pydantic import BaseSettings
import boto3
import json
from tenacity import retry, stop_after_attempt, wait_exponential

class Settings(BaseSettings):
    APP_NAME: str = "FastAPI AWS App"
    API_V1_STR: str = "/api/v1"
    
    # AWS Settings
    AWS_REGION: str = "us-east-2"
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
