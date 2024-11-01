import boto3
from ..config.settings import settings

def get_cognito_client():
    return boto3.client('cognito-idp', region_name=settings.AWS_REGION)