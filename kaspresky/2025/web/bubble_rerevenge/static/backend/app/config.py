import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'redacted')
    DEBUG = True

    SQLALCHEMY_DATABASE_URI = os.environ.get("SQLALCHEMY_DATABASE_URI", "postgresql://redacted:redacted@localhost:5432/redacted")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    REDIS_URL = os.environ.get('REDIS_URL', 'redis://localhost:6379/0')
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY', 'redacted')
    JWT_ACCESS_TOKEN_EXPIRES = 3600
    
    ALLOWED_BB_TAGS = [
        'b', 'i', 's', 'h1', 'list', 'quote', 'code', 
        'url', 'img', 'youtube', 'yt'
    ]
    
    YOUTUBE_ALLOWED_ATTRIBUTES = ['id', 'width', 'height']
