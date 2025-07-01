class Settings():
    DB_HOSTNAME: str = "127.0.0.1"
    DB_PORT: str = "5432"
    DB_NAME: str = "nbm"
    DB_USERNAME: str = "postgres"
    DB_PASSWORD: str = "password"

    DB_INGESTION_HOSTNAME: str = "127.0.0.1"
    DB_INGESTION_PORT: str = "5432"
    DB_INGESTION_NAME: str = "nbm_ingestion"
    DB_INGESTION_USERNAME: str = "postgres"
    DB_INGESTION_PASSWORD: str = "password"

settings = Settings()
