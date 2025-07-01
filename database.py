import contextlib
from sqlalchemy import create_engine, MetaData
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Session, sessionmaker
from config import settings

SQLALCHEMY_DATABASE_URL = f"postgresql://{settings.DB_USERNAME}:{settings.DB_PASSWORD}@{settings.DB_HOSTNAME}:{settings.DB_PORT}/{settings.DB_NAME}"
SQLALCHEMY_INGESTION_URL = f"postgresql://{settings.DB_INGESTION_USERNAME}:{settings.DB_INGESTION_PASSWORD}@{settings.DB_INGESTION_HOSTNAME}:{settings.DB_INGESTION_PORT}/{settings.DB_INGESTION_NAME}"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
engine_ingestion = create_engine(SQLALCHEMY_INGESTION_URL)
meta = MetaData()

# SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()
IngestionBase = declarative_base(bind=engine_ingestion, metadata=meta)

SessionLocal = sessionmaker(autocommit=False, autoflush=False)


@contextlib.contextmanager
def get_db():
    db = Session(autocommit=False, autoflush=False, bind=engine)
    try:
        yield db
    # except Exception:
    #     db.rollback()
    finally:
        db.close()


@contextlib.contextmanager
def get_db_ingestion():
    db2 = None
    try:
        db2 = Session(autocommit=False, autoflush=False, bind=engine_ingestion)
        yield db2
    finally:
        db2.close()
