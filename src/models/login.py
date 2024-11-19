from sqlalchemy import Column,String,Boolean,DateTime,ForeignKey
from database.database import Base
from datetime import datetime

class User(Base):
    __tablename__ = "users"
    id = Column(String,primary_key=True,nullable=False)
    user_name = Column(String,nullable=False)
    password = Column(String,nullable=False)
    email = Column(String,nullable=False)
    is_active = Column(Boolean,default=True,nullable=False)
    is_verified = Column(Boolean,default=False,nullable=False)
    is_created = Column(DateTime,default=datetime.now,nullable=False)
    is_modified = Column(DateTime,default=datetime.now,onupdate=datetime.now,nullable=False)
    is_deleted = Column(Boolean,default=False,nullable=False)

class Otp(Base):
    __tablename__ = "otps"
    id = Column(String,primary_key=True,nullable=False)
    user_id = Column(String,ForeignKey("users.id"),nullable=False)
    email = Column(String,nullable=False)
    otp = Column(String,nullable=False)
    created_at = Column(String,default=datetime.now,nullable=False)
    modified_at = Column(String,default=datetime.now,onupdate=datetime.now,nullable=False)
