from fastapi import APIRouter,Depends
from pydantic import BaseModel
from models import Users
from passlib.context import CryptContext
from typing import Annotated
from database import SessionLocal
from sqlalchemy.orm import Session
from starlette import status

router = APIRouter()
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


class CreateUserRequest(BaseModel):
    username:str
    email:str
    first_name:str
    last_name:str
    password:str
    role:str
    is_active:bool

def get_db():
    db= SessionLocal()

    try:
        yield db
    finally:
        db.close

db_dependency =Annotated[Session,Depends(get_db)]

@router.post("/auth/", status_code=status.HTTP_201_CREATED)
async def create_user(db:db_dependency,create_user_request:CreateUserRequest):
    create_user_model = Users(
        email = create_user_request.email,
        hashed_password = bcrypt_context.hash(create_user_request.password),
        username = create_user_request.username,
        first_name = create_user_request.first_name,
        last_name = create_user_request.last_name,
        role = create_user_request.role,
        is_active = create_user_request.is_active,
    )
    db.add(create_user_model)
    db.commit()

