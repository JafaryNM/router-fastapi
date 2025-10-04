from fastapi import APIRouter,Depends
from pydantic import BaseModel
from models import Users
from passlib.context import CryptContext
from typing import Annotated
from database import SessionLocal
from sqlalchemy.orm import Session
from starlette import status
from fastapi.security import OAuth2PasswordRequestForm
from jose import jwt
from datetime import timedelta,datetime,timezone



router = APIRouter()
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')

SECREATE_KEY = 'f9a84c71e3f45d08bcb2c75f681c4f56dca8de91fbc64ae01a9f6f76a6c3d5e2'
ALGORITHIM = 'HS256'


class CreateUserRequest(BaseModel):
    username:str
    email:str
    first_name:str
    last_name:str
    password:str
    role:str
    is_active:bool

class Token(BaseModel):
    access_token :str
    token_type:str

def get_db():
    db= SessionLocal()

    try:
        yield db
    finally:
        db.close

db_dependency =Annotated[Session,Depends(get_db)]

def authenticate_user(username:str,password:str, db):
    user = db.query(Users).filter(Users.username==username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password,user.hashed_password):
        return False
    
    return user

def create_access_token(username:str, user_id:int, expires_delta:timedelta):
    encode = {'sub':username , 'id':user_id,  }
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp':expires})
    return jwt.encode(encode, SECREATE_KEY, algorithm=ALGORITHIM)





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


@router.post("/tokens/", response_model=Token)
async def login_for_access_token(form_data:Annotated[OAuth2PasswordRequestForm, Depends()], db:db_dependency):
    user =  authenticate_user(form_data.username, form_data.password,db)
    if not user:
        return 'Failed Authentication'
    token = create_access_token(user.username, user.id, timedelta(minutes=20))
    return {'access_token':token , 'token_type':'bearer'}
    


