from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, Field, BaseConfig
from typing import List, Optional
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta
from bson import ObjectId
from pymongo import MongoClient

#MongoDB Connection
client = MongoClient('mongodb://localhost:27017/')
db = client['simple_blog']
users_collection = db['users']
blogs_collection = db['blogs']

#FastAPI instance
app = FastAPI()

#Authentication Configurations
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

#Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#Pydantic Models
class User(BaseModel):
    username: str
    email: str
    password: str
    hashed_password: str = Field(..., alias="password")
    tags: Optional[List[str]] = []

class UserInDB(BaseModel):
    class Config(BaseConfig):
        arbitrary_types_allowed = True

    id: ObjectId
    username: str
    email: str
    hashed_password: str
    tags: Optional[List[str]] = []

class BlogInDB(BaseModel):
    class Config(BaseConfig):
        arbitrary_types_allowed = True

    id: ObjectId
    title: str
    content: str
    author_id: str
    created_at: datetime = None

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: str = None
    email: str = None

class Blog(BaseModel):
    title: str
    content: str
    author_id: str

#Password Hashing
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

#user CRUD Operations
def get_user(username: str):
    return users_collection.find_one({"username": username})

def create_user(user: User):
    user_data = user.dict()
    user_data['hashed_password'] = get_password_hash(user_data.pop('password'))
    user_data.pop('tags', None)
    result = users_collection.insert_one(user_data)
    return UserInDB(**user_data, id=result.inserted_id)

def update_user(username: str, user: User):
    user_data = user.dict(exclude_unset=True)
    if 'password' in user_data:
        user_data['hashed_password'] = get_password_hash(user_data.pop('password'))
    users_collection.update_one({"username": username}, {"$set": user_data})
    return get_user(username)

#JWT Token Generation
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

#Authentication
async def authenticate_user(username: str, password: str):
    user = get_user(username)
    if not user or not verify_password(password, user['hashed_password']):
        return False
    return UserInDB(**user)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = get_user(username=token_data.username)
    if user is None:
        raise credentials_exception
    return UserInDB(**user)

#Token Endpoint
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    user = await authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

#User Endpoints
@app.post("/users/", response_model=UserInDB)
async def register_user(user: User):
    existing_user = get_user(user.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return create_user(user)

@app.get("/users/me", response_model=UserInDB)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.put("/users/me", response_model=UserInDB)
async def update_user_profile(user: User, current_user: User = Depends(get_current_user)):
    return update_user(current_user.username, user)

@app.put("/users/me/tags", response_model=UserInDB)
async def update_user_tags(tags: List[str], current_user: User = Depends(get_current_user)):
    user = get_user(current_user.username)
    users_collection.update_one({"username": user['username']}, {"$set": {"tags": tags}})
    return get_user(user['username'])

#Blog Endpoints
@app.post("/blogs/", response_model=BlogInDB)
async def create_blog(blog: Blog, current_user: User = Depends(get_current_user)):
    blog_data = blog.dict()
    blog_data['created_at'] = datetime.utcnow()
    result = blogs_collection.insert_one(blog_data)
    return BlogInDB(**blog_data, id=result.inserted_id)

@app.get("/blogs/", response_model=List[BlogInDB])
async def get_all_blogs(skip: int = 0, limit: int = 10):
    blogs = blogs_collection.find().skip(skip).limit(limit)
    return [BlogInDB(**blog) for blog in blogs]

@app.get("/blogs/{blog_id}", response_model=BlogInDB)
async def get_blog(blog_id: str):
    blog = blogs_collection.find_one({"_id": ObjectId(blog_id)})
    if not blog:
        raise HTTPException(status_code=404, detail="Blog not found")
    return BlogInDB(**blog)

@app.put("/blogs/{blog_id}", response_model=BlogInDB)
async def update_blog(blog_id: str, blog: Blog):
    blog_data = blog.dict(exclude_unset=True)
    blogs_collection.update_one({"_id": ObjectId(blog_id)}, {"$set": blog_data})
    return get_blog(blog_id)

@app.delete("/blogs/{blog_id}", status_code=204)
async def delete_blog(blog_id: str):
    result = blogs_collection.delete_one({"_id": ObjectId(blog_id)})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Blog not found")

@app.get("/dashboard", response_model=List[BlogInDB])
async def get_user_dashboard(current_user: User = Depends(get_current_user)):
    user_tags = current_user.tags
    relevant_blogs = blogs_collection.find({"tags": {"$in": user_tags}})
    sorted_blogs = relevant_blogs.sort("created_at", -1).limit(10)
    return [BlogInDB(**blog) for blog in sorted_blogs]
