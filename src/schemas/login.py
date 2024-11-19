from pydantic import BaseModel,EmailStr
from typing import Optional

class Register_User_Schema(BaseModel):
    user_name : str
    password : str
    email : EmailStr

class Get_All_User_Schema(BaseModel):
    id: str
    user_name: str
    email:str
    password: str

class Update_User_Schema(BaseModel):
    user_name: Optional[str] = None
    email:Optional[EmailStr] = None
    password: Optional[str] = None
 
class Reset_pass_Schema(BaseModel):
    user_email: EmailStr
    enter_old_password: str
    enter_new_password: str
    re_enter_new_password: str


class Forget_pass_Schema(BaseModel):

    otp: str
    enter_new_password: str
    re_enter_new_password: str
