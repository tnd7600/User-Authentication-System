from fastapi import APIRouter,HTTPException
from database.database import SessionLocal
from src.schemas.login import Update_User_Schema,Get_All_User_Schema,Register_User_Schema,Reset_pass_Schema,Forget_pass_Schema
from src.models.login import User,Otp
from src.utils.login import find_same_email,find_same_username,pwd_context,get_token,pass_checker,generate_otp,generate_otp,verify_otp
from logs.log_config import logger
import uuid,random

user_router = APIRouter()

db = SessionLocal()


@user_router.post("/register_user")
def Register_User(user:Register_User_Schema):
    logger.info("Registering New User")
    new_user = User(
        id = str(uuid.uuid4()),
        user_name = user.user_name,
        email = user.email,
        password = pwd_context.hash(user.password)
    )

    find_minimum_one_entry = db.query(User).first()
    if find_minimum_one_entry:
        find_same_email(user.email)
        find_same_username(user.user_name)

    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    logger.success("Users Registered Successfully")

    return "User Register Successfully now go for the verification"


@user_router.post("/generate_otp")
def Generate_otp(email:str):
    generate_otp(email)
    return "OTP generated successfully"



@user_router.get("/verify_otp")
def Verify_otp(email:str, otp:str):
    logger.info("Getting User Data")
    find_user = db.query(User).filter(User.email == email, User.is_active == True, User.is_verified == False, User.is_deleted == False).first()

    if not find_user:
        logger.error("No User Found")
        raise HTTPException(status_code=400, detail="User not found")
    
    verify_otp(email,otp)

    find_user.is_verified = True
    db.commit()
    db.refresh(find_user)
    logger.success("OTP Verified")
    return "OTP verified successfully"



@user_router.get("/login_user")
def Login_user(email:str, password:str):
    logger.info("Getting User Data")
    find_user_with_email = db.query(User).filter(User.email == email, User.is_active == True, User.is_verified == True, User.is_deleted == False).first()

    if not find_user_with_email:
        logger.error("User Not Found")
        raise HTTPException(status_code=400, detail="User not found")
    
    logger.info("Verifing Password")
    pass_checker(password, find_user_with_email.password)
      
    access_token = get_token(find_user_with_email.id, find_user_with_email.user_name, find_user_with_email.email)
    logger.success("User Login Successfully")

    return "Login successfull",access_token



@user_router.get("/get_all_users",response_model=list[Get_All_User_Schema])
def Get_All_Users():
    logger.info("Getting Active Users Data")
    all_user_with_condition = db.query(User).filter(User.is_active == True, User.is_deleted == False, User.is_verified == True).all() 
    if not all_user_with_condition:
        logger.error("No Users Found")
        raise HTTPException(status_code=400, detail="No Users Found")
    logger.success("Active Users Data Retrived Successfully")
    return all_user_with_condition



@user_router.get("/get_user/{user_email}", response_model=Get_All_User_Schema)
def Get_User(user_email:str):
    logger.info("Getting User Data")
    find_user = db.query(User).filter(User.email == user_email,User.is_active == True , User.is_deleted == False , User.is_verified == True).first()

    if not find_user:
        logger.error("No User Found")
        raise HTTPException(status_code=400, detail="User Not Found")
    
    logger.success("User Data Retrived Successfully")
    return find_user



@user_router.patch("/update_user/{user_email}")
def Update_User(user_email:str, user:Update_User_Schema):

    logger.info("Getting User Data")
    find_user = db.query(User).filter(User.email == user_email,User.is_active == True , User.is_verified == True , User.is_deleted == False).first()

    if not find_user:
        logger.error("User Not Found")
        raise HTTPException(status_code=400, detail="User not found")
    
    new_user_schema_without_none = user.model_dump(exclude_none=True)

    for key,value in new_user_schema_without_none.items():
        if key == "password":
            setattr(find_user,key,pwd_context.hash(value))
        else:
            find_same_email(value)
            find_same_username(value)
            setattr(find_user,key,value)

    db.commit()
    db.refresh(find_user)
    logger.success("User Data Updated Successfully")
    
    return {"message":"user update successfully","data":find_user}



@user_router.delete("/delete_user/{user_email}")
def Delete_User(user_email:str):

    logger.info("Getting User Data")
    find_user = db.query(User).filter(User.email == user_email,User.is_active == True , User.is_verified == True ).first()

    if not find_user:
        logger.error("User Not Found")
        raise HTTPException(status_code=400, detail="User not found")

    if find_user.is_deleted == True:
        logger.error("User Already Deleted")
        raise HTTPException(status_code=400, detail="User already deleted")
    

    find_user.is_deleted = True
    find_user.is_active = False
    find_user.is_verified = False

    db.commit()
    db.refresh(find_user)
    logger.success("User Data Deleted Successfully")

    return {"message":"user deleted successfully","data":find_user}

@user_router.put("/reset_password")
def Reset_Password(user:Reset_pass_Schema):
    find_user = db.query(User).filter(User.email == user.user_email,User.is_active == True , User.is_verified == True , User.is_deleted == False).first()

    if not find_user:
        logger.error("User Not Found")
        raise HTTPException(status_code=400, detail="User not found")
    
    logger.info("Verifing Password")
    pass_checker(user.enter_old_password, find_user.password)
 
    if user.enter_new_password == user.re_enter_new_password:
        find_user.password ==  pwd_context.hash(user.enter_new_password)
    else:
        logger.error("password does't match")
        raise HTTPException(status_code=400, detail="Password Does't Match")
    
    db.commit()
    db.refresh(find_user)
    logger.success("Password Updated")

    return "Password Updated Sucessfully"



@user_router.post("/forget_password_generate_otp")
def Forget_Password_Generate_otp(email:str):
    generate_otp(email)
    return "OTP generated successfully"



@user_router.put("/forget_password")
def Forget_Password(user:Forget_pass_Schema):
    logger.info("Getting User Data")
    find_user = db.query(User).filter(User.email == user.user_email, User.is_active == True, User.is_verified == True, User.is_deleted == False).first()

    if not find_user:
        logger.error("No User Found")
        raise HTTPException(status_code=400, detail="User not found")
    
    verify_otp(user.user_email,user.otp)

    find_user.password ==  pwd_context.hash(user.enter_new_password)

    db.refresh(find_user)
    logger.success("Password Changed")
    return "Password Changed successfully"


