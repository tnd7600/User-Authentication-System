from database.database import SessionLocal
from src.models.login import User,Otp
from fastapi import HTTPException
from passlib.context import CryptContext
from logs.log_config import logger

db=SessionLocal()




def find_same_email(email:str):
    find_same_email = db.query(User).filter(User.email == email).first()
    logger.info("Verifing Email")
    
    if find_same_email:
        if find_same_email.is_active == True:
            logger.error("Email already exists")
            raise HTTPException(status_code=400, detail="Email already exists")
        if find_same_email.is_active == False:
            logger.error("Email already exist but this account is deleted")
            raise HTTPException(status_code=400, detail="Email already exist but this account is deleted try with different email")





def find_same_username(username:str):
    find_same_username = db.query(User).filter(User.user_name == username and User.is_active==True).first()
    logger.info("Verifing Username")

    if find_same_username:
        if find_same_username.is_active == True:
            logger.error("Username already exists")
            raise HTTPException(status_code=400, detail="Username already exists")
        if find_same_username.is_active == False:
            logger.error("Username already exists but this account is deleted")
            raise HTTPException(status_code=400, detail="Username already exists but this account is deleted try with different username")





pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def pass_checker(user_pass, hash_pass):
    if pwd_context.verify(user_pass, hash_pass):
        return True
    else:
        logger.error("Password is incorrect")
        raise HTTPException(status_code=401, detail="Password is incorrect")









import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config import SENDER_EMAIL_ID,EMAIL_PASSKEY

def send_email(receiver, subject, body):

    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = SENDER_EMAIL_ID
    smtp_pass = EMAIL_PASSKEY


    msg = MIMEMultipart()
    msg['From'] = SENDER_EMAIL_ID
    msg['To'] = receiver
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.set_debuglevel(1) 
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(SENDER_EMAIL_ID, receiver, msg.as_string())
        return True
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Failed to send OTP email")



from config import SECRET_KEY,ALGORITHM
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import HTTPException, status


def get_token(id:str,user_name: str, email: str):

    payload = {
        "id": id,
        "username": user_name,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=30),  
    }

    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token}



def decode_token(token: str):
    try:
    
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        id = payload.get("id")
        email = payload.get("email")
        username = payload.get("username")

        if not id or not username or not email:

            logger.error("Invalid token")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid token",
            )
        return id , username , email
    
    except jwt.ExpiredSignatureError:
        logger.error("Token has expired")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token has expired",
        )
    
    except jwt.InvalidTokenError:
        logger.error("Invalid token")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token",
        )
    

    
import random,uuid

def generate_otp(email):
    logger.info("Getting User Data")
    find_user_with_email = db.query(User).filter(User.email == email,User.is_active == True, User.is_deleted == False).first()
    if not find_user_with_email:
        logger.error("No User Found")
        raise HTTPException(status_code=400, detail="User not found")
    
    logger.info("Generating OTP")
    random_otp = random.randint(1000,9999)
    print("---------------------------------------")
    print(random_otp)
    print("---------------------------------------")

    new_otp = Otp(
        id = str(uuid.uuid4()),
        user_id = find_user_with_email.id,
        email = find_user_with_email.email,
        otp = random_otp
    )
  
    logger.info("Sending OTP email.")
    send_email(find_user_with_email.email, "Test Email", f"Otp is {random_otp}")

    db.add(new_otp)
    db.commit()
    db.refresh(new_otp)
    logger.success("Verification OTP Sent Successfully")



def verify_otp(email, otp):
    find_otp = db.query(Otp).filter(Otp.email == email, Otp.otp == otp).first()

    if not find_otp:
        logger.error("Wrong OTP Entered")
        raise HTTPException(status_code=400, detail="OTP not found")
    logger.info("Verifing OTP")

    db.delete(find_otp)
    db.commit()
    