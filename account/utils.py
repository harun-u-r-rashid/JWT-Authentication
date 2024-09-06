import random
from django.core.mail import EmailMessage
from .models import Account, OneTimePassword
from django.conf import settings
from django.template.loader import render_to_string
from django.core.mail import EmailMultiAlternatives

def generateOtp():
    return ''.join(random.choices('123456789', k=6))

def send_code_to_user(email):
    try:
        otp_code = generateOtp()
        user = Account.objects.get(email=email)
        
        # Save OTP to the database
        otp_obj = OneTimePassword.objects.create(account=user, code=otp_code)
        otp_obj.save()
        
        email_subject = "Activate your account"
        email_body = render_to_string('otpEmail.html', {'otp_code': otp_code})
        
        email_message = EmailMultiAlternatives(email_subject, '', to=[user.email])
        email_message.attach_alternative(email_body, 'text/html')
        email_message.send()
        
    except Exception as e:
        return f"Failed to send OTP email to {email}: {str(e)}"



# import logging
# from django.core.mail import EmailMessage
# from .models import Account, OneTimePassword
# from django.conf import settings

# logger = logging.getLogger(__name__)

# def send_code_to_user(email):
#     try:
#         subject = "One time password for Email Verification"
#         otp_code = generateOtp()
#         print("OTP", otp_code)
#         account = Account.objects.get(email=email)
#         current_site = "myAuth.com"
#         email_body = f"Hi {account.first_name}, thanks for signing up on {current_site}, please verify your email with the one-time passcode: {otp_code}"
#         from_email = settings.DEFAULT_FROM_EMAIL

#         OneTimePassword.objects.create(account=account, code=otp_code)

#         send_email = EmailMessage(
#             subject=subject, body=email_body, from_email=from_email, to=[email]
#         )
#         send_email.send(fail_silently=False)
#         logger.info(f"Sent OTP email to {email}")

#     except Exception as e:
#         logger.error(f"Failed to send OTP email to {email}: {str(e)}")


def send_email_to_reset_password(data):
    email=EmailMessage(
        subject=data['email_subject'],
        body=data['email_body'],
        from_email=settings.EMAIL_HOST_USER,
        to=[data['to_email']]
    )
    email.send()