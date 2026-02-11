import requests
import json
from typing import Optional
import os
from dotenv import load_dotenv
import re
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

load_dotenv()  # Load environment variables from a .env file if present
# You will need to install the 'requests' library if you haven't already:
# pip install requests

# OAuth 2.0 authentication method with the Microsoft Graph API.

def send_password_reset_email(recipient_email: str, reset_link: str) -> Optional[str]:
    """
    Sends a password reset email to a user via the Microsoft Graph API using OAuth 2.0.

    Args:
        recipient_email: The email address of the user who requested the reset.
        reset_link: The unique URL for the user to reset their password.

    Returns:
        None if the email was sent successfully, or an error message string if it failed.
    """
    
    TENANT_ID = os.getenv("TID")  # Your Azure AD tenant ID
    CLIENT_ID = os.getenv("CID")  # Your Azure AD client ID
    CLIENT_SECRET = os.getenv("SID")  # Your Azure AD client secret

    print(f"DEBUG - TENANT_ID: {TENANT_ID}")
    print(f"DEBUG - CLIENT_ID: {CLIENT_ID}")
    print(f"DEBUG - CLIENT_SECRET: {'***' if CLIENT_SECRET else None}")
    
    if not all([TENANT_ID, CLIENT_ID, CLIENT_SECRET]):
        return "Environment variables not loaded properly"
    

    SENDER_EMAIL = "noreply@mentormate.co.za"  
    SENDER_NAME = "MentorMate"

    # --- 1. Acquire an Access Token ---
    token_url = f"https://login.microsoftonline.com/{TENANT_ID}/oauth2/v2.0/token"
    token_data = {
        "grant_type": "client_credentials",
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://graph.microsoft.com/.default"
    }
    
    try:
        token_response = requests.post(token_url, data=token_data)
        token_response.raise_for_status()
        access_token = token_response.json().get("access_token")
        if not access_token:
            return "Failed to acquire access token. Check your credentials and permissions."
    except requests.exceptions.RequestException as e:
        error_message = f"Error acquiring token: {e.response.text if e.response else e}"
        return error_message


    # --- 2. Construct the Email Body (HTML) ---
    html_body = f"""
    <html>
    <head>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; }}
            .container {{ max-width: 600px; margin: 20px auto; padding: 20px; border: 1px solid #ddd; border-radius: 8px; }}
            .button {{ background-color: #007BFF; color: white; padding: 12px 25px; text-decoration: none; border-radius: 5px; display: inline-block; }}
            .footer {{ margin-top: 20px; font-size: 0.8em; color: #777; }}
        </style>
    </head>
    <body>
        <div class="container">
            <h2>Password Reset Request</h2>
            <p>Hi,</p>
            <p>We received a request to reset your password for your account with {SENDER_NAME}. If you didn't make this request, you can safely ignore this email.</p>
            <p>To reset your password, please click the button below. This link is valid for one hour.</p>
            <p style="text-align: center;">
                <a href="{reset_link}" class="button">Reset Password</a>
            </p>
            <p>If you're having trouble with the button, you can copy and paste this URL into your web browser:</p>
            <p><a href="{reset_link}">{reset_link}</a></p>
            <div class="footer">
                <p>Thanks,<br>The {SENDER_NAME} Team</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    # --- 3. Create the Email Payload for the Graph API ---
    email_payload = {
        "message": {
            "subject": "Reset Your Password",
            "body": {
                "contentType": "HTML",
                "content": html_body
            },
            "toRecipients": [
                {
                    "emailAddress": {
                        "address": recipient_email
                    }
                }
            ],
             "from": {
                "emailAddress": {
                    "name": SENDER_NAME,
                    "address": SENDER_EMAIL
                }
            }
        },
        "saveToSentItems": "true"
    }

    # --- 4. Send the Email via Graph API ---
    send_mail_url = f"https://graph.microsoft.com/v1.0/users/{SENDER_EMAIL}/sendMail"
    headers = {
        'Authorization': f'Bearer {access_token}',
        'Content-Type': 'application/json'
    }

    try:
        response = requests.post(send_mail_url, headers=headers, data=json.dumps(email_payload))
        response.raise_for_status()  # Raises an exception for 4xx/5xx status codes
        print(f"Password reset email successfully sent to {recipient_email}")
        return None
    except requests.exceptions.HTTPError as e:
        error_message = f"An HTTP error occurred sending the email: {e.response.text}"
        print(error_message)
        return error_message
    except Exception as e:
        error_message = f"An unexpected error occurred: {e}"
        print(error_message)
        return error_message


# # --- Example Usage ---
# if __name__ == "__main__":
    #TEST SCENARIO
    # Simulate a user requesting a password reset.

    # user_email_to_reset = ""
    # unique_reset_token = "a1b2c3d4e5f6g7h8i9j0" # Example token
    # password_reset_url = f"https://mycompanydomain.com/reset-password?token={unique_reset_token}"

    # Call the function to send the email
    # result = send_password_reset_email(user_email_to_reset, password_reset_url)

    # if result:
    #     print(f"Failed to send email. Reason: {result}")


def send_contact_email(
    sender_name: str, 
    sender_email: str, 
    subject: str, 
    message: str, 
    recipient_email: Optional[str] = None,
    cc_emails: Optional[list] = None,
    bcc_emails: Optional[list] = None
) -> Optional[str]:
    """
    Sends a contact form email from a user to the company via SMTP.

    Args:
        sender_name: The name of the person sending the message.
        sender_email: The email address of the person sending the message.
        subject: The subject of the email.
        message: The body/content of the email message.
        recipient_email: The recipient email address (company email). 
                        If not provided, uses COMPANY_EMAIL from env.
        cc_emails: List of email addresses to CC (optional).
        bcc_emails: List of email addresses to BCC (optional).

    Returns:
        None if the email was sent successfully, or an error message string if it failed.
    """
    
    # Validate email format
    def is_valid_email(email: str) -> bool:
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None
    
    # Get SMTP configuration from environment variables
    SMTP_SERVER = os.getenv('SMTP_SERVER')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USERNAME = os.getenv('SMTP_USERNAME')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD')
    SMTP_FROM = os.getenv('SMTP_FROM', SMTP_USERNAME)
    COMPANY_EMAIL = os.getenv('COMPANY_EMAIL', 'mentormatecoza@gmail.com')
    
    # Use provided recipient email or default to company email
    recipient_email = recipient_email or COMPANY_EMAIL
    
    # Validate required environment variables
    required_env_vars = ['SMTP_SERVER', 'SMTP_USERNAME', 'SMTP_PASSWORD']
    missing_vars = [var for var in required_env_vars if not os.getenv(var)]
    if missing_vars:
        return f"SMTP configuration is missing. Please check environment variables: {', '.join(missing_vars)}"
    
    # Validate input parameters
    if not all([sender_name, sender_email, subject, message]):
        return "Missing required fields: name, email, subject, and message are all required."
    
    # Validate email format
    if not is_valid_email(sender_email):
        return f"Invalid sender email format: {sender_email}"
    
    if recipient_email and not is_valid_email(recipient_email):
        return f"Invalid recipient email format: {recipient_email}"
    
    if not is_valid_email(SMTP_FROM):
        return f"Invalid FROM email in configuration: {SMTP_FROM}"
    
    try:
        # Prepare all recipients
        all_recipients = [recipient_email]
        if cc_emails:
            all_recipients.extend(cc_emails)
        if bcc_emails:
            all_recipients.extend(bcc_emails)
        
        # Create plain text version
        text_body = f"""Contact Form Submission
========================

From: {sender_name}
Email: {sender_email}
Subject: {subject}

Message:
--------
{message}

---
This email was sent via the contact form on MentorMate website.
"""
        
        # Build email message
        email_msg = MIMEMultipart('alternative')
        email_msg['Subject'] = f"Contact Form: {subject}"
        email_msg['From'] = SMTP_FROM
        email_msg['To'] = recipient_email
        email_msg['Reply-To'] = sender_email
        
        if cc_emails:
            invalid_cc = [email for email in cc_emails if not is_valid_email(email)]
            if invalid_cc:
                return f"Invalid CC email addresses: {', '.join(invalid_cc)}"
            email_msg['Cc'] = ', '.join(cc_emails)
        
        # Attach plain text
        email_msg.attach(MIMEText(text_body, 'plain'))
        
        # Simple HTML version
        html_body = f"""<html><body>
<h2>Contact Form Submission</h2>
<p><strong>From:</strong> {sender_name}</p>
<p><strong>Email:</strong> <a href="mailto:{sender_email}">{sender_email}</a></p>
<p><strong>Subject:</strong> {subject}</p>
<p><strong>Message:</strong></p>
<p>{message.replace(chr(10), '<br>')}</p>
<hr>
<p><small>This email was sent via the contact form on MentorMate website.</small></p>
</body></html>"""
        
        email_msg.attach(MIMEText(html_body, 'html'))
        
        # Send via SMTP - Simple and direct approach
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(email_msg, from_addr=SMTP_FROM, to_addrs=all_recipients)
        
        print(f"Contact email successfully sent from {sender_name} to company contact")
        return None
        
    except smtplib.SMTPAuthenticationError as e:
        error_message = f"SMTP authentication failed: {str(e)}"
        # Don't log passwords in production!
        print("SMTP authentication failed. Check credentials.")
        return error_message
    except smtplib.SMTPException as e:
        error_message = f"SMTP error: {str(e)}"
        print(f"SMTP error: {error_message}")
        return error_message
    except Exception as e:
        error_message = f"Unexpected error: {str(e)}"
        print(f"Unexpected error: {error_message}")
        return error_message


