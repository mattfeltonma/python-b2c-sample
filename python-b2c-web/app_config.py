import os

# Set the client id and client secret of the web app
CLIENT_ID = os.getenv('CLIENT_ID')
CLIENT_SECRET = os.getenv('CLIENT_SECRET')

# Setup the redirect URIs configured for the application
REDIRECT_PATH = "/getAToken"
REDIRECT_PATH_MFA = "/getATokenMFA"

# Setup the variables required for the B2C functionality
b2c_tenant = os.getenv('B2C_DIR')
signupsignin_user_flow = "B2C_1_signupsignin1"
signupsignin_user_flow_mfa = "B2C_1_signupsignin1_mfa"
editprofile_user_flow = "B2C_1_profileediting1"
resetpassword_user_flow = "B2C_1_passwordreset1"
authority_template = "https://{tenant}.b2clogin.com/{tenant}.onmicrosoft.com/{user_flow}"

AUTHORITY = authority_template.format(
    tenant=b2c_tenant, user_flow=signupsignin_user_flow)
MFAAUTHORITY = authority_template.format(
    tenant=b2c_tenant, user_flow=signupsignin_user_flow_mfa)
B2C_PROFILE_AUTHORITY = authority_template.format(
    tenant=b2c_tenant, user_flow=editprofile_user_flow)
B2C_RESET_PASSWORD_AUTHORITY = authority_template.format(
    tenant=b2c_tenant, user_flow=resetpassword_user_flow)

REDIRECT_PATH = "/getAToken"
REDIRECT_PATH_MFA = "/getATokenMFA"

# Set the address that the API is running under
API_ENDPOINT = os.getenv('API_ENDPOINT', default = 'http://python-b2c-api:5001')

# Scopes the application need to use
SCOPES = [f"https://{b2c_tenant}.onmicrosoft.com/api/Accounts.Read",f"https://{b2c_tenant}.onmicrosoft.com/api/Accounts.Write"]

# Specifies to flask-sessions module that server-side sessions should be written to disk
SESSION_TYPE = "filesystem"

# Generate a random key to protect against CSRF
SECRET_KEY = os.urandom(32)