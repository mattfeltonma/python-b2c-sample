import json
import os
import uuid
import requests
from flask import Flask, render_template, session, request, redirect, url_for
from flask_session import Session 
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp
import msal
import app_config

# Setup up a Flask instance and support server-side sessions using Flask-Session
app = Flask(__name__)
app.config.from_object(app_config)
Session(app)

# This section is needed for url_for("foo", _external=True) to automatically
# generate http scheme when this sample is running on localhost,
# and to generate https scheme when it is deployed behind reversed proxy.
# See also https://flask.palletsprojects.com/en/1.0.x/deploying/wsgi-standalone/#proxy-setups
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Setup form to change beneficiary
class EditBeneficiaryForm(FlaskForm):
    beneficiary_name = StringField('Beneficiary Name', validators=[DataRequired()])
    submit = SubmitField('Submit')

# Setup a submit button to redirect for a change to beneficiary
class ChangeBeneficiaryButton(FlaskForm):
    change_beneficiary = SubmitField()

# Retrieve an ID token and access token for the user and store the ID token claims in the server-side session
# Place the access token and id token into cache
def retrieve_id_token(code, scopes, redirect_uri, authority):
    cache = _load_cache()
    result = _build_msal_app(authority=authority, cache=cache).acquire_token_by_authorization_code(
        request.args['code'],
        scopes=scopes,
        redirect_uri=redirect_uri)
    if "error" in result:
        return result
    if not session.get('user'):
        session["user"] = result.get("id_token_claims")
    _save_cache(cache)

@app.route("/")
def index():
    if not session.get("user"):
        return redirect(url_for("login"))
    return render_template('index.html', user=session["user"], version=msal.__version__)

@app.route("/login")
def login():
    session["state"] = str(uuid.uuid4())
    auth_url = _build_auth_url(redirect="authorized", scopes=app_config.SCOPES, state=session["state"])
    return render_template("login.html", auth_url=auth_url, version=msal.__version__)

# Authenticate the user and send the user through the non-MFA B2C sign-up policy
@app.route(app_config.REDIRECT_PATH)
def authorized():
    if request.args.get('state') != session.get("state"):
        return redirect(url_for("index"))  # No-OP. Goes back to Index page
    if "error" in request.args:  # Authentication/Authorization failure
        return render_template("auth_error.html", result=request.args)
    if request.args.get('code'):
        result = retrieve_id_token(
            authority = app_config.AUTHORITY,
            code = request.args.get('code'),
            scopes = app_config.SCOPES,
            redirect_uri = url_for("authorized", _external=True)
        )
        if result != None: 
            return render_template("auth_error.html", result=result)
    return redirect(url_for("index"))

# Authenticate the user and send the user through the MFA B2C Policy
@app.route(app_config.REDIRECT_PATH_MFA)
def authorized_mfa():
    if request.args.get('state') != session.get("state"):
        return redirect(url_for("index"))  # No-OP. Goes back to Index page
    if "error" in request.args:  # Authentication/Authorization failure
        return render_template("auth_error.html", result=request.args)
    if request.args.get('code'):
        result = retrieve_id_token(
            authority = app_config.MFAAUTHORITY,
            code = request.args.get('code'),
            scopes = app_config.SCOPES,
            redirect_uri = url_for("authorized_mfa", _external=True)
        )
    return redirect(url_for("changeben"))

# Endpoint to logout
@app.route("/logout")
def logout():
    session.clear()  # Wipe out user and its token cache from session
    return redirect(  # Also logout from your tenant's web session
        app_config.AUTHORITY + "/oauth2/v2.0/logout" +
        "?post_logout_redirect_uri=" + url_for("index", _external=True))

# Test the API's public endpoint
@app.route("/publicapi")
def publicapi():
    api_data = requests.get( 
        f"{app_config.API_ENDPOINT}/public"
        )
    return render_template('apitest.html', user=session["user"], result=api_data.text)

# Query the API and display the user's policy information
@app.route("/acctinfo")
def acctinfo():
    token = _get_token_from_cache(app_config.SCOPES)
    if not token:
        return redirect(url_for("login"))
    api_data = requests.get( 
        f"{app_config.API_ENDPOINT}/acctinfo",
        headers={'Authorization': 'Bearer ' + token['access_token']},
        )
    if api_data.status_code == 200:
        form = ChangeBeneficiaryButton()
        if form.validate():
            return redirect(url_for('change'))
        return render_template('account.html',user=session["user"],account=json.loads(api_data.text),form=form)
    else:
        return render_template("auth_error.html", result=api_data)

# Modify account data in backend API
@app.route("/change")
def change():
    auth_url = _build_auth_url(authority=app_config.MFAAUTHORITY, scopes=app_config.SCOPES, state=session["state"], redirect="authorized_mfa")
    return redirect(auth_url)

# Allow the user to change the beneficiary
@app.route("/changeben", methods=["GET","POST"])
def changeben():
    token = _get_token_from_cache(app_config.SCOPES)
    form = EditBeneficiaryForm()
    if form.validate_on_submit():
        api_data = requests.get( 
            f"{app_config.API_ENDPOINT}/acctupdate",
            headers={'Authorization': 'Bearer ' + token['access_token']},
            params= {'name':form.beneficiary_name.data}
            )
        return redirect(url_for('acctinfo'))
    return render_template('bene.html',user=session["user"],form=form)

# Display the claims in the user's ID token
@app.route("/claims")
def claims():
    claim_list = json.dumps(session["user"], sort_keys = True, indent = 4, separators = (',', ': '))
    return render_template('claims.html',user=session["user"],claims=claim_list)

# Load the token cache
def _load_cache():
    cache = msal.SerializableTokenCache()
    if session.get("token_cache"):
        cache.deserialize(session["token_cache"])
    return cache

# Save a token to the token cache
def _save_cache(cache):
    if cache.has_state_changed:
        session["token_cache"] = cache.serialize()

# Handle building the MSAL client
def _build_msal_app(cache=None, authority=None):
    return msal.ConfidentialClientApplication(
        app_config.CLIENT_ID, authority=authority or app_config.AUTHORITY,
        client_credential=app_config.CLIENT_SECRET, token_cache=cache)

# Handle building the B2C URL
def _build_auth_url(authority=None, scopes=None, state=None, redirect=None):
    return _build_msal_app(authority=authority).get_authorization_request_url(
        scopes or [],
        state=state or str(uuid.uuid4()),
        redirect_uri=url_for(redirect, _external=True))

# Retrieve a token from token cache
def _get_token_from_cache(scope=None):
    cache = _load_cache()  # This web app maintains one cache per session
    cca = _build_msal_app(cache=cache)
    accounts = cca.get_accounts()
    if accounts:  # So all account(s) belong to the current signed-in user
        result = cca.acquire_token_silent(scope, account=accounts[0])
        _save_cache(cache)
        return result

app.jinja_env.globals.update(_build_auth_url=_build_auth_url)  # Used in template

if __name__ == "__main__":
    app.run(host='0.0.0.0')

