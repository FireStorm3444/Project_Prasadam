import os
import random
import uuid
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
from werkzeug.middleware.proxy_fix import ProxyFix
import firebase_admin
from dotenv import load_dotenv
from firebase_admin import credentials, firestore
from google.cloud.firestore import ArrayUnion, DELETE_FIELD, transactional
from flask import Flask, render_template, request, redirect, url_for, session, flash
from google.auth.transport import requests as grequests
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from werkzeug.security import generate_password_hash, check_password_hash
from mailjet_rest import Client

# Load environment variables
load_dotenv()

# Allow insecure OAuth flow during development
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)
app.secret_key = os.environ.get('FLASK_SECRET', 'dev_secret')

# Google OAuth client file
GOOGLE_CLIENT_SECRETS_FILE = "/etc/secrets/client_secret.json"

# Initialize Firebase
try:
    cred = credentials.Certificate("/etc/secrets/firebase_key.json")
    firebase_admin.initialize_app(cred)
    db = firestore.client()
except Exception as e:
    print("Firebase init error:", e)
    db = None


# Small helpers
def send_otp(email, otp):
    """Sends an OTP using the Mailjet API."""
    api_key = os.environ.get("MAILJET_API_KEY")
    api_secret = os.environ.get("MAILJET_SECRET_KEY")

    print(f"DEBUG: Using API Key: '{api_key}' and Secret Key: '{api_secret}'")

    if not api_key or not api_secret:
        print("Mailjet API keys not configured.")
        return False

    mailjet = Client(auth=(api_key, api_secret), version='v3.1')

    # NOTE: You must verify a sender email/domain in your Mailjet account.
    # Replace 'your-verified-sender@yourdomain.com' with an email you have verified in Mailjet.
    # For now, you can use the same email you are sending from.
    sender_email = "shekhar99bd@gmail.com"

    data = {
        'Messages': [
            {
                "From": {
                    "Email": sender_email,
                    "Name": "Prasadam App"
                },
                "To": [
                    {
                        "Email": email,
                        "Name": "User"
                    }
                ],
                "Subject": "Your Prasadam Verification Code",
                "TextPart": f"Your verification code is: {otp}"
            }
        ]
    }

    try:
        result = mailjet.send.create(data=data)
        if result.status_code == 200:
            print("OTP email sent successfully via Mailjet.")
            return True
        else:
            print(f"Mailjet error: {result.status_code} - {result.json()}")
            return False
    except Exception as e:
        print(f"An exception occurred with Mailjet: {e}")
        return False


def normalize_role(value):
    if not value:
        return 'donor'
    v = str(value).strip().lower()
    if 'super' in v and 'admin' in v:
        return 'super_admin'
    if v in ('admin', 'administrator'):
        return 'admin'
    if 'driver' in v:
        return 'driver'
    if 'recipient' in v or 'ngo' in v:
        return 'recipient'
    if 'donor' in v or 'user' in v:
        return 'donor'
    return v.replace(' ', '_').replace('-', '_')


def get_user_profile_picture(email):
    try:
        docs = db.collection('users').where('email', '==', email).limit(1).get()
        if docs:
            return docs[0].to_dict().get('profile_picture', 'https://avatar.iran.liara.run/public/3')
    except Exception as e:
        print('profile pic error', e)
    return 'https://avatar.iran.liara.run/public/3'


def _get_added_doc_id(add_result):
    # Firestore add() may return DocumentReference or (DocumentReference, write_result) or (write_time, DocumentReference)
    try:
        from google.cloud.firestore_v1.document import DocumentReference
        if isinstance(add_result, (list, tuple)):
            for item in add_result:
                if hasattr(item, 'id') and isinstance(item, DocumentReference):
                    return item.id
        elif hasattr(add_result, 'id'):
            return add_result.id
    except Exception:
        pass
    return None

# Helper to perform array-union updates without relying on firestore.ArrayUnion at call sites.
def _safe_array_union_update(doc_ref, field_name, values):
    """Fetches the document, performs a set-like union of the array field with values, and updates the document.
    This avoids direct dependency on firestore.ArrayUnion which some static tools may warn about.
    """
    try:
        snap = doc_ref.get()
        if not snap.exists:
            # If doc doesn't exist, create it with the array
            doc_ref.set({field_name: list({v for v in values})}, merge=True)
            return
        data = snap.to_dict() or {}
        existing = data.get(field_name, []) or []
        # Make sure we operate on list of strings
        existing_set = set(existing)
        for v in values:
            if v not in existing_set:
                existing.append(v)
                existing_set.add(v)
        doc_ref.update({field_name: existing})
    except Exception as e:
        # Fallback: try using firestore array operations
        try:
            doc_ref.update({field_name: ArrayUnion(values)})
        except Exception:
            raise

# Helper function to get user affiliations
def get_user_affiliations(user_id):
    try:
        user_doc = db.collection('users').document(user_id).get()
        if user_doc.exists:
            return user_doc.to_dict().get('affiliations', [])
        return []
    except Exception:
        return []

@app.route('/home')
def home():
    if 'email' not in session or session.get('role') != 'donor':
        flash('You must be a donor')
        return redirect(url_for('login'))
    profile_picture = get_user_profile_picture(session.get('email'))
    user_name = session.get('user_name', 'User')
    user_id = session.get('user_id')
    listings_list = []
    try:
        # Get donor's listings from listings collection
        for doc in db.collection('listings').where('donor_id', '==', user_id).stream():
            d = doc.to_dict()
            d['id'] = doc.id
            listings_list.append(d)

        # Sort by timestamp (most recent first)
        listings_list.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return render_template('dashboard_donor.html',
                            user_name=user_name,
                            requests=listings_list,  # Keep variable name as requests for template compatibility
                            profile_picture=profile_picture)
    except Exception as e:
        flash(f'Error loading dashboard: {e}')
        return render_template('dashboard_donor.html',
                            user_name=user_name,
                            requests=[],
                            profile_picture=profile_picture)

# Routes
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if not db:
            flash('Database error')
            return redirect(url_for('login'))

        try:
            users = db.collection('users').where('email', '==', email).limit(1).get()
            if not users:
                flash('Invalid credentials')
                return redirect(url_for('login'))
            user_doc = users[0]
            user = user_doc.to_dict()

            session['role'] = normalize_role(user.get('role', 'donor'))
            session['user_name'] = user.get('user_name', user.get('name', 'User'))

            # If user has a password, verify
            if user.get('password') and check_password_hash(user['password'], password):
                otp = str(random.randint(100000, 999999))
                otp_expiry = datetime.now() + timedelta(minutes=10)
                user_doc.reference.update({'otp': otp, 'otp_expiry': otp_expiry})
                # if send_otp(email, otp):
                session['email'] = email
                return redirect(url_for('otp'))
                # else:
                #     flash('Failed to send OTP')
            else:
                flash('Invalid credentials')
        except Exception as e:
            flash(f'Login error: {e}')
        return redirect(url_for('login'))
    return render_template('index.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out')
    return redirect(url_for('landing_page'))


# Google OAuth - initiate
@app.route('/login/google')
def login_google():
    base_url = os.environ.get('BASE_URL', 'http://localhost:5000')
    redirect_uri = f'{base_url}/google/callback'
    try:
        flow = Flow.from_client_secrets_file(
            GOOGLE_CLIENT_SECRETS_FILE,
            scopes=["https://www.googleapis.com/auth/userinfo.email", "openid"],
            redirect_uri = redirect_uri
        )
        auth_url, state = flow.authorization_url(prompt='select_account', access_type='offline', include_granted_scopes='true')
        session['state'] = state
        return redirect(auth_url)
    except Exception as e:
        flash(f'Google login error: {e}')
        return redirect(url_for('login'))


@app.route('/google/callback')
def callback():
    base_url = os.environ.get('BASE_URL', 'http://localhost:5000')
    redirect_uri = f'{base_url}/google/callback'
    try:
        if request.args.get('__debugger__') == 'yes':
            return '', 204
        if request.args.get('error'):
            flash('Google authentication cancelled')
            return redirect(url_for('login'))

        authorization_response = request.url
        flow = Flow.from_client_secrets_file(
            GOOGLE_CLIENT_SECRETS_FILE,
            scopes=["https://www.googleapis.com/auth/userinfo.email", "openid"],
            redirect_uri=redirect_uri
        )

        flow.state = session.get('state')
        flow.fetch_token(authorization_response=authorization_response)
        session.pop('state', None)
        creds = flow.credentials
        req = grequests.Request()
        idinfo = id_token.verify_oauth2_token(id_token=creds.id_token, request=req, audience=flow.client_config['client_id'])
        session['email'] = idinfo.get('email')
        session['user_name'] = idinfo.get('name')

        # Check user in DB
        users = db.collection('users').where('email', '==', session['email']).get()
        if users:
            user_doc = users[0]
            user = user_doc.to_dict()
            session['role'] = normalize_role(user.get('role', 'donor'))
            session['user_name'] = user.get('user_name', user.get('name', session['user_name']))
            # issue OTP for second factor
            otp = str(random.randint(100000, 999999))
            otp_expiry = datetime.now() + timedelta(minutes=10)
            user_doc.reference.update({'otp': otp, 'otp_expiry': otp_expiry})
            # send_otp(session['email'], otp)
            return redirect(url_for('otp'))
        else:
            # New Google users go to registration page
            return redirect(url_for('register_google'))

    except Exception as e:
        print('google callback error', e)
        flash('Google login failed')
        return redirect(url_for('login'))


# Manual registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        name = request.form.get('name')
        usertype = (request.form.get('usertype') or '').strip().lower()

        if not db:
            flash('DB error')
            return redirect(url_for('register'))
        try:
            exists = db.collection('users').where('email', '==', email).get()
            if exists:
                flash('User exists')
                return redirect(url_for('register'))

            role = 'donor'
            if usertype in ('ngo', 'recipient'):
                role = 'recipient'
            elif usertype == 'driver':
                role = 'driver'

            hashed = generate_password_hash(password)
            user_data = {
                'user_name': name,
                'email': email,
                'phone': request.form.get('phone'),
                'address': request.form.get('address'),
                'password': hashed,
                'role': role,
                'is_verified': False if role == 'recipient' else True,
                'affiliations': [],
                'affiliated_by': None,
                'status': 'active',
                'created_at': datetime.now().isoformat()
            }
            db.collection('users').add(user_data)
            flash('Registered successfully')
            return redirect(url_for('login'))
        except Exception as e:
            flash(f'Registration error: {e}')
            return redirect(url_for('register'))
    return render_template('register.html')


# OTP verification
@app.route('/otp', methods=['GET', 'POST'])
def otp():
    email = session.get('email')
    if not email:
        return redirect(url_for('login'))
    if request.method == 'POST':
        entered = request.form.get('otp')
        docs = db.collection('users').where('email', '==', email).limit(1).get()
        if not docs:
            flash('User not found')
            return redirect(url_for('login'))
        user_doc = docs[0]
        user = user_doc.to_dict()
        session['user_id'] = user_doc.id
        session['role'] = normalize_role(user.get('role', 'donor'))
        session['user_name'] = user.get('user_name', user.get('name', session.get('user_name')))
        # if user.get('otp') == entered and user.get('otp_expiry') and datetime.now() < user['otp_expiry'].replace(tzinfo=None):
        if True:
            user_doc.reference.update({'otp': None, 'otp_expiry': None})
            flash('Login successful')

            # Check if user needs to reset password (for new affiliates)
            if user.get('force_password_reset'):
                return redirect(url_for('force_password_reset'))

            if session['role'] in ('admin', 'super_admin'):
                return redirect(url_for('admin_dashboard'))
            if session['role'] == 'driver':
                return redirect(url_for('driver_dashboard'))
            if session['role'] == 'recipient':
                return redirect(url_for('ngo_dashboard'))
            else:
                return redirect(url_for('home'))
        else:
            flash('Invalid or expired OTP')
            return redirect(url_for('otp'))
    return render_template('otp.html')


# Create a listing (new_request) - saves to 'listings' and copies to 'requests' for compatibility
@app.route('/new_request', methods=['GET', 'POST'])
def new_request():
    if 'email' not in session:
        flash('Please login')
        return redirect(url_for('login'))
    profile_picture = get_user_profile_picture(session.get('email'))
    if request.method == 'POST':
        try:
            visibility = request.form.get('visibility', 'public')
            donor_id = session.get('user_id')
            data = {
                'donor_name': session.get('user_name'),
                'donor_id': donor_id,
                'donor_email': session.get('email'),
                'food_type': request.form.get('food_type'),
                'quantity': int(request.form.get('quantity') or 0),
                'description': request.form.get('description'),
                'cooking_time': request.form.get('cooking_time'),
                'instructions': request.form.get('instructions'),
                'address': request.form.get('address'),
                'pickup_time': request.form.get('pickup_time'),
                'status': 'Pending',
                'visibility': visibility,
                'timestamp': datetime.now().isoformat()
            }
            db.collection('listings').add(data)
            flash('Listing created')
            return redirect(url_for('home'))
        except Exception as e:
            flash(f'Error: {e}')
            return redirect(url_for('new_request'))
    return render_template('new_listing.html', profile_picture=profile_picture)


# Find recipients (donor browsing verified NGOs)
@app.route('/find_recipients')
def find_recipients():
    if 'email' not in session or session.get('role') != 'donor':
        flash('You must be a donor')
        return redirect(url_for('home'))
    profile_picture = get_user_profile_picture(session.get('email'))
    try:
        recipients = []
        # Get only verified NGOs
        for doc in db.collection('users').where('role', '==', 'recipient').where('is_verified', '==', True).stream():
            recipient = doc.to_dict()
            recipient['id'] = doc.id
            recipients.append(recipient)

        # Get current user's affiliations and pending requests
        user_doc = db.collection('users').document(session['user_id']).get()
        user_affiliations = user_doc.to_dict().get('affiliations', []) if user_doc.exists else []

        # Get pending affiliation requests
        pending = []
        for doc in db.collection('affiliations').where('donor_id', '==', session['user_id']).where('status', '==', 'pending').stream():
            pending.append(doc.to_dict().get('recipient_id'))

        return render_template('find_recipients.html',
                            recipients=recipients,
                            user_affiliations=user_affiliations,
                            pending_recipient_ids=pending,
                            profile_picture=profile_picture)
    except Exception as e:
        flash(f'Error: {e}')
        return redirect(url_for('home'))


# Donor sends affiliation request
@app.route('/affiliate/request/<recipient_id>', methods=['POST'])
def request_affiliation(recipient_id):
    if 'email' not in session or session.get('role') != 'donor':
        flash('Must be donor')
        return redirect(url_for('home'))
    try:
        # Create affiliation request document
        doc = {
            'donor_id': session['user_id'],
            'recipient_id': recipient_id,
            'status': 'pending',
            'requested_by': session['user_id'],
            'timestamp': datetime.now().isoformat()
        }
        db.collection('affiliations').add(doc)
        flash('Affiliation request sent')
    except Exception as e:
        flash(f'Error: {e}')
    return redirect(url_for('find_recipients'))


# Manage affiliations (sent for donors, incoming for recipients)
@app.route('/manage_affiliations')
def manage_affiliations():
    if 'email' not in session:
        return redirect(url_for('login'))
    profile_picture = get_user_profile_picture(session.get('email'))
    role = session.get('role')
    try:
        if role == 'donor':
            # Show sent affiliation requests for donors
            sent = []
            for doc in db.collection('affiliations').where('donor_id', '==', session['user_id']).stream():
                d = doc.to_dict()
                d['id'] = doc.id
                # Get recipient details
                recipient = db.collection('users').document(d['recipient_id']).get()
                if recipient.exists:
                    d['recipient_name'] = recipient.to_dict().get('user_name')
                sent.append(d)
            return render_template('manage_affiliations.html',
                                sent_requests=sent,
                                profile_picture=profile_picture)
        elif role == 'recipient':
            # Show incoming requests for NGOs
            incoming = []
            for doc in db.collection('affiliations').where('recipient_id', '==', session['user_id']).where('status', '==', 'pending').stream():
                d = doc.to_dict()
                d['id'] = doc.id
                # Get donor details
                donor = db.collection('users').document(d['donor_id']).get()
                if donor.exists:
                    donor_data = donor.to_dict()
                    d['donor_name'] = donor_data.get('user_name')
                    d['donor_email'] = donor_data.get('email')
                incoming.append(d)

            # Get added affiliations (accepted/active affiliations created by this NGO)
            added_affiliations = []
            for doc in db.collection('affiliations').where('recipient_id', '==', session['user_id']).where('requested_by', '==', session['user_id']).stream():
                aff = doc.to_dict()
                aff['id'] = doc.id

                # Get donor details
                donor_id = aff.get('donor_id')
                if donor_id:
                    donor_doc = db.collection('users').document(donor_id).get()
                    if donor_doc.exists:
                        donor_data = donor_doc.to_dict()
                        aff['donor_name'] = donor_data.get('user_name') or donor_data.get('name')
                        aff['donor_email'] = donor_data.get('email')
                        aff['donor_phone'] = donor_data.get('phone')
                        aff['donor_address'] = donor_data.get('address')
                        # Check if donor has activated (logged in and reset password)
                        aff['donor_activated'] = not donor_data.get('force_password_reset', False)
                        # Include temp password if not activated
                        if not aff['donor_activated']:
                            aff['temp_password'] = aff.get('temp_password', 'N/A')
                added_affiliations.append(aff)

            # Get affiliated drivers (drivers created/managed by this NGO)
            affiliated_drivers = []
            for doc in db.collection('users').where('role', '==', 'driver').where('affiliated_by', '==', session['user_id']).stream():
                driver = doc.to_dict()
                driver['id'] = doc.id
                affiliated_drivers.append(driver)

            return render_template('manage_affiliations.html',
                                incoming_requests=incoming,
                                added_affiliations=added_affiliations,
                                affiliated_drivers=affiliated_drivers,
                                profile_picture=profile_picture)
        else:
            flash('Not available')
            return redirect(url_for('home'))
    except Exception as e:
        flash(f'Error: {e}')
        return redirect(url_for('home'))


# Recipient accepts/rejects affiliation request
@app.route('/affiliate/respond/<request_id>', methods=['POST'])
def respond_affiliation(request_id):
    if 'email' not in session or session.get('role') != 'recipient':
        flash('Must be recipient')
        return redirect(url_for('home'))
    try:
        resp = request.form.get('response')
        if resp not in ('accepted', 'rejected'):
            flash('Invalid')
            return redirect(url_for('manage_affiliations'))

        ref = db.collection('affiliations').document(request_id)
        doc = ref.get()
        if not doc.exists:
            flash('Not found')
            return redirect(url_for('manage_affiliations'))

        data = doc.to_dict()
        ref.update({'status': resp})

        if resp == 'accepted':
            donor_id = data.get('donor_id')
            recipient_id = data.get('recipient_id')
            if donor_id and recipient_id:
                # Add to each other's affiliations arrays
                _safe_array_union_update(db.collection('users').document(donor_id), 'affiliations', [recipient_id])
                _safe_array_union_update(db.collection('users').document(recipient_id), 'affiliations', [donor_id])
            flash('Affiliation accepted')
        else:
            flash('Affiliation rejected')
    except Exception as e:
        flash(f'Error: {e}')
    return redirect(url_for('manage_affiliations'))


# Google registration page for new Google users
@app.route('/register/google', methods=['GET', 'POST'])
def register_google():
    email = session.get('email')
    if not email:
        flash('Session expired')
        return redirect(url_for('login'))
    if request.method == 'POST':
        try:
            name = request.form.get('name')
            phone = request.form.get('phone')
            usertype = request.form.get('usertype')
            address = request.form.get('address')
            role = 'donor'
            if (usertype or '').lower() in ('ngo', 'recipient'):
                role = 'recipient'
            user_data = {
                'user_name': name,
                'email': email,
                'phone': phone,
                'address': address,
                'password': None,
                'role': role,
                'is_verified': False if role == 'recipient' else True,
                'affiliations': [],
                'affiliated_by': None,
                'status': 'active',
                'created_at': datetime.now().isoformat()
            }
            db.collection('users').add(user_data)
            flash('Registration successful. Please login via Google again.')
            return redirect(url_for('login_google'))
        except Exception as e:
            flash(f'Error: {e}')
            return redirect(url_for('register_google'))
    return render_template('register_google.html', email=email)

# NGO - add partner (donor)
@app.route('/ngo/add_partner', methods=['POST'])
def add_partner():
    if session.get('role') != 'recipient':
        flash('Must be recipient')
        return redirect(url_for('home'))
    try:
        # Generate temporary password
        temp_password = ''.join(random.choices('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', k=12))
        hashed = generate_password_hash(temp_password)

        # Create the new donor account
        user_data = {
            'user_name': request.form.get('name'),
            'email': request.form.get('email'),
            'phone': request.form.get('phone'),
            'address': request.form.get('address'),
            'password': hashed,
            'role': 'donor',
            'is_verified': True,
            'force_password_reset': True,
            'status': 'active',
            'affiliations': [],
            'created_at': datetime.now().isoformat()
        }

        # Check if user already exists
        existing_users = db.collection('users').where('email', '==', user_data['email']).get()
        if existing_users:
            flash('A user with this email already exists')
            return redirect(url_for('ngo_onboard_page'))

        # Add the user
        added = db.collection('users').add(user_data)
        new_donor_id = _get_added_doc_id(added)

        if new_donor_id:
            # Create affiliation request
            affiliation_data = {
                'donor_id': new_donor_id,
                'recipient_id': session['user_id'],
                'status': 'pending_activation',
                'requested_by': session['user_id'],
                'temp_password': temp_password,  # Store temporarily for display
                'timestamp': datetime.now().isoformat()
            }
            db.collection('affiliations').add(affiliation_data)

            # Update affiliations for both donor and recipient immediately
            _safe_array_union_update(db.collection('users').document(new_donor_id), 'affiliations', [session['user_id']])
            _safe_array_union_update(db.collection('users').document(session['user_id']), 'affiliations', [new_donor_id])


            # Send email with temporary password
            email_body = f"Welcome to Prasadam! Your temporary login credentials:\nEmail: {user_data['email']}\nTemporary Password: {temp_password}\n\nPlease login and change your password immediately."
            send_otp(user_data['email'], email_body)

            # Show success message with temporary password
            flash(f'Partner added successfully! Temporary Password: {temp_password} (Please save this - it will only be shown once)')
            session['temp_password_display'] = temp_password
            session['new_partner_email'] = user_data['email']

    except Exception as e:
        flash(f'Error: {e}')
    return redirect(url_for('ngo_onboard_page'))


# NGO - add driver
@app.route('/ngo/add_driver', methods=['POST'])
def add_driver():
    if session.get('role') != 'recipient':
        flash('Must be recipient')
        return redirect(url_for('home'))
    try:
        temp = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=8))
        hashed = generate_password_hash(temp)
        user = {
            'user_name': request.form.get('name'),
            'email': request.form.get('email'),
            'phone': request.form.get('phone'),
            'password': hashed,
            'role': 'driver',
            'affiliated_by': session['user_id'],
            'is_verified': True,
            'force_password_reset': True,
            'status': 'active',
            'created_at': datetime.now().isoformat()
        }
        added = db.collection('users').add(user)
        new_id = _get_added_doc_id(added)
        if new_id:
            _safe_array_union_update(db.collection('users').document(session['user_id']), 'affiliations', [new_id])
        send_otp(request.form.get('email'), temp)
        flash('Driver added')
    except Exception as e:
        flash(f'Error: {e}')
    return redirect(url_for('ngo_dashboard'))


# Recipient onboarding page (Add Partner / Add Driver)
@app.route('/ngo/onboard')
def ngo_onboard_page():
    if session.get('role') != 'recipient':
        flash('Must be recipient')
        return redirect(url_for('login'))
    return render_template('add_affiliates.html', profile_picture=get_user_profile_picture(session.get('email')))


# NGO Dashboard
@app.route('/ngo_dashboard')
def ngo_dashboard():
    if 'email' not in session or session.get('role') != 'recipient':
        flash('You must be an NGO/Charity Organization')
        return redirect(url_for('login'))
    profile_picture = get_user_profile_picture(session.get('email'))
    user_id = session.get('user_id')
    try:
        user_doc = db.collection('users').document(user_id).get()
        user = user_doc.to_dict() if user_doc.exists else {}
        is_verified = user.get('is_verified', False)
        affiliated_listings = []
        public_listings = []
        affiliated_drivers = []
        if is_verified:
            affs = user.get('affiliations', [])

            # Get all listings first
            all_listings = []
            for doc in db.collection('listings').stream():
                d = doc.to_dict()
                d['id'] = doc.id
                all_listings.append(d)

            # Separate listings based on visibility and affiliation
            for listing in all_listings:
                donor_id = listing.get('donor_id')
                # If from affiliated donor and affiliates_only, add to affiliated listings
                if donor_id in affs and listing.get('visibility') == 'affiliates_only' and listing.get('status') != 'Collected':
                    affiliated_listings.append(listing)
                # If public listing that's still pending, show in public listings tab
                elif listing.get('visibility') == 'public' and listing.get('status') != 'Collected':
                    public_listings.append(listing)

            # Get affiliated drivers
            for doc in db.collection('users').where('role', '==', 'driver').where('affiliated_by', '==', user_id).stream():
                affiliated_drivers.append(doc.to_dict())

        # Sort listings by timestamp (newest first)
        affiliated_listings.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
        public_listings.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

        return render_template('dashboard_recipient.html',
                             profile_picture=profile_picture,
                             is_verified=is_verified,
                             affiliated_listings=affiliated_listings,
                             public_listings=public_listings,
                             affiliated_drivers=affiliated_drivers)
    except Exception as e:
        flash(f'Error: {e}')
        return redirect(url_for('home'))


# Claim listing
@app.route('/listing/claim/<listing_id>', methods=['POST'])
def claim_listing(listing_id):
    if 'email' not in session or session.get('role') != 'recipient':
        flash('Must be recipient')
        # If AJAX, return JSON
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return {'success': False, 'message': 'Must be recipient'}, 403
        return redirect(url_for('home'))
    try:
        ref = db.collection('listings').document(listing_id)
        ref.update({'status': 'Claimed', 'claimed_by_recipient_id': session['user_id'], 'claimed_at': datetime.now().isoformat()})
        # If request came via AJAX, return JSON so frontend doesn't redirect
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return {'success': True, 'message': 'Listing claimed'}
        flash('Listing claimed')
    except Exception as e:
        # Return JSON on AJAX errors as well
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return {'success': False, 'message': str(e)}, 500
        flash(f'Error: {e}')
    return redirect(url_for('ngo_dashboard'))


# Assign driver to claimed listing (NGO)
@app.route('/ngo/assign_driver_to_listing/<listing_id>', methods=['POST'])
def ngo_assign_driver(listing_id):
    if 'email' not in session or session.get('role') != 'recipient':
        flash('Must be recipient')
        return redirect(url_for('home'))
    try:
        driver_email = request.form.get('driver_email')
        drivers = db.collection('users').where('email', '==', driver_email).limit(1).get()
        if not drivers:
            flash('Driver not found')
            return redirect(url_for('ngo_dashboard'))
        driver_doc = drivers[0]; driver = driver_doc.to_dict(); driver_id = driver_doc.id
        if driver.get('affiliated_by') != session['user_id']:
            flash('Driver not affiliated to you')
            return redirect(url_for('ngo_dashboard'))
        listing_ref = db.collection('listings').document(listing_id)
        listing_doc = listing_ref.get()
        if not listing_doc.exists:
            flash('Listing not found')
            return redirect(url_for('ngo_dashboard'))
        listing = listing_doc.to_dict()
        if listing.get('claimed_by_recipient_id') != session['user_id']:
            flash('You did not claim this listing')
            return redirect(url_for('ngo_dashboard'))
        listing_ref.update({'status': 'Assigned', 'driver_id': driver_id, 'driver_email': driver.get('email'), 'driver_name': driver.get('user_name', driver.get('name')), 'assigned_at': datetime.now().isoformat()})
        flash('Driver assigned')
    except Exception as e:
        flash(f'Error: {e}')
    return redirect(url_for('ngo_dashboard'))


# Driver dashboard: show listings claimed by the NGO they belong to
@app.route('/driver-dashboard')
def driver_dashboard():
    if session.get('role') != 'driver':
        flash('Must be driver')
        return redirect(url_for('home'))
    profile_picture = get_user_profile_picture(session.get('email'))
    user_id = session.get('user_id')
    pickups = []
    available_claimed = []
    try:
        driver_doc = db.collection('users').document(user_id).get()
        affiliated_by = driver_doc.to_dict().get('affiliated_by') if driver_doc.exists else None
        if affiliated_by:
            for doc in db.collection('listings').where('claimed_by_recipient_id', '==', affiliated_by).stream():
                d = doc.to_dict(); d['id'] = doc.id
                # If listing is claimed and not yet assigned, show as available for drivers to take
                if d.get('status') == 'Claimed':
                    available_claimed.append(d)
                # If listing is assigned/collected and assigned to this driver, show in pickups
                elif d.get('status') in ('Assigned', 'Collected') and d.get('driver_id') == user_id:
                    pickups.append(d)
        else:
            for doc in db.collection('listings').where('driver_id', '==', user_id).stream():
                d = doc.to_dict(); d['id'] = doc.id
                if d.get('status') in ('Assigned', 'Collected'):
                    pickups.append(d)
        # Determine if there is an active pickup (Assigned and not Collected) for this driver
        active_pickup = None
        for p in pickups:
            if p.get('status') == 'Assigned' and p.get('driver_id') == user_id:
                active_pickup = p
                break

        return render_template('dashboard_driver.html', pickups=pickups, available_claimed=available_claimed, active_pickup=active_pickup, profile_picture=profile_picture)
    except Exception as e:
        flash(f'Error: {e}')
        return redirect(url_for('home'))


# Admin dashboard simplified: verify NGOs and view listings
@app.route('/admin')
def admin_dashboard():
    if session.get('role') not in ('admin', 'super_admin'):
        flash('Not authorized')
        return redirect(url_for('login'))
    profile_picture = get_user_profile_picture(session.get('email'))
    try:
        unverified = []
        for d in db.collection('users').where('role', '==', 'recipient').where('is_verified', '==', False).stream():
            item = d.to_dict()
            item['id'] = d.id
            unverified.append(item)
        pending = [d.to_dict() for d in db.collection('listings').where('status', '==', 'Pending').stream()]
        approved = [d.to_dict() for d in db.collection('listings').where('status', '==', 'Approved').stream()]
        drivers = [d.to_dict() for d in db.collection('users').where('role', '==', 'driver').stream()]
        return render_template('dashboard_admin.html', unverified_ngos=unverified, pending_requests=pending, approved_requests=approved, assigned_requests=[], drivers=drivers, profile_picture=profile_picture)
    except Exception as e:
        flash(f'Error: {e}')
        return redirect(url_for('home'))


# Admin verify user
@app.route('/admin/verify_user/<user_id>', methods=['POST'])
def verify_user(user_id):
    if session.get('role') not in ('admin', 'super_admin'):
        flash('Not authorized')
        return redirect(url_for('login'))
    try:
        db.collection('users').document(user_id).update({'is_verified': True})
        flash('Recipeint verified')
    except Exception as e:
        flash(f'Error: {e}')
    return redirect(url_for('admin_dashboard'))


# Profile, update, password flows (kept compatible)
@app.route('/profile')
def profile():
    if 'email' not in session:
        return redirect(url_for('login'))
    try:
        docs = db.collection('users').where('email', '==', session['email']).limit(1).get()
        if not docs:
            flash('User not found')
            return redirect(url_for('home'))
        user = docs[0].to_dict()
        user_id = docs[0].id
        role = session.get('role')

        # Format created_at date if available
        if user.get('created_at'):
            try:
                created_date = datetime.fromisoformat(user['created_at'].replace('Z', '+00:00'))
                user['created_at'] = created_date.strftime('%b %d, %Y')
            except Exception:
                pass

        # Initialize stats dictionary
        stats = {
            'total_requests': 0,
            'pending_requests': 0,
            'approved_requests': 0,
            'assigned_requests': 0,
            'collected_requests': 0,
            'total_users': 0,
            'total_donations': 0,
            'total_servings': 0,
            'completed_donations': 0,
            'pending_donations': 0,
            'total_pickups': 0,
            'completed_pickups': 0,
            'pending_pickups': 0,
            'total_claims': 0,
            'completed_claims': 0,
            'pending_claims': 0
        }

        try:
            # Calculate role-specific statistics
            if role in ['admin', 'super_admin']:
                # Get all listings for comprehensive stats
                listings = db.collection('listings').stream()
                listings_data = [d.to_dict() for d in listings]
                stats['total_requests'] = len(listings_data)
                stats['pending_requests'] = len([r for r in listings_data if r.get('status') == 'Pending'])
                stats['approved_requests'] = len([r for r in listings_data if r.get('status') == 'Assigned'])
                stats['collected_requests'] = len([r for r in listings_data if r.get('status') == 'Collected'])

                # Calculate total servings from all collected donations
                stats['total_servings'] = sum(d.get('quantity', 0) for d in listings_data if d.get('status') == 'Collected')

                # Get user counts by role
                all_users = list(db.collection('users').stream())
                stats['total_users'] = len(all_users)

                # Get counts of donors, recipients, and drivers
                stats['donor_count'] = len([u for u in all_users if u.to_dict().get('role') == 'donor'])
                stats['recipient_count'] = len([u for u in all_users if u.to_dict().get('role') == 'recipient'])
                stats['driver_count'] = len([u for u in all_users if u.to_dict().get('role') == 'driver'])

            elif role == 'donor':
                # Get donor's donations
                listings = db.collection('listings').where('donor_id', '==', user_id).stream()
                listings_data = [d.to_dict() for d in listings]
                stats['total_donations'] = len(listings_data)
                stats['completed_donations'] = len([d for d in listings_data if d.get('status') == 'Collected'])
                stats['pending_donations'] = len([d for d in listings_data if d.get('status') != 'Collected'])

                # Count total servings from all donations (not just collected)
                stats['total_servings'] = sum(d.get('quantity', 0) for d in listings_data)

                # Add recent donation activity count (last 30 days)
                thirty_days_ago = (datetime.now() - timedelta(days=30)).isoformat()
                stats['recent_activity'] = len([d for d in listings_data
                                               if d.get('timestamp') and d.get('timestamp') >= thirty_days_ago])

            elif role == 'driver':
                # Get driver's pickups
                listings = db.collection('listings').where('driver_id', '==', user_id).stream()
                listings_data = [d.to_dict() for d in listings]
                stats['total_pickups'] = len(listings_data)
                stats['completed_pickups'] = len([p for p in listings_data if p.get('status') == 'Collected'])
                stats['pending_pickups'] = len([p for p in listings_data if p.get('status') == 'Assigned'])

                # Count servings only from collected donations
                stats['total_servings'] = sum(p.get('quantity', 0) for p in listings_data if p.get('status') == 'Collected')

                # Add affiliated NGO count
                driver_doc = db.collection('users').document(user_id).get()
                affiliated_by = driver_doc.to_dict().get('affiliated_by') if driver_doc.exists else None
                stats['affiliated_ngo'] = 1 if affiliated_by else 0

            elif role == 'recipient':
                # Get NGO's claimed donations
                listings = db.collection('listings').where('claimed_by_recipient_id', '==', user_id).stream()
                listings_data = [d.to_dict() for d in listings]
                stats['total_claims'] = len(listings_data)
                stats['completed_claims'] = len([c for c in listings_data if c.get('status') == 'Collected'])
                stats['pending_claims'] = len([c for c in listings_data if c.get('status') != 'Collected'])

                # Count servings only from collected donations
                stats['total_servings'] = sum(c.get('quantity', 0) for c in listings_data if c.get('status') == 'Collected')

                # Add affiliated donors and drivers counts
                user_doc = db.collection('users').document(user_id).get()
                if user_doc.exists:
                    # Count affiliated donors
                    affiliations = user_doc.to_dict().get('affiliations', [])
                    stats['affiliated_donors'] = len(affiliations)

                    # Count affiliated drivers
                    affiliated_drivers = db.collection('users').where('role', '==', 'driver').where('affiliated_by', '==', user_id).get()
                    stats['affiliated_drivers'] = len(list(affiliated_drivers))

        except Exception as e:
            print(f'Error calculating stats: {e}')

        return render_template('profile.html', user_data=user, stats=stats, profile_picture=get_user_profile_picture(session.get('email')))
    except Exception as e:
        flash(f'Error: {e}')
        return redirect(url_for('home'))


@app.route('/update_profile_info', methods=['POST'])
def update_profile_info():
    if 'email' not in session:
        return redirect(url_for('login'))
    try:
        name = request.form.get('name')
        phone = request.form.get('phone')
        address = request.form.get('address')
        docs = db.collection('users').where('email', '==', session['email']).limit(1).get()
        if not docs:
            flash('User not found')
            return redirect(url_for('profile'))
        ref = docs[0].reference
        ref.update({'name': name, 'user_name': name, 'phone': phone, 'address': address, 'updated_at': datetime.now().isoformat()})
        session['user_name'] = name
        flash('Profile updated')
    except Exception as e:
        flash(f'Error: {e}')
    return redirect(url_for('profile'))


@app.route('/change_password', methods=['POST'])
def change_password():
    if 'email' not in session:
        return redirect(url_for('login'))
    try:
        current = request.form.get('current_password')
        new = request.form.get('new_password')
        confirm = request.form.get('confirm_password')
        if new != confirm:
            flash('Passwords do not match')
            return redirect(url_for('profile'))
        docs = db.collection('users').where('email', '==', session['email']).limit(1).get()
        if not docs:
            flash('User not found')
            return redirect(url_for('profile'))
        doc = docs[0]
        data = doc.to_dict()
        # if force_password_reset True, skip verifying current
        if not data.get('force_password_reset'):
            if not data.get('password') or not check_password_hash(data['password'], current):
                flash('Current password incorrect')
                return redirect(url_for('profile'))
        hashed = generate_password_hash(new)
        update = {
            'password': hashed,
            'password_updated_at': datetime.now().isoformat(),
            'force_password_reset': '0'  # Use string instead of boolean
        }
        doc.reference.update(update)
        flash('Password changed')
    except Exception as e:
        flash(f'Error: {e}')
    return redirect(url_for('profile'))


# Request details and update (backwards compat to requests collection)
@app.route('/request_details/<request_id>')
def request_details(request_id):
    if 'email' not in session:
        flash('Please login')
        return redirect(url_for('login'))

    user_role = session.get('role')

    # Redirect to role-specific routes
    if user_role == 'donor':
        return redirect(url_for('donor_request_details', request_id=request_id))
    elif user_role == 'recipient':
        return redirect(url_for('recipient_request_details', request_id=request_id))
    elif user_role == 'driver':
        return redirect(url_for('pickup_details', request_id=request_id))
    else:
        flash('Invalid user role')
        return redirect(url_for('login'))

@app.route('/donor_request_details/<request_id>', methods=['GET', 'POST'])
def donor_request_details(request_id):
    if 'email' not in session or session.get('role') != 'donor':
        flash('Please login as a donor')
        return redirect(url_for('login'))

    try:
        # Prefer newer 'listings' documents, fall back to legacy 'requests' documents
        doc = db.collection('listings').document(request_id).get()
        if not doc.exists:
            doc = db.collection('requests').document(request_id).get()
            if not doc.exists:
                flash('Request not found')
                return redirect(url_for('home'))

        data = doc.to_dict() or {}
        data['id'] = request_id

        # Check if this donor owns this request. Prefer donor_id when available
        owner_ok = False
        if data.get('donor_id'):
            owner_ok = (data.get('donor_id') == session.get('user_id'))
        else:
            owner_ok = (data.get('donor_email') == session.get('email') or data.get('donor_name') == session.get('user_name'))
        if not owner_ok:
            flash('You are not authorized to view this request')
            return redirect(url_for('home'))

        # POST: handle updates (only allowed when Pending)
        if request.method == 'POST':
            updates = {
                'food_type': request.form.get('food_type'),
                'quantity': int(request.form.get('quantity') or 0),
                'description': request.form.get('description'),
                'cooking_time': request.form.get('cooking_time'),
                'instructions': request.form.get('instructions'),
                'address': request.form.get('address'),
                'pickup_time': request.form.get('pickup_time'),
                'visibility': request.form.get('visibility', 'public')
            }
            if data.get('status') == 'Pending':
                # Update both collections for compatibility if requests doc exists
                try:
                    db.collection('listings').document(request_id).update(updates)
                except Exception:
                    pass
                try:
                    db.collection('requests').document(request_id).update(updates)
                except Exception:
                    pass
                flash('Request updated successfully!')
            else:
                flash('Cannot update request - it has already been processed')
            return redirect(url_for('donor_request_details', request_id=request_id))

        # Enrich with driver info if assigned
        driver = None
        if data.get('driver_email'):
            ddocs = db.collection('users').where('email', '==', data.get('driver_email')).limit(1).get()
            if ddocs:
                dd = ddocs[0].to_dict()
                driver = {
                    'name': dd.get('user_name'),
                    'phone': dd.get('phone'),
                    'email': dd.get('email'),
                    'profile_picture': dd.get('profile_picture')
                }

        # Enrich with recipient (NGO) info if claimed
        claimed_id = data.get('claimed_by_recipient_id') or data.get('recipient_id')
        if claimed_id:
            try:
                rdoc = db.collection('users').document(claimed_id).get()
                if rdoc.exists:
                    rdata = rdoc.to_dict()
                    data['recipient_name'] = rdata.get('user_name') or rdata.get('name')
                    data['recipient_id'] = claimed_id
                    data['recipient_phone'] = rdata.get('phone')
                    data['recipient_email'] = rdata.get('email')
                    data['recipient_address'] = rdata.get('address')
                    data['recipient_profile_picture'] = rdata.get('profile_picture')
            except Exception:
                pass

        # Also enrich donor contact details (in case templates expect them)
        try:
            if data.get('donor_id'):
                dd = db.collection('users').document(data.get('donor_id')).get()
                if dd.exists:
                    ddata = dd.to_dict()
                    data['donor_phone'] = ddata.get('phone')
                    data['donor_email'] = ddata.get('email')
                    data['donor_address'] = ddata.get('address')
                    data['donor_profile_picture'] = ddata.get('profile_picture')
            elif data.get('donor_email'):
                ddocs = db.collection('users').where('email', '==', data.get('donor_email')).limit(1).get()
                if ddocs:
                    ddata = ddocs[0].to_dict()
                    data['donor_phone'] = ddata.get('phone')
                    data['donor_address'] = ddata.get('address')
                    data['donor_profile_picture'] = ddata.get('profile_picture')
        except Exception:
            pass

        return render_template('listing_details_donor.html',
                               request=data,
                               driver=driver,
                               profile_picture=get_user_profile_picture(session.get('email')))

    except Exception as e:
        flash(f'Error: {e}')
        return redirect(url_for('home'))

@app.route('/recipient_request_details/<request_id>')
def recipient_request_details(request_id):
    if 'email' not in session or session.get('role') != 'recipient':
        flash('Please login as an NGO')
        return redirect(url_for('login'))

    try:
        # Try to fetch the listing from 'listings' first (newer documents), fall back to 'requests' for older/backwards-compat docs
        listing_doc = db.collection('listings').document(request_id).get()
        if listing_doc.exists:
            data = listing_doc.to_dict()
        else:
            doc = db.collection('requests').document(request_id).get()
            if not doc.exists:
                flash('Listing not found')
                return redirect(url_for('ngo_dashboard'))
            data = doc.to_dict()

        data['id'] = request_id

        # Check if this listing is visible to the recipient
        user_id = session.get('user_id')
        user_affiliations = get_user_affiliations(user_id)

        # Check visibility permissions
        can_view = False
        visibility = data.get('visibility', 'public')
        if visibility == 'public':
            can_view = True
        elif visibility == 'affiliates_only':
            donor_id = data.get('donor_id')
            if donor_id and donor_id in user_affiliations:
                can_view = True
            else:
                donor_docs = db.collection('users').where('user_name', '==', data.get('donor_name')).limit(1).get()
                if donor_docs:
                    donor_id = donor_docs[0].id
                    if donor_id in user_affiliations:
                        can_view = True

        if not can_view:
            flash('You are not authorized to view this listing')
            return redirect(url_for('ngo_dashboard'))

        # Enrich with driver info if assigned
        driver = None
        if data.get('driver_email'):
            ddocs = db.collection('users').where('email', '==', data.get('driver_email')).limit(1).get()
            if ddocs:
                dd = ddocs[0].to_dict()
                driver = {
                    'name': dd.get('user_name'),
                    'phone': dd.get('phone'),
                    'email': dd.get('email'),
                    'profile_picture': dd.get('profile_picture')
                }

        # Enrich with donor contact details for recipient view
        try:
            if data.get('donor_id'):
                donor_doc = db.collection('users').document(data.get('donor_id')).get()
                if donor_doc.exists:
                    donor = donor_doc.to_dict()
                    data['donor_name'] = donor.get('user_name') or donor.get('name')
                    data['donor_phone'] = donor.get('phone')
                    data['donor_email'] = donor.get('email')
                    data['donor_address'] = donor.get('address')
                    data['donor_profile_picture'] = donor.get('profile_picture')
            elif data.get('donor_email'):
                ddocs = db.collection('users').where('email', '==', data.get('donor_email')).limit(1).get()
                if ddocs:
                    donor = ddocs[0].to_dict()
                    data['donor_phone'] = donor.get('phone')
                    data['donor_address'] = donor.get('address')
                    data['donor_id'] = ddocs[0].id
                    data['donor_profile_picture'] = donor.get('profile_picture')
        except Exception:
            pass

        # Enrich with recipient (NGO) contact details if available
        claimed_id = data.get('claimed_by_recipient_id') or data.get('recipient_id')
        if claimed_id:
            try:
                rdoc = db.collection('users').document(claimed_id).get()
                if rdoc.exists:
                    rdata = rdoc.to_dict()
                    data['recipient_id'] = claimed_id
                    data['recipient_name'] = rdata.get('user_name') or rdata.get('name')
                    data['recipient_phone'] = rdata.get('phone')
                    data['recipient_email'] = rdata.get('email')
                    data['recipient_address'] = rdata.get('address')
                    data['recipient_profile_picture'] = rdata.get('profile_picture')
            except Exception:
                pass

        return render_template('listing_details_recipient.html',
                               request=data,
                               driver=driver,
                               profile_picture=get_user_profile_picture(session.get('email')))

    except Exception as e:
        flash(f'Error: {e}')
        return redirect(url_for('ngo_dashboard'))

@app.route('/pickup_details/<request_id>')
def pickup_details(request_id):
    if 'email' not in session or session.get('role') != 'driver':
        flash('Please login as a driver')
        return redirect(url_for('login'))
    try:
        # Get all current pickups for this driver to check active status
        driver_id = session.get('user_id')
        current_pickups = []
        active_pickup = None
        for doc in db.collection('listings').where('driver_id', '==', driver_id).where('status', '==', 'Assigned').stream():
            pickup = doc.to_dict()
            pickup['id'] = doc.id
            current_pickups.append(pickup)
            if pickup['status'] == 'Assigned':
                active_pickup = pickup
                break

        # If driver has an active pickup, only allow viewing that pickup
        if active_pickup and active_pickup['id'] != request_id:
            flash('Please complete your active pickup before viewing other listings')
            return redirect(url_for('driver_dashboard'))

        # Rest of the pickup details logic
        listing_doc = db.collection('listings').document(request_id).get()
        if listing_doc.exists:
            data = listing_doc.to_dict()
            data_id = listing_doc.id
        else:
            doc = db.collection('requests').document(request_id).get()
            if not doc.exists:
                flash('Pickup not found')
                return redirect(url_for('driver_dashboard'))
            data = doc.to_dict()
            data_id = doc.id

        data['id'] = data_id

        # Get driver's affiliated NGO
        driver_doc = db.collection('users').document(driver_id).get()
        affiliated_by = driver_doc.to_dict().get('affiliated_by') if driver_doc.exists else None

        # Check if listing is from driver's affiliated NGO
        is_from_affiliated_ngo = (data.get('claimed_by_recipient_id') == affiliated_by)

        # Get donor's full contact details from users collection
        donor_email = data.get('donor_email')
        if donor_email:
            donor_docs = db.collection('users').where('email', '==', donor_email).limit(1).get()
            if donor_docs:
                donor_data = donor_docs[0].to_dict()
                # Update data with donor's current contact info
                data['donor_phone'] = donor_data.get('phone')
                data['donor_contact'] = donor_data.get('phone')  # For backwards compatibility
                data['donor_id'] = donor_docs[0].id
                data['donor_address'] = donor_data.get('address')
                data['donor_profile_picture'] = donor_data.get('profile_picture')

        # If we don't have donor email but have donor_id, try that
        elif data.get('donor_id'):
            donor_doc = db.collection('users').document(data.get('donor_id')).get()
            if donor_doc.exists:
                donor_data = donor_doc.to_dict()
                data['donor_phone'] = donor_data.get('phone')
                data['donor_contact'] = donor_data.get('phone')
                data['donor_email'] = donor_data.get('email')
                data['donor_address'] = donor_data.get('address')
                data['donor_profile_picture'] = donor_data.get('profile_picture')

        # Enrich with recipient (NGO) contact details if available
        claimed_id = data.get('claimed_by_recipient_id') or data.get('recipient_id')
        if claimed_id:
            try:
                rdoc = db.collection('users').document(claimed_id).get()
                if rdoc.exists:
                    rdata = rdoc.to_dict()
                    data['recipient_name'] = rdata.get('user_name') or rdata.get('name')
                    data['recipient_phone'] = rdata.get('phone')
                    data['recipient_id'] = claimed_id
                    data['recipient_email'] = rdata.get('email')
                    data['recipient_address'] = rdata.get('address')
                    data['recipient_profile_picture'] = rdata.get('profile_picture')
            except Exception:
                pass

        return render_template('listing_details_driver.html',
                             request=data,
                             pickups=current_pickups,
                             is_from_affiliated_ngo=is_from_affiliated_ngo,
                             profile_picture=get_user_profile_picture(session.get('email')))

    except Exception as e:
        flash(f'Error: {e}')
        return redirect(url_for('driver_dashboard'))


# Activate affiliation after password reset
@app.route('/affiliate/activate/<request_id>', methods=['POST'])
def activate_affiliation(request_id):
    try:
        ref = db.collection('affiliations').document(request_id)
        doc = ref.get()
        if not doc.exists:
            flash('Affiliation request not found')
            return redirect(url_for('manage_affiliations'))

        data = doc.to_dict()
        donor_id = data.get('donor_id')
        recipient_id = data.get('recipient_id')

        # Check if donor has reset their password
        donor_doc = db.collection('users').document(donor_id).get()
        if donor_doc.exists:
            donor = donor_doc.to_dict()
            if not donor.get('force_password_reset', True):  # Password has been reset
                # Activate the affiliation
                ref.update({'status': 'accepted', 'activated_at': datetime.now().isoformat()})

                # Add to each other's affiliations
                _safe_array_union_update(db.collection('users').document(donor_id), 'affiliations', [recipient_id])
                _safe_array_union_update(db.collection('users').document(recipient_id), 'affiliations', [donor_id])

                flash('Affiliation activated successfully!')
            else:
                flash('Partner must reset their password first')
        else:
            flash('Partner not found')
    except Exception as e:
        flash(f'Error: {e}')
    return redirect(url_for('manage_affiliations'))


# Force password reset for new affiliates
@app.route('/force_password_reset', methods=['GET', 'POST'])
def force_password_reset():
    if 'email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match')
            return render_template('force_password_reset.html')

        if len(new_password) < 8:
            flash('Password must be at least 8 characters long')
            return render_template('force_password_reset.html')

        try:
            user_id = session.get('user_id')
            docs = db.collection('users').where('email', '==', session['email']).limit(1).get()
            if docs:
                hashed = generate_password_hash(new_password)
                docs[0].reference.update({
                    'password': hashed,
                    'force_password_reset': False,
                    'password_updated_at': datetime.now().isoformat()
                })

                # Auto-activate any pending affiliations for this user
                for doc in db.collection('affiliations').where('donor_id', '==', user_id).where('status', '==', 'pending_activation').stream():
                    affiliation_data = doc.to_dict()
                    recipient_id = affiliation_data.get('recipient_id')

                    # Update status and establish affiliation
                    doc.reference.update({'status': 'accepted', 'activated_at': datetime.now().isoformat(), 'temp_password': DELETE_FIELD})
                    _safe_array_union_update(db.collection('users').document(user_id), 'affiliations', [recipient_id])
                    _safe_array_union_update(db.collection('users').document(recipient_id), 'affiliations', [user_id])

                flash('Password updated successfully! Your affiliation has been activated.')

                # Redirect based on role
                if session.get('role') == 'donor':
                    return redirect(url_for('home'))
                elif session.get('role') == 'driver':
                    return redirect(url_for('driver_dashboard'))
                else:
                    return redirect(url_for('ngo_dashboard'))
        except Exception as e:
            flash(f'Error updating password: {e}')

    return render_template('force_password_reset.html')


# Debug route to trigger error
@app.route('/debug-sentry')
def debug_sentry():
    division_by_zero = 1 / 0  # This will raise a ZeroDivisionError
    return "This will not be reached"


# Remove affiliation (recipient removes a partner or driver)
@app.route('/remove_affiliation/<affiliation_id>', methods=['POST'])
def remove_affiliation(affiliation_id):
    if 'email' not in session or session.get('role') != 'recipient':
        flash('Not authorized')
        return redirect(url_for('manage_affiliations'))

    try:
        # Check if this is a driver removal
        if request.form.get('type') == 'driver':
            # When removing a driver, the affiliation_id is actually the driver's user ID
            driver_ref = db.collection('users').document(affiliation_id)
            driver_doc = driver_ref.get()
            if not driver_doc.exists:
                flash('Driver not found')
                return redirect(url_for('manage_affiliations'))

            driver = driver_doc.to_dict()
            # Verify this driver is affiliated with this NGO
            if driver.get('affiliated_by') != session['user_id']:
                flash('Not authorized to remove this driver')
                return redirect(url_for('manage_affiliations'))

            # Remove driver from NGO's affiliations and clear driver's affiliation
            recipient_ref = db.collection('users').document(session['user_id'])
            try:
                rec_doc = recipient_ref.get()
                if rec_doc.exists:
                    rec_data = rec_doc.to_dict()
                    affiliations = rec_data.get('affiliations', [])
                    if affiliation_id in affiliations:
                        affiliations.remove(affiliation_id)
                        recipient_ref.update({'affiliations': affiliations})
            except Exception: pass

            # Update driver's record
            driver_ref.update({
                'affiliated_by': None,
                'status': 'inactive'  # Optional: deactivate the driver
            })

            flash('Driver removed successfully')
            return redirect(url_for('manage_affiliations'))

        # Handle donor/partner removal (existing logic)
        aff_ref = db.collection('affiliations').document(affiliation_id)
        aff_doc = aff_ref.get()
        if not aff_doc.exists:
            flash('Affiliation not found')
            return redirect(url_for('manage_affiliations'))

        aff = aff_doc.to_dict()
        donor_id = aff.get('donor_id')
        recipient_id = aff.get('recipient_id')

        # Remove each other from affiliations array
        if donor_id and recipient_id:
            donor_ref = db.collection('users').document(donor_id)
            recipient_ref = db.collection('users').document(recipient_id)
            # Remove donor from recipient's affiliations
            try:
                rec_doc = recipient_ref.get()
                if rec_doc.exists:
                    rec_data = rec_doc.to_dict()
                    affiliations = rec_data.get('affiliations', [])
                    if donor_id in affiliations:
                        affiliations.remove(donor_id)
                        recipient_ref.update({'affiliations': affiliations})
            except Exception: pass
            # Remove recipient from donor's affiliations
            try:
                don_doc = donor_ref.get()
                if don_doc.exists:
                    don_data = don_doc.to_dict()
                    affiliations = don_data.get('affiliations', [])
                    if recipient_id in affiliations:
                        affiliations.remove(recipient_id)
                        donor_ref.update({'affiliations': affiliations})
            except Exception: pass

        # Delete the affiliation document
        aff_ref.delete()
        flash('Affiliation removed successfully')

    except Exception as e:
        flash(f'Error: {e}')
    return redirect(url_for('manage_affiliations'))


@app.route('/driver/accept_listing/<listing_id>', methods=['POST'])
def driver_accept_listing(listing_id):
    if 'email' not in session or session.get('role') != 'driver':
        flash('Must be driver')
        return redirect(url_for('pickup_details', request_id=listing_id))

    try:
        driver_id = session.get('user_id')
        driver_doc = db.collection('users').document(driver_id).get()
        if not driver_doc.exists:
            flash('Driver not found')
            return redirect(url_for('pickup_details', request_id=listing_id))

        affiliated_by = driver_doc.to_dict().get('affiliated_by')
        if not affiliated_by:
            flash('You are not affiliated to any NGO')
            return redirect(url_for('pickup_details', request_id=listing_id))

        # Check if driver already has an active pickup (status 'Assigned')
        active_pickups = []
        for doc in db.collection('listings').where('driver_id', '==', driver_id).where('status', '==', 'Assigned').stream():
            active_pickups.append(doc.to_dict())

        if active_pickups:
            flash('You already have an active pickup. Please complete it before taking a new one.')
            return redirect(url_for('pickup_details', request_id=listing_id))

        listing_ref = db.collection('listings').document(listing_id)

        @transactional
        def assign_txn(transaction, ref, drv_id, aff_by):
            snap = ref.get(transaction=transaction)
            if not snap.exists:
                return 'notfound'
            data = snap.to_dict()
            # must be claimed by this driver's NGO and still Claimed
            if data.get('status') != 'Claimed' or data.get('claimed_by_recipient_id') != aff_by:
                return 'taken'
            transaction.update(ref, {
                'status': 'Assigned',
                'driver_id': drv_id,
                'driver_email': session.get('email'),
                'driver_name': session.get('user_name'),
                'assigned_at': datetime.now().isoformat()
            })
            return 'ok'

        transaction = db.transaction()
        result = assign_txn(transaction, listing_ref, driver_id, affiliated_by)

        if result == 'notfound':
            flash('Listing not found')
        elif result == 'taken':
            flash('This listing is not available or has already been taken')
        else:
            flash('Listing assigned to you successfully!')
            return redirect(url_for('driver_dashboard'))  # Redirect to dashboard on success

    except Exception as e:
        flash(f'Error: {e}')

    return redirect(url_for('pickup_details', request_id=listing_id))


@app.route('/mark_collected/<listing_id>', methods=['POST'])
def mark_collected(listing_id):
    if 'email' not in session or session.get('role') != 'driver':
        flash('Please login as a driver')
        return redirect(url_for('login'))
    try:
        # Fetch from listings first, fall back to requests
        listing_ref = db.collection('listings').document(listing_id)
        listing_doc = listing_ref.get()

        if not listing_doc.exists:
            flash('Listing not found')
            return redirect(url_for('driver_dashboard'))

        listing = listing_doc.to_dict()
        driver_id = session.get('user_id')

        # Check if this listing is assigned to the current driver
        if listing.get('driver_id') != driver_id:
            flash('This listing is not assigned to you')
            return redirect(url_for('driver_dashboard'))

        # Check if listing is in correct status
        if listing.get('status') != 'Assigned':
            flash('This listing cannot be marked as collected')
            return redirect(url_for('driver_dashboard'))

        # Update listing status to Collected
        listing_ref.update({
            'status': 'Collected',
            'collected_at': datetime.now().isoformat()
        })

        flash('Listing marked as collected successfully!')
    except Exception as e:
        flash(f'Error: {e}')
    return redirect(url_for('driver_dashboard'))


# Pickup history for drivers
@app.route('/pickup_history')
def pickup_history():
    if 'email' not in session or session.get('role') != 'driver':
        flash('Please login as a driver')
        return redirect(url_for('login'))

    try:
        driver_id = session.get('user_id')
        profile_picture = get_user_profile_picture(session.get('email'))

        # Get all pickups assigned to this driver
        active_pickups = []
        completed_pickups = []
        total_servings = 0

        for doc in db.collection('listings').where('driver_id', '==', driver_id).stream():
            pickup = doc.to_dict()
            pickup['id'] = doc.id

            # Format timestamps for better readability
            if pickup.get('assigned_at'):
                try:
                    timestamp = datetime.fromisoformat(pickup['assigned_at'].replace('Z', '+00:00'))
                    pickup['assigned_at'] = timestamp.strftime('%b %d, %Y at %I:%M %p')
                except Exception:
                    pass

            if pickup.get('collected_at'):
                try:
                    timestamp = datetime.fromisoformat(pickup['collected_at'].replace('Z', '+00:00'))
                    pickup['collected_at'] = timestamp.strftime('%b %d, %Y at %I:%M %p')
                except Exception:
                    pass

            # Add pickup to appropriate list based on status
            if pickup.get('status') == 'Assigned':
                active_pickups.append(pickup)
            elif pickup.get('status') == 'Collected':
                completed_pickups.append(pickup)
                # Add to total servings counter
                total_servings += pickup.get('quantity', 0)

        # Sort pickups by assigned time (most recent first)
        active_pickups.sort(key=lambda x: x.get('assigned_at', ''), reverse=True)
        completed_pickups.sort(key=lambda x: x.get('collected_at', ''), reverse=True)

        # Statistics for the dashboard
        stats = {
            'total_pickups': len(active_pickups) + len(completed_pickups),
            'active_pickups': len(active_pickups),
            'completed_pickups': len(completed_pickups),
            'total_servings': total_servings
        }

        return render_template('history_pickup.html',
                               active_pickups=active_pickups,
                               completed_pickups=completed_pickups,
                               stats=stats,
                               profile_picture=profile_picture)

    except Exception as e:
        flash(f'Error loading pickup history: {e}')
        return redirect(url_for('driver_dashboard'))


@app.route('/donation_history')
def donation_history():
    if session.get('role') != 'donor':
        flash('Access denied. Only donors can view donation history.')
        return redirect(url_for('home'))

    user_id = session.get('user_id')
    # Fetch user profile from Firestore
    user_doc = db.collection('users').document(user_id).get()
    user = user_doc.to_dict() if user_doc.exists else None
    profile_picture = user.get('profile_picture') if user else None

    # Fetch all listings for this donor
    all_donations = []
    for doc in db.collection('listings').where('donor_id', '==', user_id).stream():
        d = doc.to_dict()
        d['id'] = doc.id
        all_donations.append(d)

    # Sort by timestamp (most recent first)
    all_donations.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    # Split into active and completed
    active_donations = [d for d in all_donations if d.get('status') != 'Collected']
    completed_donations = [d for d in all_donations if d.get('status') == 'Collected']

    # Calculate stats
    stats = {
        'total_donations': len(all_donations),
        'active_donations': len(active_donations),
        'completed_donations': len(completed_donations),
        'total_servings': sum(d.get('quantity', 0) for d in all_donations)
    }

    # Enrich with recipient and driver names
    def get_user_name(user_id):
        if not user_id:
            return None
        udoc = db.collection('users').document(user_id).get()
        if udoc.exists:
            u = udoc.to_dict()
            return u.get('user_name') or u.get('name')
        return None

    for donation in active_donations + completed_donations:
        if donation.get('claimed_by_recipient_id'):
            donation['recipient_name'] = get_user_name(donation['claimed_by_recipient_id']) or 'Unknown NGO'
        if donation.get('driver_id'):
            donation['driver_name'] = get_user_name(donation['driver_id']) or 'Unknown Driver'
        # Format timestamps for display if present
        if donation.get('timestamp'):
            try:
                dt = datetime.fromisoformat(donation['timestamp'].replace('Z', '+00:00'))
                donation['created_at'] = dt.strftime('%b %d, %Y at %I:%M %p')
            except Exception:
                donation['created_at'] = donation['timestamp']
        if donation.get('claimed_at'):
            try:
                dt = datetime.fromisoformat(donation['claimed_at'].replace('Z', '+00:00'))
                donation['claimed_at'] = dt.strftime('%b %d, %Y at %I:%M %p')
            except Exception:
                pass
        if donation.get('assigned_at'):
            try:
                dt = datetime.fromisoformat(donation['assigned_at'].replace('Z', '+00:00'))
                donation['assigned_at'] = dt.strftime('%b %d, %Y at %I:%M %p')
            except Exception:
                pass
        if donation.get('completed_at'):
            try:
                dt = datetime.fromisoformat(donation['completed_at'].replace('Z', '+00:00'))
                donation['completed_at'] = dt.strftime('%b %d, %Y at %I:%M %p')
            except Exception:
                pass

    return render_template('history_donation.html',
                         active_donations=active_donations,
                         completed_donations=completed_donations,
                         stats=stats,
                         profile_picture=profile_picture)

@app.route('/claim_history')
def claim_history():
    if session.get('role') != 'recipient':
        flash('Access denied. Only NGOs can view claim history.')
        return redirect(url_for('ngo_dashboard'))

    user_id = session.get('user_id')
    # Fetch user profile from Firestore
    user_doc = db.collection('users').document(user_id).get()
    user = user_doc.to_dict() if user_doc.exists else None
    profile_picture = user.get('profile_picture') if user else None

    # Fetch all listings claimed by this recipient
    all_claims = []
    for doc in db.collection('listings').where('claimed_by_recipient_id', '==', user_id).stream():
        d = doc.to_dict()
        d['id'] = doc.id
        all_claims.append(d)

    # Sort by timestamp (most recent first)
    all_claims.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    # Split into active and completed
    active_claims = [d for d in all_claims if d.get('status') != 'Collected']
    completed_claims = [d for d in all_claims if d.get('status') == 'Collected']

    # Calculate stats
    stats = {
        'total_claims': len(all_claims),
        'active_claims': len(active_claims),
        'completed_claims': len(completed_claims),
        'total_servings': sum(d.get('quantity', 0) for d in all_claims)
    }

    # Format timestamps and enrich with donor/driver info
    for claim in active_claims + completed_claims:
        # Get donor details if not present
        if not claim.get('donor_name') and claim.get('donor_id'):
            try:
                donor_doc = db.collection('users').document(claim['donor_id']).get()
                if donor_doc.exists:
                    donor = donor_doc.to_dict()
                    claim['donor_name'] = donor.get('user_name') or donor.get('name')
            except Exception:
                pass

        # Get driver details if assigned
        if claim.get('driver_id') and not claim.get('driver_name'):
            try:
                driver_doc = db.collection('users').document(claim['driver_id']).get()
                if driver_doc.exists:
                    driver = driver_doc.to_dict()
                    claim['driver_name'] = driver.get('user_name') or driver.get('name')
            except Exception:
                pass

        # Format timestamps for display
        if claim.get('timestamp'):
            try:
                dt = datetime.fromisoformat(claim['timestamp'].replace('Z', '+00:00'))
                claim['created_at'] = dt.strftime('%b %d, %Y at %I:%M %p')
            except Exception:
                claim['created_at'] = claim['timestamp']
        if claim.get('claimed_at'):
            try:
                dt = datetime.fromisoformat(claim['claimed_at'].replace('Z', '+00:00'))
                claim['claimed_at'] = dt.strftime('%b %d, %Y at %I:%M %p')
            except Exception:
                pass
        if claim.get('assigned_at'):
            try:
                dt = datetime.fromisoformat(claim['assigned_at'].replace('Z', '+00:00'))
                claim['assigned_at'] = dt.strftime('%b %d, %Y at %I:%M %p')
            except Exception:
                pass
        if claim.get('collected_at'):
            try:
                dt = datetime.fromisoformat(claim['collected_at'].replace('Z', '+00:00'))
                claim['collected_at'] = dt.strftime('%b %d, %Y at %I:%M %p')
            except Exception:
                pass

    return render_template('history_recipient.html',
                         active_claims=active_claims,
                         completed_claims=completed_claims,
                         stats=stats,
                         profile_picture=profile_picture)

@app.route('/')
def landing_page():
    """Public landing page for visitors. Renders templates/landing_page.html or falls back to index.html."""
    try:
        return render_template('landing_page.html')
    except Exception:
        return render_template('index.html')

# Profile picture upload configuration
UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Create upload folder if it doesn't exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Profile picture upload route
@app.route('/update_profile_picture', methods=['POST'])
def update_profile_picture():
    if 'email' not in session:
        flash('Please login')
        return redirect(url_for('login'))

    if 'profile_picture' not in request.files:
        flash('No file uploaded')
        return redirect(url_for('profile'))

    file = request.files['profile_picture']
    if file.filename == '':
        flash('No file selected')
        return redirect(url_for('profile'))

    if file and allowed_file(file.filename):
        # Generate unique filename
        filename = secure_filename(f"profile_{uuid.uuid4().hex}.{file.filename.rsplit('.', 1)[1].lower()}")
        filepath = os.path.join(UPLOAD_FOLDER, filename)

        try:
            # Save file
            file.save(filepath)

            # Update user's profile picture in database
            user_docs = db.collection('users').where('email', '==', session['email']).limit(1).get()
            if user_docs:
                user_doc = user_docs[0]

                # Delete old profile picture if it exists
                old_pic = user_doc.to_dict().get('profile_picture', '')
                if old_pic and 'uploads' in old_pic:
                    try:
                        old_path = os.path.join('static', old_pic.split('static/')[-1])
                        if os.path.exists(old_path):
                            os.remove(old_path)
                    except Exception:
                        pass

                # Update with new profile picture URL
                user_doc.reference.update({
                    'profile_picture': url_for('static', filename=f'uploads/{filename}', _external=True)
                })

                flash('Profile picture updated successfully')
            else:
                flash('User not found')
        except Exception as e:
            flash(f'Error uploading profile picture: {e}')
    else:
        flash('Invalid file type. Please upload an image (PNG, JPG, JPEG, GIF)')

    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)
