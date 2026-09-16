import os
import urllib.parse
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify
from supabase import create_client, Client
from dotenv import load_dotenv
from functools import wraps
from datetime import datetime, timedelta
import qrcode
import io
import base64
import secrets
import razorpay
import cohere
import time

# 1. Load environment variables from .env file FIRST
load_dotenv()


# 2. Initialize Flask app SECOND
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY')
app.permanent_session_lifetime = timedelta(days=7)

# 3. Security Configurations THIRD (Now 'app' is defined!)
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents JavaScript from accessing the session cookie
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax' # Protects against CSRF attacks
app.config['SESSION_COOKIE_SECURE'] = False   # Set to True ONLY when deployed on HTTPS (Render)

# For production, we will handle this via environment variables later
if os.getenv('FLASK_ENV') == 'production':
    app.config['SESSION_COOKIE_SECURE'] = True

# 4. Initialize Supabase Clients FOURTH
def required_env(name):
    value = os.getenv(name)
    if not value:
        raise RuntimeError(f'{name} environment variable is missing')
    return value


supabase_url = required_env('SUPABASE_URL')

# We use anon key for Authentication (login/signup)
supabase_auth: Client = create_client(
    supabase_url,
    required_env('SUPABASE_ANON_KEY')
)

# We use service_role key for Database queries (bypasses RLS, relies on backend code for security)
supabase_db: Client = create_client(
    supabase_url,
    required_env('SUPABASE_SERVICE_ROLE_KEY')
)

# 5. Initialize Razorpay FIFTH
razorpay_client = razorpay.Client(
    auth=(os.getenv('RAZORPAY_KEY_ID'), os.getenv('RAZORPAY_KEY_SECRET'))
)

# ==========================================
# HELPER FUNCTIONS
# ==========================================

def log_audit_event(user_id, action, entity_type=None, entity_id=None, metadata=None):
    """Logs an important action to the audit_logs table."""
    try:
        supabase_db.table('audit_logs').insert({
            'user_id': user_id,
            'action': action,
            'entity_type': entity_type,
            'entity_id': entity_id,
            'metadata': metadata or {}
        }).execute()
    except Exception as e:
        print(f"Audit log error: {e}")

# ... (The rest of your routes and functions continue exactly as they were below this) ...

# ==========================================
# AUTHENTICATION & AUTHORIZATION HELPERS
# ==========================================

def get_current_user():
    """Checks if the user has a valid session and returns their data."""
    access_token = session.get('access_token')
    if not access_token:
        return None
    
    try:
        # Verify the token with Supabase
        response = supabase_auth.auth.get_user(access_token)
        if response and response.user:
            return response.user
    except Exception as e:
        print(f"Auth error: {e}")
        session.clear()  # Clear invalid session
        return None
    return None

def get_user_profile(user_id):
    """Fetches the user's profile from the database."""
    try:
        response = supabase_db.table('profiles').select('*').eq('auth_user_id', user_id).execute()
        if response.data:
            return response.data[0]
    except Exception as e:
        print(f"Profile fetch error: {e}")
    return None

# Inject user data into all templates automatically
@app.context_processor
def inject_user():
    user = get_current_user()
    profile = None
    if user:
        profile = get_user_profile(user.id)
    return dict(current_user=user, current_profile=profile)


def login_required(f):
    """Decorator to protect routes. User must be logged in and active."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        if not user:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        
        profile = get_user_profile(user.id)
        if not profile:
            flash('Profile not found. Please contact support.', 'danger')
            session.clear()
            return redirect(url_for('login'))
            
        # 1. Check if account is blocked (hard ban)
        if profile.get('status') != 'active':
            flash('Your account is inactive or blocked.', 'danger')
            session.clear()
            return redirect(url_for('login'))

        # 2. Check if account is RESTRICTED (soft ban)
        # If restricted, only allow access to the Dashboard (to see the warning)
        # Block access to QR, Analytics, Business settings, etc.
        if profile.get('is_restricted') and request.path != '/dashboard':
            flash('️ Your account is restricted. Please check the notification on your Dashboard.', 'danger')
            return redirect(url_for('dashboard'))
            
        return f(*args, **kwargs)
    return decorated_function

def client_required(f):
    """Decorator to ensure only 'client' role can access."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        profile = get_user_profile(user.id)
        if profile.get('role') != 'client':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def owner_required(f):
    """Decorator to ensure only 'owner' role can access."""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        user = get_current_user()
        profile = get_user_profile(user.id)
        if profile.get('role') != 'owner':
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function



# ==========================================
# PUBLIC WEBSITE ROUTES
# ==========================================

@app.route('/')
def home():
    # If logged in, go to dashboard. If not, show landing page.
    if get_current_user():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/features')
def features():
    return render_template('features.html')

@app.route('/pricing')
def pricing():
    return render_template('pricing.html')

@app.route('/use-cases')
def use_cases():
    return render_template('use_cases.html')

@app.route('/faq')
def faq():
    return render_template('faq.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')


# ==========================================
# PUBLIC & AUTH ROUTES
# ==========================================



@app.route('/login')
def login():
    if get_current_user():
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/signup')
def signup():
    if get_current_user():
        return redirect(url_for('dashboard'))
    return render_template('signup.html')

@app.route('/auth/google')
def auth_google():
    """Redirects user to Google OAuth via Supabase."""
    # Use Supabase's built-in OAuth URL
    redirect_uri = url_for('login', _external=True)
    
    auth_url = f"{os.getenv('SUPABASE_URL')}/auth/v1/authorize"
    params = {
        'provider': 'google',
        'redirect_to': redirect_uri
    }
    
    query_string = urllib.parse.urlencode(params)
    google_url = f"{auth_url}?{query_string}"
    
    return redirect(google_url)

@app.route('/auth/callback')
def auth_callback():
    """Handles the redirect back from Google OAuth."""
    # Get the code from query parameters
    code = request.args.get('code')
    error = request.args.get('error')
    
    if error:
        error_description = request.args.get('error_description', 'Unknown error')
        flash(f'Authentication error: {error_description}', 'danger')
        return redirect(url_for('login'))
    
    if not code:
        # If no code, check if token is in URL (alternative flow)
        flash('No authentication code received. Please try again.', 'warning')
        return redirect(url_for('login'))
    
    try:
        # Exchange the code for a session
        res = supabase_auth.auth.exchange_code_for_session(code)
        
        if res.session:
            # Store tokens in session
            session['access_token'] = res.session.access_token
            session['refresh_token'] = res.session.refresh_token
            session.permanent = True  # Make session permanent
            
            flash('Successfully logged in!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to create session. Please try again.', 'danger')
            return redirect(url_for('login'))
            
    except Exception as e:
        print(f"Callback error: {e}")
        flash('Authentication failed. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/send-otp', methods=['POST'])
def send_otp():
    """Sends a One-Time Password to the user's email."""
    email = request.form.get('email')
    if not email:
        flash('Email is required.', 'danger')
        return redirect(url_for('login'))
    
    try:
        # Supabase handles both signup and login via OTP
        supabase_auth.auth.sign_in_with_otp({'email': email})
        flash('OTP sent to your email. Please check your inbox.', 'success')
        session['otp_email'] = email
        return redirect(url_for('verify_otp_page'))
    except Exception as e:
        print(f"OTP send error: {e}")
        flash('Failed to send OTP. Please try again.', 'danger')
        return redirect(url_for('login'))

@app.route('/verify-otp')
def verify_otp_page():
    if 'otp_email' not in session:
        return redirect(url_for('login'))
    return render_template('verify_otp.html', email=session['otp_email'])

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    """Verifies the OTP entered by the user."""
    email = request.form.get('email') or session.get('otp_email')
    token = request.form.get('token')
    
    if not email or not token:
        flash('Email and OTP are required.', 'danger')
        return redirect(url_for('login'))
        
    try:
        res = supabase_auth.auth.verify_otp({'email': email, 'token': token, 'type': 'email'})
        if res.session:
            session['access_token'] = res.session.access_token
            session['refresh_token'] = res.session.refresh_token
            session.pop('otp_email', None)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid OTP.', 'danger')
    except Exception as e:
        print(f"OTP verify error: {e}")
        flash('Invalid OTP or expired. Please try again.', 'danger')
        
    return redirect(url_for('verify_otp_page'))

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/auth/set-session', methods=['POST'])
def set_session():
    """Receives access token from frontend (hash fragment) and sets server session."""
    data = request.get_json()
    access_token = data.get('access_token')
    
    if not access_token:
        return jsonify({'error': 'No token provided'}), 400
    
    try:
        # Verify the token with Supabase
        response = supabase_auth.auth.get_user(access_token)
        
        if response and response.user:
            # Store in Flask session
            session['access_token'] = access_token
            session.permanent = True
            return jsonify({'success': True, 'redirect': url_for('dashboard')})
        else:
            return jsonify({'error': 'Invalid token'}), 401
            
    except Exception as e:
        print(f"Set session error: {e}")
        return jsonify({'error': 'Token verification failed'}), 401

# ==========================================
# PROTECTED DASHBOARD ROUTES
# ==========================================

@app.route('/dashboard')
@login_required
def dashboard():
    user = get_current_user()
    profile = get_user_profile(user.id)
    
    # Redirect owners to the owner dashboard
    if profile.get('role') == 'owner':
        return redirect(url_for('owner_dashboard'))
    
    # Get user's business
    business_result = supabase_db.table('businesses').select('*').eq('owner_user_id', user.id).execute()
    business_exists = False
    business = None
    reviews_count = 0
    qr_scans = 0
    subscription = None
    alerts = []
    
    if business_result.data and len(business_result.data) > 0:
        business_exists = True
        business = business_result.data[0]
        business_id = business['id']
        
        # 1. Count Reviews Generated (total reviews in pool)
        reviews_result = supabase_db.table('review_pool').select('id', count='exact').eq('business_id', business_id).execute()
        reviews_count = reviews_result.count if reviews_result.count else 0
        
        # 2. Count QR Code Scans (page_view events)
        scans_result = supabase_db.table('review_events').select('id', count='exact').eq('business_id', business_id).eq('event_type', 'page_view').execute()
        qr_scans = scans_result.count if scans_result.count else 0
        
        # 3. Get active subscription
        sub_result = supabase_db.table('subscriptions').select('*').eq('client_id', user.id).eq('status', 'active').execute()
        if sub_result.data:
            subscription = sub_result.data[0]
            
            # Calculate days remaining
            if subscription.get('end_date'):
                try:
                    end_date = datetime.fromisoformat(subscription['end_date'].replace('Z', '+00:00'))
                    days_remaining = (end_date - datetime.now(end_date.tzinfo)).days
                    subscription['days_remaining'] = max(0, days_remaining)
                except:
                    subscription['days_remaining'] = 0
            else:
                subscription['days_remaining'] = 0
        
        # 4. Check for unread alerts from Owner
        alerts_result = supabase_db.table('client_alerts').select('*').eq('client_id', user.id).eq('is_read', False).order('created_at', desc=True).execute()
        alerts = alerts_result.data if alerts_result.data else []

    if alerts:
        supabase_db.table('client_alerts').update({'is_read': True}).eq('client_id', user.id).eq('is_read', False).execute()

    return render_template('dashboard.html', 
                         business_exists=business_exists,
                         business=business,
                         subscription=subscription,
                         reviews_count=reviews_count,
                         qr_scans=qr_scans,
                         alerts=alerts)


# ==========================================
# BUSINESS SETUP ROUTES
# ==========================================

@app.route('/business/setup')
@client_required
def business_setup():
    """Show business setup form for clients who haven't created a business yet."""
    user = get_current_user()
    profile = get_user_profile(user.id)
    
    # Check if user already has a business
    existing_business = supabase_db.table('businesses').select('*').eq('owner_user_id', user.id).execute()
    
    if existing_business.data and len(existing_business.data) > 0:
        # User already has a business, redirect to dashboard
        return redirect(url_for('dashboard'))
    
    # Fetch industries and business types for the form
    industries = supabase_db.table('industries').select('*').eq('status', 'active').execute()
    business_types = supabase_db.table('business_types').select('*').eq('status', 'active').execute()
    
    return render_template('business_setup.html', 
                         industries=industries.data, 
                         business_types=business_types.data)

@app.route('/business/create', methods=['POST'])
@client_required
def business_create():
    """Create a new business for the client."""
    user = get_current_user()
    profile = get_user_profile(user.id)
    
    # Get form data
    business_name = request.form.get('business_name')
    location = request.form.get('location')
    industry_id = request.form.get('industry_id')
    business_type_id = request.form.get('business_type_id')
    custom_business_type = request.form.get('custom_business_type')
    google_review_url = request.form.get('google_review_url')
    keywords = request.form.get('keywords')
    description = request.form.get('description')
    
    # Validation
    if not business_name:
        flash('Business name is required.', 'danger')
        return redirect(url_for('business_setup'))
    
    if not industry_id:
        flash('Please select an industry.', 'danger')
        return redirect(url_for('business_setup'))
    
    # If business type is "other", require custom text
    if business_type_id == 'other' and not custom_business_type:
        flash('Please specify your business type.', 'danger')
        return redirect(url_for('business_setup'))
    
    try:
        # Create the business
        business_data = {
            'owner_user_id': user.id,
            'business_name': business_name,
            'location': location,
            'industry_id': industry_id if industry_id != 'other' else None,
            'business_type_id': business_type_id if business_type_id != 'other' else None,
            'custom_business_type': custom_business_type if business_type_id == 'other' else None,
            'google_review_url': google_review_url,
            'keywords': keywords,
            'description': description,
            'status': 'active'
        }
        
        result = supabase_db.table('businesses').insert(business_data).execute()
        
        if result.data:
            flash('Business created successfully!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Failed to create business. Please try again.', 'danger')
            return redirect(url_for('business_setup'))
            
    except Exception as e:
        print(f"Business creation error: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('business_setup'))

@app.route('/business')
@client_required
def business_view():
    """View and edit existing business."""
    user = get_current_user()
    profile = get_user_profile(user.id)
    
    # Get user's business
    result = supabase_db.table('businesses').select('*').eq('owner_user_id', user.id).execute()
    
    if not result.data or len(result.data) == 0:
        return redirect(url_for('business_setup'))
    
    business = result.data[0]
    
    # Fetch industries and business types for the form
    industries = supabase_db.table('industries').select('*').eq('status', 'active').execute()
    business_types = supabase_db.table('business_types').select('*').eq('status', 'active').execute()
    
    return render_template('business_view.html', 
                         business=business,
                         industries=industries.data, 
                         business_types=business_types.data)

@app.route('/business/update', methods=['POST'])
@client_required
def business_update():
    """Update existing business."""
    user = get_current_user()
    profile = get_user_profile(user.id)
    
    # Get user's business
    result = supabase_db.table('businesses').select('id').eq('owner_user_id', user.id).execute()
    
    if not result.data or len(result.data) == 0:
        flash('Business not found.', 'danger')
        return redirect(url_for('business_setup'))
    
    business_id = result.data[0]['id']
    
    # Get form data
    business_name = request.form.get('business_name')
    location = request.form.get('location')
    industry_id = request.form.get('industry_id')
    business_type_id = request.form.get('business_type_id')
    custom_business_type = request.form.get('custom_business_type')
    google_review_url = request.form.get('google_review_url')
    keywords = request.form.get('keywords')
    description = request.form.get('description')
    
    # Validation
    if not business_name:
        flash('Business name is required.', 'danger')
        return redirect(url_for('business_view'))
    
    try:
        # Update the business
        update_data = {
            'business_name': business_name,
            'location': location,
            'industry_id': industry_id if industry_id != 'other' else None,
            'business_type_id': business_type_id if business_type_id != 'other' else None,
            'custom_business_type': custom_business_type if business_type_id == 'other' else None,
            'google_review_url': google_review_url,
            'keywords': keywords,
            'description': description,
            'updated_at': 'now()'
        }
        
        result = supabase_db.table('businesses').update(update_data).eq('id', business_id).execute()
        
        flash('Business updated successfully!', 'success')
        return redirect(url_for('business_view'))
            
    except Exception as e:
        print(f"Business update error: {e}")
        flash('An error occurred. Please try again.', 'danger')
        return redirect(url_for('business_view'))

# ==========================================
# ERROR HANDLERS
# ==========================================

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page Not Found"), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error_code=403, error_message="Access Forbidden"), 403

@app.errorhandler(500)
def internal_error(e):
    # In production, you would log this error to a file or service like Sentry
    print(f"CRITICAL SERVER ERROR: {e}")
    return render_template('error.html', error_code=500, error_message="Internal Server Error"), 500


#====razorpay integration========
import razorpay
from datetime import datetime, timedelta

# Initialize Razorpay
razorpay_client = razorpay.Client(
    auth=(os.getenv('RAZORPAY_KEY_ID'), os.getenv('RAZORPAY_KEY_SECRET'))
)

# ==========================================
# SUBSCRIPTION & PAYMENT ROUTES
# ==========================================

@app.route('/subscription')
@client_required
def subscription_page():
    """Show subscription plans and current subscription status."""
    user = get_current_user()
    profile = get_user_profile(user.id)
    
    # Get user's business
    business_result = supabase_db.table('businesses').select('id').eq('owner_user_id', user.id).execute()
    if not business_result.data:
        flash('Please setup your business first.', 'warning')
        return redirect(url_for('business_setup'))
    
    business_id = business_result.data[0]['id']
    
    # Get active subscription
    active_sub = supabase_db.table('subscriptions').select('*').eq('client_id', user.id).eq('status', 'active').execute()
    current_subscription = active_sub.data[0] if active_sub.data else None
    
    # Get all active plans
    plans = supabase_db.table('plans').select('*').eq('status', 'active').execute()
    
    return render_template('subscription.html', 
                         plans=plans.data, 
                         current_subscription=current_subscription,
                         business_id=business_id)


@app.route('/payment/create-order', methods=['POST'])
@client_required
def create_payment_order():
    """Create Razorpay payment order with optional discount."""
    user = get_current_user()
    
    plan_id = request.form.get('plan_id')
    discount_code = request.form.get('discount_code', '').strip().upper()
    
    # Get plan details
    plan_result = supabase_db.table('plans').select('*').eq('id', plan_id).eq('status', 'active').execute()
    if not plan_result.data:
        return jsonify({'error': 'Invalid plan'}), 400
    
    plan = plan_result.data[0]
    original_amount = float(plan['price'])
    
    # Apply Discount
    discount_result = validate_discount_code(discount_code, original_amount)
    discount_amount = 0
    final_amount = original_amount
    
    if discount_result['valid']:
        discount_amount = discount_result['discount_amount']
        final_amount = discount_result['final_amount']
        
        # Increment used count safely
        supabase_db.table('discount_codes').update(
            {'used_count': supabase_db.table('discount_codes').select('used_count').eq('id', discount_result['discount_id']).single().execute().data['used_count'] + 1}
        ).eq('id', discount_result['discount_id']).execute()

    # Convert to paise for Razorpay
    amount_in_paise = int(final_amount * 100)
    
    # Get user's business
    business_result = supabase_db.table('businesses').select('id').eq('owner_user_id', user.id).execute()
    business_id = business_result.data[0]['id'] if business_result.data else None
    
    try:
        razorpay_order = razorpay_client.order.create({
            'amount': amount_in_paise,
            'currency': plan['currency'],
            'payment_capture': 1,
            'notes': {'user_id': str(user.id), 'plan_id': plan_id}
        })
        
        subscription_data = {
            'client_id': user.id,
            'business_id': business_id,
            'plan_id': plan_id,
            'razorpay_order_id': razorpay_order['id'],
            'status': 'pending',
            'amount': original_amount,
            'discount_amount': discount_amount,
            'final_amount': final_amount,
            'created_at': 'now()'
        }
        
        supabase_db.table('subscriptions').insert(subscription_data).execute()
        
        return jsonify({
            'success': True,
            'order_id': razorpay_order['id'],
            'amount': amount_in_paise,
            'currency': plan['currency'],
            'key_id': os.getenv('RAZORPAY_KEY_ID'),
            'discount_applied': discount_amount > 0,
            'final_display_amount': final_amount
        })
        
    except Exception as e:
        print(f"Payment order creation error: {e}")
        return jsonify({'error': 'Failed to create payment order'}), 500



@app.route('/payment/verify', methods=['POST'])
@client_required
def verify_payment():
    """Verify Razorpay payment signature and activate subscription."""
    user = get_current_user()
    profile = get_user_profile(user.id)
    
    # Get payment details from request
    razorpay_order_id = request.form.get('razorpay_order_id')
    razorpay_payment_id = request.form.get('razorpay_payment_id')
    razorpay_signature = request.form.get('razorpay_signature')
    
    try:
        # Verify payment signature
        razorpay_client.utility.verify_payment_signature({
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature
        })
        
        # Get subscription record
        sub_result = supabase_db.table('subscriptions').select('*').eq('razorpay_order_id', razorpay_order_id).execute()
        if not sub_result.data:
            return jsonify({'error': 'Subscription not found'}), 404
        
        subscription = sub_result.data[0]
        
        # Calculate dates
        plan_result = supabase_db.table('plans').select('duration_days').eq('id', subscription['plan_id']).execute()
        duration_days = plan_result.data[0]['duration_days']
        
        start_date = datetime.utcnow()
        end_date = start_date + timedelta(days=duration_days)
        
        # Update subscription to active
        supabase_db.table('subscriptions').update({
            'status': 'active',
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature,
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'updated_at': 'now()'
        }).eq('razorpay_order_id', razorpay_order_id).execute()
        
        # Create payment record
        payment_data = {
            'client_id': user.id,
            'business_id': subscription.get('business_id'),
            'plan_id': subscription['plan_id'],
            'razorpay_order_id': razorpay_order_id,
            'razorpay_payment_id': razorpay_payment_id,
            'razorpay_signature': razorpay_signature,
            'amount': subscription['amount'],
            'discount_amount': subscription.get('discount_amount', 0),
            'final_amount': subscription['final_amount'],
            'currency': 'INR',
            'status': 'completed',
            'payment_date': 'now()'
        }
        
        supabase_db.table('payments').insert(payment_data).execute()
        
        return jsonify({'success': True, 'message': 'Payment successful! Subscription activated.'})
        
    except razorpay.errors.SignatureVerificationError:
        # Payment verification failed
        supabase_db.table('subscriptions').update({
            'status': 'failed'
        }).eq('razorpay_order_id', razorpay_order_id).execute()
        
        return jsonify({'error': 'Payment verification failed'}), 400
        
    except Exception as e:
        print(f"Payment verification error: {e}")
        return jsonify({'error': 'Payment processing failed'}), 500

@app.route('/payment/success')
@client_required
def payment_success():
    """Show success page after payment."""
    return render_template('payment_success.html')

@app.route('/billing')
@client_required
def billing_page():
    """Show billing history."""
    user = get_current_user()
    
    # Get user's payments
    payments = supabase_db.table('payments').select('*').eq('client_id', user.id).order('created_at', desc=True).execute()
    
    return render_template('billing.html', payments=payments.data)

#====razorpay integration========


# ==========================================
#ai agent 
# ==========================================
import cohere
import json
import time

# ==========================================
# COHERE AI & KEY ROTATION (UPDATED TO CHAT API)
# ==========================================

def get_cohere_keys():
    """Returns a list of valid Cohere API keys from environment."""
    keys = []
    for i in range(1, 5):
        key = os.getenv(f'COHERE_API_KEY_{i}')
        if key and key.strip():
            keys.append(key)
    return keys

def call_cohere_chat(message, max_tokens=1000):
    """Calls Cohere Chat API with automatic key rotation on rate limits."""
    keys = get_cohere_keys()
    if not keys:
        raise Exception("No Cohere API keys configured.")
    
    last_error = None
    for key in keys:
        try:
            co = cohere.Client(key)
            response = co.chat(
                message=message,
                max_tokens=max_tokens,
                temperature=0.7,
                p=0.75,
                prompt_truncation="OFF"
            )
            return response.text
        except Exception as e:
            error_str = str(e).lower()
            # If it's a rate limit or quota error, try the next key
            if "429" in error_str or "rate limit" in error_str or "quota" in error_str:
                last_error = e
                continue 
            # For any other error (bad key, bad prompt), raise immediately
            raise e
            
    # If we exhausted all keys and all failed with rate limits
    raise Exception(f"All Cohere API keys failed. Last error: {last_error}")

def generate_ai_context(business):
    """Creates or updates AI context for a business."""
    existing = supabase_db.table('ai_context').select('id').eq('business_id', business['id']).execute()
    
    context_data = {
        'business_id': business['id'],
        'business_description': business.get('description', ''),
        'industry': 'General',
        'business_type': business.get('custom_business_type', 'Business'),
        'keywords': business.get('keywords', ''),
        'tone': 'Professional and Friendly',
        'language': 'English',
        'active': True
    }
    
    if existing.data:
        supabase_db.table('ai_context').update(context_data).eq('business_id', business['id']).execute()
    else:
        supabase_db.table('ai_context').insert(context_data).execute()
        
    return context_data

def generate_review_pool(business_id, star_rating, count=12):
    """Generates AI review suggestions for a specific star rating."""
    # Get business and AI context
    business = supabase_db.table('businesses').select('*').eq('id', business_id).execute().data[0]
    context = supabase_db.table('ai_context').select('*').eq('business_id', business_id).execute().data[0]
    
    # Get master prompt
    prompt_settings = supabase_db.table('ai_settings').select('setting_value').eq('setting_key', 'master_review_prompt').execute().data[0]
    master_prompt = prompt_settings['setting_value']
    
    # Format prompt
    formatted_prompt = master_prompt.format(
        count=count,
        business_name=business['business_name'],
        business_type=context['business_type'],
        industry=context['industry'],
        location=business.get('location', 'Unknown'),
        keywords=context['keywords'],
        description=context['business_description'],
        star_rating=star_rating
    )
    
    # Call Cohere Chat API
    generated_text = call_cohere_chat(formatted_prompt, max_tokens=1500)
    
    # Parse JSON safely
    try:
        # Remove markdown formatting if AI accidentally adds it
        if generated_text.startswith("```"):
            generated_text = generated_text.split("\n", 1)[1]
        if generated_text.endswith("```"):
            generated_text = generated_text.rsplit("```", 1)[0]
            
        reviews = json.loads(generated_text)
    except json.JSONDecodeError:
        print(f"JSON Parse Error for star {star_rating}: {generated_text}")
        return 0
    
    # Save to database
    inserted_count = 0
    for review_text in reviews:
        if isinstance(review_text, str) and len(review_text) > 10:
            supabase_db.table('review_pool').insert({
                'business_id': business_id,
                'star_rating': star_rating,
                'review_text': review_text.strip(),
                'status': 'available'
            }).execute()
            inserted_count += 1
            
    return inserted_count

# ==========================================
# AI ROUTES
# ==========================================

@app.route('/api/generate-pool', methods=['POST'])
@client_required
def api_generate_pool():
    """Triggers the generation of the initial 60-review pool."""
    user = get_current_user()
    
    # Get user's business
    business_result = supabase_db.table('businesses').select('id').eq('owner_user_id', user.id).execute()
    if not business_result.data:
        return jsonify({'error': 'Business not found'}), 404
        
    business_id = business_result.data[0]['id']
    
    try:
        # 1. Generate AI Context
        full_business = supabase_db.table('businesses').select('*').eq('id', business_id).execute().data[0]
        generate_ai_context(full_business)
        
        # 2. Generate 12 reviews for each star rating (1 to 5)
        total_generated = 0
        for star in range(1, 6):
            count = generate_review_pool(business_id, star, count=12)
            total_generated += count
            # Small delay to prevent overwhelming the API
            time.sleep(1) 
            
        return jsonify({'success': True, 'message': f'Successfully generated {total_generated} review suggestions!'})
        
    except Exception as e:
        print(f"AI Generation Error: {e}")
        return jsonify({'error': str(e)}), 500

# ==========================================
#ai agent 
# ==========================================

# ==========================================
# QR CODE & CUSTOMER REVIEW ROUTES
# ==========================================

# ==========================================
# QR CODE & CUSTOMER REVIEW ROUTES
# ==========================================

def generate_qr_image_base64(url):
    """Generates a QR code in memory and returns it as a Base64 string."""
    import io
    import base64
    import qrcode
    import qrcode.image.pil  # Explicitly import PIL factory
    
    # Force qrcode to use PIL (Pillow) instead of pypng
    qr = qrcode.QRCode(
        version=1,
        box_size=10,
        border=5,
        image_factory=qrcode.image.pil.PilImage
    )
    qr.add_data(url)
    qr.make(fit=True)
    
    # Create the image (this is now guaranteed to be a PIL Image)
    img = qr.make_image(fill_color="#14532d", back_color="white")
    
    # Save to bytes buffer
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    
    # Encode to base64
    img_str = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return img_str


@app.route('/qr')
@client_required
def qr_dashboard():
    """Show QR code page for the client."""
    user = get_current_user()
    
    # Get business
    business_result = supabase_db.table('businesses').select('id, business_name, google_review_url').eq('owner_user_id', user.id).execute()
    if not business_result.data:
        flash('Please setup your business first.', 'warning')
        return redirect(url_for('business_setup'))
        
    business = business_result.data[0]
    
    # CHECK FOR ACTIVE SUBSCRIPTION
    subscription_result = supabase_db.table('subscriptions').select('*').eq('client_id', user.id).eq('status', 'active').execute()
    
    if not subscription_result.data:
        flash('You need an active subscription to access QR codes. Please choose a plan.', 'warning')
        return redirect(url_for('subscription_page'))
    
    # Check if QR code exists
    qr_result = supabase_db.table('qr_codes').select('*').eq('business_id', business['id']).execute()
    
    if not qr_result.data:
        # Generate new token and QR code
        token = secrets.token_urlsafe(12)
        review_url = f"{request.host_url}r/{token}"
        
        supabase_db.table('qr_codes').insert({
            'business_id': business['id'],
            'public_token': token
        }).execute()
        
        qr_result = supabase_db.table('qr_codes').select('*').eq('business_id', business['id']).execute()

    qr_data = qr_result.data[0]
    review_url = f"{request.host_url}r/{qr_data['public_token']}"
    qr_image = generate_qr_image_base64(review_url)
    
    return render_template('qr_dashboard.html', 
                         business=business, 
                         qr_data=qr_data, 
                         review_url=review_url, 
                         qr_image=qr_image)



@app.route('/r/<token>')
def customer_review_page(token):
    """Public page for customers to leave a review. No login required."""
    # Find business by token
    qr_result = supabase_db.table('qr_codes').select('business_id, active').eq('public_token', token).eq('active', True).execute()
    
    if not qr_result.data:
        return render_template('base.html', content='<div class="text-center py-20"><h1 class="text-2xl text-danger">Invalid or Expired QR Code</h1></div>'), 404
        
    business_id = qr_result.data[0]['business_id']
    
    # Get business details
    business_result = supabase_db.table('businesses').select('business_name, google_review_url, owner_user_id').eq('id', business_id).execute()
    if not business_result.data:
        return "Business not found", 404
        
    business = business_result.data[0]
    
    # CHECK IF OWNER IS RESTRICTED
    owner_profile = supabase_db.table('profiles').select('is_restricted').eq('auth_user_id', business['owner_user_id']).single().execute().data
    
    if owner_profile and owner_profile.get('is_restricted'):
        # Show suspended message instead of review form
        return render_template('base.html', content=f'''
            <div class="min-h-[60vh] flex items-center justify-center px-4">
                <div class="text-center max-w-md">
                    <div class="w-20 h-20 bg-red-100 rounded-full flex items-center justify-center mx-auto mb-6">
                        <svg class="w-10 h-10 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"></path>
                        </svg>
                    </div>
                    <h1 class="text-2xl font-bold text-text mb-4">Service Temporarily Unavailable</h1>
                    <p class="text-muted mb-6">
                        <strong>{business['business_name']}</strong> is currently undergoing maintenance. 
                        Please try again later or contact the business directly.
                    </p>
                    <a href="/" class="inline-block bg-primary hover:bg-primary-hover text-white px-6 py-2 rounded-lg transition">
                        Go Home
                    </a>
                </div>
            </div>
        '''), 503
    
    return render_template('customer_review.html', 
                         business=business, 
                         token=token)

@app.route('/api/review/suggestions', methods=['POST'])
def get_review_suggestions():
    """API to fetch AI suggestions based on star rating."""
    data = request.get_json()
    token = data.get('token')
    star_rating = data.get('star_rating')
    
    if not token or not star_rating:
        return jsonify({'error': 'Missing data'}), 400
        
    # Find business
    qr_result = supabase_db.table('qr_codes').select('business_id').eq('public_token', token).execute()
    if not qr_result.data:
        return jsonify({'error': 'Invalid token'}), 404
        
    business_id = qr_result.data[0]['business_id']
    
    # Fetch 5 available reviews for this star rating
    reviews_result = supabase_db.table('review_pool').select('id, review_text').eq('business_id', business_id).eq('star_rating', star_rating).eq('status', 'available').limit(5).execute()
    
    if not reviews_result.data:
        # Fallback if pool is empty (shouldn't happen if Phase 10 worked)
        return jsonify({'suggestions': ["Great service!", "Highly recommended.", "Very professional.", "Excellent experience.", "Will visit again."]})
        
    return jsonify({'suggestions': reviews_result.data})


@app.route('/api/review/select', methods=['POST'])
def select_review():
    """Mark a review as 'used' and trigger auto-refill if needed."""
    data = request.get_json()
    review_id = data.get('review_id')
    
    if not review_id:
        return jsonify({'error': 'Missing review ID'}), 400
        
    try:
        # 1. Get the review details before updating
        review_data = supabase_db.table('review_pool').select('business_id, star_rating').eq('id', review_id).execute().data[0]
        
        # 2. Mark as used
        supabase_db.table('review_pool').update({
            'status': 'used',
            'used_at': 'now()'
        }).eq('id', review_id).execute()
        
        # 3. TRIGGER AUTO-REFILL (Phase 12)
        maintain_review_pool(review_data['business_id'], review_data['star_rating'])
        
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error marking review used: {e}")
        return jsonify({'error': 'Failed to update'}), 500

# ==========================================
# QR CODE & CUSTOMER REVIEW ROUTES
# ==========================================




# ==========================================
# PHASE 12: AUTO-REFILL LOGIC
# ==========================================

def maintain_review_pool(business_id, star_rating):
    """Checks if available reviews are low, and refills them automatically based on Owner settings."""
    # 1. Get Owner Settings
    min_pool_setting = supabase_db.table('ai_settings').select('setting_value').eq('setting_key', 'min_pool_size').execute()
    min_pool_size = int(min_pool_setting.data[0]['setting_value']) if min_pool_setting.data else 5

    refill_setting = supabase_db.table('ai_settings').select('setting_value').eq('setting_key', 'refill_quantity').execute()
    refill_quantity = int(refill_setting.data[0]['setting_value']) if refill_setting.data else 7

    # 2. Count available reviews
    count_result = supabase_db.table('review_pool').select('id', count='exact').eq('business_id', business_id).eq('star_rating', star_rating).eq('status', 'available').execute()
    available_count = count_result.count if count_result.count is not None else 0
    
    # 3. Refill if needed
    if available_count < min_pool_size:
        print(f"⚠️ Low review pool! Refilling {refill_quantity} reviews (Current: {available_count})")
        try:
            generate_review_pool(business_id, star_rating, count=refill_quantity)
            print("✅ Review pool refilled successfully.")
        except Exception as e:
            print(f"❌ Failed to refill review pool: {e}")

# ==========================================
# PHASE 13: ANALYTICS ROUTES
# ==========================================

@app.route('/api/analytics/event', methods=['POST'])
def log_analytics_event():
    """Logs customer interactions anonymously."""
    data = request.get_json()
    event_type = data.get('event_type')
    token = data.get('token')
    star_rating = data.get('star_rating')
    review_id = data.get('review_id')
    
    if not token or not event_type:
        return jsonify({'error': 'Missing data'}), 400
        
    # Find business
    qr_result = supabase_db.table('qr_codes').select('business_id').eq('public_token', token).execute()
    if not qr_result.data:
        return jsonify({'error': 'Invalid token'}), 404
        
    business_id = qr_result.data[0]['business_id']
    
    # Get or create session ID from cookie
    session_id = request.cookies.get('review_session_id') or secrets.token_hex(8)
    
    event_data = {
        'business_id': business_id,
        'session_id': session_id,
        'event_type': event_type,
        'star_rating': star_rating,
        'review_id': review_id
    }
    
    supabase_db.table('review_events').insert(event_data).execute()
    
    # Set cookie for future requests
    response = jsonify({'success': True})
    response.set_cookie('review_session_id', session_id, max_age=31536000) # 1 year
    return response

@app.route('/analytics')
@client_required
def analytics_page():
    """Displays analytics dashboard for the client."""
    user = get_current_user()
    
    # Get business
    business_result = supabase_db.table('businesses').select('id, business_name').eq('owner_user_id', user.id).execute()
    if not business_result.data:
        return redirect(url_for('business_setup'))
        
    business_id = business_result.data[0]['id']
    business_name = business_result.data[0]['business_name']
    
    # 1. Total Page Views
    views_result = supabase_db.table('review_events').select('id', count='exact').eq('business_id', business_id).eq('event_type', 'page_view').execute()
    total_views = views_result.count or 0
    
    # 2. Total Reviews Copied
    copied_result = supabase_db.table('review_events').select('id', count='exact').eq('business_id', business_id).eq('event_type', 'review_copied').execute()
    total_copied = copied_result.count or 0
    
    # 3. Total Google Clicks
    google_result = supabase_db.table('review_events').select('id', count='exact').eq('business_id', business_id).eq('event_type', 'google_clicked').execute()
    total_google = google_result.count or 0
    
    # 4. Star Rating Distribution
    stars_result = supabase_db.table('review_events').select('star_rating').eq('business_id', business_id).eq('event_type', 'star_selected').execute()
    star_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    
    if stars_result.data:
        for row in stars_result.data:
            rating = row.get('star_rating')
            if rating in star_counts:
                star_counts[rating] += 1
                
    # Calculate max for bar chart scaling
    max_stars = max(star_counts.values()) if max(star_counts.values()) > 0 else 1
    
    return render_template('analytics.html',
                         business_name=business_name,
                         total_views=total_views,
                         total_copied=total_copied,
                         total_google=total_google,
                         star_counts=star_counts,
                         max_stars=max_stars)


# ==========================================
# OWNER DASHBOARD ROUTES
# ==========================================


@app.route('/owner')
@owner_required
def owner_dashboard():
    """Main Owner Overview Page."""
    # 1. Total Clients
    clients_count = supabase_db.table('profiles').select('id', count='exact').eq('role', 'client').execute()
    total_clients = clients_count.count if clients_count.count else 0

    # 2. Active Subscriptions
    active_subs_count = supabase_db.table('subscriptions').select('id', count='exact').eq('status', 'active').execute()
    active_subs = active_subs_count.count if active_subs_count.count else 0

    # 3. Total Revenue (Sum of all completed payments)
    # Note: For MVP, we fetch and sum in Python. In production, use a Supabase Database Function.
    payments = supabase_db.table('payments').select('final_amount').eq('status', 'completed').execute()
    total_revenue = sum(p['final_amount'] for p in payments.data) if payments.data else 0

    # 4. Total Businesses
    biz_count = supabase_db.table('businesses').select('id', count='exact').execute()
    total_businesses = biz_count.count if biz_count.count else 0

    return render_template('owner_overview.html', 
                         total_clients=total_clients,
                         active_subs=active_subs,
                         total_revenue=total_revenue,
                         total_businesses=total_businesses)


@app.route('/owner/clients')
@owner_required
def owner_clients():
    """List all registered clients with usage metrics."""
    clients_result = supabase_db.table('profiles').select('*').eq('role', 'client').order('created_at', desc=True).execute()
    clients = clients_result.data if clients_result.data else []

    for client in clients:
        auth_user_id = client.get('auth_user_id')
        
        # Get Business Name
        biz_result = supabase_db.table('businesses').select('id, business_name').eq('owner_user_id', auth_user_id).limit(1).execute()
        client['business_name'] = biz_result.data[0]['business_name'] if biz_result.data else 'No Business Setup'
        business_id = biz_result.data[0]['id'] if biz_result.data else None

        # --- NEW METRICS ---
        # 1. Reviews Generated (Count rows in review_pool)
        if business_id:
            reviews_res = supabase_db.table('review_pool').select('id', count='exact').eq('business_id', business_id).execute()
            client['reviews_generated'] = reviews_res.count if reviews_res.count else 0
            
            # 2. QR Scans (Count page_view events)
            scans_res = supabase_db.table('review_events').select('id', count='exact').eq('business_id', business_id).eq('event_type', 'page_view').execute()
            client['qr_scans'] = scans_res.count if scans_res.count else 0
        else:
            client['reviews_generated'] = 0
            client['qr_scans'] = 0
        # ---------------------

        # Get Subscription
        sub_result = supabase_db.table('subscriptions').select('status, end_date').eq('client_id', auth_user_id).order('created_at', desc=True).limit(1).execute()
        if sub_result.data:
            client['sub_status'] = sub_result.data[0]['status']
            client['sub_end'] = sub_result.data[0]['end_date'][:10] if sub_result.data[0].get('end_date') else '-'
        else:
            client['sub_status'] = 'none'
            client['sub_end'] = '-'

    return render_template('owner_clients.html', clients=clients)


# ==========================================
# OWNER DASHBOARD ROUTES
# ==========================================


# ==========================================
# PHASE 15: DISCOUNT CODES
# ==========================================

from datetime import datetime


def validate_discount_code(code, plan_price):
    """Validates a discount code and returns the discounted amount."""
    if not code:
        return {'valid': False, 'error': 'No code provided'}
        
    # Fetch code from DB
    result = supabase_db.table('discount_codes').select('*').eq('code', code.upper()).eq('status', 'active').execute()
    
    if not result.data:
        return {'valid': False, 'error': 'Invalid or inactive code'}
        
    discount = result.data[0]
    
    # Check dates
    now = datetime.utcnow()
    if discount.get('valid_until') and datetime.fromisoformat(discount['valid_until'].replace('Z', '+00:00').replace('+00:00', '')) < now:
        return {'valid': False, 'error': 'Code has expired'}
        
    # Check uses
    if discount['max_uses'] > 0 and discount['used_count'] >= discount['max_uses']:
        return {'valid': False, 'error': 'Code usage limit reached'}
        
    # Calculate discount
    discount_amount = 0
    if discount['discount_type'] == 'percentage':
        discount_amount = plan_price * (discount['discount_value'] / 100)
    else: # fixed
        discount_amount = discount['discount_value']
        
    # Ensure final amount isn't negative
    final_amount = max(0, plan_price - discount_amount)
    
    return {
        'valid': True, 
        'discount_amount': discount_amount, 
        'final_amount': final_amount,
        'discount_id': discount['id']
    }

@app.route('/owner/discounts')
@owner_required
def owner_discounts():
    """View all discount codes."""
    discounts = supabase_db.table('discount_codes').select('*').order('created_at', desc=True).execute().data
    return render_template('owner_discounts.html', discounts=discounts)

@app.route('/owner/discounts/create', methods=['POST'])
@owner_required
def create_discount():
    """Create a new discount code."""
    code = request.form.get('code').strip().upper()
    discount_type = request.form.get('discount_type')
    discount_value = float(request.form.get('discount_value'))
    max_uses = int(request.form.get('max_uses') or 0)
    valid_until = request.form.get('valid_until') or None
    
    try:
        supabase_db.table('discount_codes').insert({
            'code': code,
            'discount_type': discount_type,
            'discount_value': discount_value,
            'max_uses': max_uses,
            'valid_until': valid_until,
            'status': 'active'
        }).execute()
        flash('Discount code created successfully!', 'success')
    except Exception as e:
        print(f"Discount creation error: {e}")
        flash('Failed to create discount code. Code might already exist.', 'danger')
        
    return redirect(url_for('owner_discounts'))

@app.route('/api/validate-discount', methods=['POST'])
def api_validate_discount():
    """API for frontend to check discount before payment."""
    data = request.get_json()
    code = data.get('code')
    plan_price = float(data.get('plan_price'))
    
    result = validate_discount_code(code, plan_price)
    return jsonify(result)


# ==========================================
# PHASE 15: DISCOUNT CODES
# ==========================================
# ==========================================
# PHASE 16: LEAD MANAGEMENT
# ==========================================

@app.route('/owner/leads')
@owner_required
def owner_leads():
    """View all leads."""
    leads = supabase_db.table('leads').select('*').order('created_at', desc=True).execute().data
    return render_template('owner_leads.html', leads=leads)

@app.route('/owner/leads/create', methods=['POST'])
@owner_required
def create_lead():
    """Create a new lead."""
    try:
        supabase_db.table('leads').insert({
            'name': request.form.get('name'),
            'email': request.form.get('email'),
            'phone': request.form.get('phone'),
            'business_name': request.form.get('business_name'),
            'industry': request.form.get('industry'),
            'status': 'new',
            'notes': request.form.get('notes')
        }).execute()
        flash('Lead created successfully!', 'success')
    except Exception as e:
        print(f"Lead creation error: {e}")
        flash('Failed to create lead.', 'danger')
        
    return redirect(url_for('owner_leads'))

@app.route('/owner/leads/update/<lead_id>', methods=['POST'])
@owner_required
def update_lead(lead_id):
    """Update lead status or notes."""
    try:
        supabase_db.table('leads').update({
            'status': request.form.get('status'),
            'notes': request.form.get('notes'),
            'follow_up_date': request.form.get('follow_up_date') or None,
            'updated_at': 'now()'
        }).eq('id', lead_id).execute()
        flash('Lead updated successfully!', 'success')
    except Exception as e:
        print(f"Lead update error: {e}")
        flash('Failed to update lead.', 'danger')
        
    return redirect(url_for('owner_leads'))

# ==========================================
# PHASE 16: LEAD MANAGEMENT
# ==========================================
# ==========================================
# PHASE 17: ACCOUNTING ROUTES (OWNER)
# ==========================================

# ==========================================
# PHASE 17: ACCOUNTING ROUTES (OWNER)
# ==========================================

@app.route('/owner/accounting')
@owner_required
def owner_accounting():
    """Financial overview for the owner."""
    # 1. Total Revenue
    total_payments = supabase_db.table('payments').select('final_amount').eq('status', 'completed').execute()
    total_revenue = sum(p['final_amount'] for p in total_payments.data) if total_payments.data else 0

    # 2. Monthly & Yearly Revenue
    now = datetime.utcnow()
    first_day_of_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    first_day_of_year = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)

    monthly_payments = supabase_db.table('payments').select('final_amount').eq('status', 'completed').gte('created_at', first_day_of_month.isoformat()).execute()
    monthly_revenue = sum(p['final_amount'] for p in monthly_payments.data) if monthly_payments.data else 0

    yearly_payments = supabase_db.table('payments').select('final_amount').eq('status', 'completed').gte('created_at', first_day_of_year.isoformat()).execute()
    yearly_revenue = sum(p['final_amount'] for p in yearly_payments.data) if yearly_payments.data else 0

    # 3. Recent Transactions (without join)
    recent_payments_raw = supabase_db.table('payments').select('*').eq('status', 'completed').order('created_at', desc=True).limit(10).execute().data
    
    # Enrich with client emails
    recent_payments = []
    if recent_payments_raw:
        for payment in recent_payments_raw:
            # Get client email from profiles
            profile_result = supabase_db.table('profiles').select('email').eq('auth_user_id', payment['client_id']).execute()
            client_email = profile_result.data[0]['email'] if profile_result.data else 'Unknown'
            recent_payments.append({
                **payment,
                'client_email': client_email
            })

    return render_template('owner_accounting.html', 
                         total_revenue=total_revenue,
                         monthly_revenue=monthly_revenue,
                         yearly_revenue=yearly_revenue,
                         recent_payments=recent_payments)

# ==========================================
# PHASE 18: SUPPORT TICKETS ROUTES
# ==========================================

# --- Client Routes ---

@app.route('/support')
@client_required
def client_support():
    """List client's support tickets."""
    user = get_current_user()
    tickets = supabase_db.table('support_tickets').select('*').eq('client_id', user.id).order('created_at', desc=True).execute().data
    return render_template('support.html', tickets=tickets)

@app.route('/support/create', methods=['POST'])
@client_required
def create_support_ticket():
    """Create a new support ticket."""
    user = get_current_user()
    subject = request.form.get('subject')
    description = request.form.get('description')
    priority = request.form.get('priority')

    try:
        result = supabase_db.table('support_tickets').insert({
            'client_id': user.id,
            'subject': subject,
            'description': description,
            'priority': priority,
            'status': 'open'
        }).execute()
        
        ticket_id = result.data[0]['id']
        
        # Add initial description as first message
        supabase_db.table('support_messages').insert({
            'ticket_id': ticket_id,
            'sender_id': user.id,
            'sender_role': 'client',
            'message': description
        }).execute()
        
        flash('Ticket created successfully!', 'success')
    except Exception as e:
        print(f"Ticket creation error: {e}")
        flash('Failed to create ticket.', 'danger')
        
    return redirect(url_for('client_support'))

@app.route('/support/<ticket_id>')
@client_required
def view_support_ticket(ticket_id):
    """View a specific ticket and its messages."""
    user = get_current_user()
    
    # Verify ownership
    ticket_result = supabase_db.table('support_tickets').select('*').eq('id', ticket_id).eq('client_id', user.id).execute()
    if not ticket_result.data:
        flash('Ticket not found.', 'danger')
        return redirect(url_for('client_support'))
        
    ticket = ticket_result.data[0]
    
    # Get messages
    messages = supabase_db.table('support_messages').select('*').eq('ticket_id', ticket_id).order('created_at').execute().data    
    return render_template('support_view.html', ticket=ticket, messages=messages, user_role='client')

@app.route('/support/<ticket_id>/message', methods=['POST'])
@client_required
def reply_to_ticket(ticket_id):
    """Client replies to a ticket."""
    user = get_current_user()
    message = request.form.get('message')
    
    if message:
        supabase_db.table('support_messages').insert({
            'ticket_id': ticket_id,
            'sender_id': user.id,
            'sender_role': 'client',
            'message': message
        }).execute()
        
        # Update ticket status back to open if it was resolved/waiting
        supabase_db.table('support_tickets').update({'status': 'open', 'updated_at': 'now()'}).eq('id', ticket_id).execute()
        
    return redirect(url_for('view_support_ticket', ticket_id=ticket_id))

# --- Owner Routes ---

@app.route('/owner/support')
@owner_required
def owner_support():
    """View all support tickets."""
    tickets_raw = supabase_db.table('support_tickets').select('*').order('created_at', desc=True).execute().data
    
    # Enrich with client emails
    tickets = []
    if tickets_raw:
        for ticket in tickets_raw:
            profile_result = supabase_db.table('profiles').select('email').eq('auth_user_id', ticket['client_id']).execute()
            client_email = profile_result.data[0]['email'] if profile_result.data else 'Unknown'
            tickets.append({
                **ticket,
                'client_email': client_email
            })
    
    return render_template('owner_support.html', tickets=tickets)

@app.route('/owner/support/<ticket_id>')
@owner_required
def owner_view_ticket(ticket_id):
    """Owner views a specific ticket."""
    ticket_result = supabase_db.table('support_tickets').select('*').eq('id', ticket_id).execute()
    if not ticket_result.data:
        flash('Ticket not found.', 'danger')
        return redirect(url_for('owner_support'))
        
    ticket = ticket_result.data[0]
    
    # Get client email
    profile_result = supabase_db.table('profiles').select('email').eq('auth_user_id', ticket['client_id']).execute()
    ticket['client_email'] = profile_result.data[0]['email'] if profile_result.data else 'Unknown'
    
    messages = supabase_db.table('support_messages').select('*').eq('ticket_id', ticket_id).order('created_at').execute().data


    return render_template('support_view.html', ticket=ticket, messages=messages, user_role='owner')

@app.route('/owner/support/<ticket_id>/message', methods=['POST'])
@owner_required
def owner_reply_to_ticket(ticket_id):
    """Owner replies to a ticket."""
    user = get_current_user()
    message = request.form.get('message')
    new_status = request.form.get('status')
    
    if message:
        supabase_db.table('support_messages').insert({
            'ticket_id': ticket_id,
            'sender_id': user.id,
            'sender_role': 'owner',
            'message': message
        }).execute()
        
    update_data = {'updated_at': 'now()'}
    if new_status:
        update_data['status'] = new_status
        
    supabase_db.table('support_tickets').update(update_data).eq('id', ticket_id).execute()
    
    return redirect(url_for('owner_view_ticket', ticket_id=ticket_id))
# ==========================================
# PHASE 17: ACCOUNTING ROUTES (OWNER)
# ==========================================



# ==========================================
# PHASE 19: OWNER AI MANAGEMENT
# ==========================================

@app.route('/owner/ai', methods=['GET', 'POST'])
@owner_required
def owner_ai_settings():
    """View and update global AI settings."""
    user = get_current_user()
    
    if request.method == 'POST':
        master_prompt = request.form.get('master_review_prompt')
        min_pool_size = request.form.get('min_pool_size')
        refill_quantity = request.form.get('refill_quantity')
        
        try:
            # Update settings in DB
            if master_prompt:
                supabase_db.table('ai_settings').update({'setting_value': master_prompt, 'updated_at': 'now()'}).eq('setting_key', 'master_review_prompt').execute()
            if min_pool_size:
                supabase_db.table('ai_settings').update({'setting_value': min_pool_size, 'updated_at': 'now()'}).eq('setting_key', 'min_pool_size').execute()
            if refill_quantity:
                supabase_db.table('ai_settings').update({'setting_value': refill_quantity, 'updated_at': 'now()'}).eq('setting_key', 'refill_quantity').execute()
            
            # Log the change
            log_audit_event(
                user.id, 
                'updated_ai_settings', 
                'ai_settings', 
                metadata={
                    'min_pool_size': min_pool_size, 
                    'refill_quantity': refill_quantity
                }
            )
            
            flash('AI Settings updated successfully!', 'success')
        except Exception as e:
            print(f"AI Settings update error: {e}")
            flash('Failed to update AI settings.', 'danger')
            
        return redirect(url_for('owner_ai_settings'))

    # GET request: Fetch current settings
    settings_raw = supabase_db.table('ai_settings').select('*').in_('setting_key', ['master_review_prompt', 'min_pool_size', 'refill_quantity']).execute().data
    
    # Convert list to dictionary for easy template access
    settings = {s['setting_key']: s['setting_value'] for s in settings_raw}
    
    return render_template('owner_ai.html', settings=settings)





@app.route('/owner/clients/<client_id>/block', methods=['POST'])
@owner_required
def block_client(client_id):
    """Block or activate a client account."""
    user = get_current_user()
    
    # Get current status
    profile_result = supabase_db.table('profiles').select('status').eq('auth_user_id', client_id).execute()
    
    if not profile_result.data:
        flash('Client not found.', 'danger')
        return redirect(url_for('owner_clients'))
    
    current_status = profile_result.data[0]['status']
    
    # Toggle status
    new_status = 'blocked' if current_status == 'active' else 'active'
    
    try:
        supabase_db.table('profiles').update({
            'status': new_status,
            'updated_at': 'now()'
        }).eq('auth_user_id', client_id).execute()
        
        # Log the action
        log_audit_event(
            user.id,
            f'{"blocked" if new_status == "blocked" else "activated"}_client',
            'profile',
            client_id,
            {'email': profile_result.data[0].get('email', 'unknown')}
        )
        
        flash(f'Client has been {new_status}.', 'success')
    except Exception as e:
        print(f"Block client error: {e}")
        flash('Failed to update client status.', 'danger')
    
    return redirect(url_for('owner_clients'))

@app.route('/owner/clients/<client_id>/edit')
@owner_required
def edit_client(client_id):
    """View and edit client details."""
    # Get client profile
    profile_result = supabase_db.table('profiles').select('*').eq('auth_user_id', client_id).execute()
    
    if not profile_result.data:
        flash('Client not found.', 'danger')
        return redirect(url_for('owner_clients'))
    
    client = profile_result.data[0]
    
    # Get client's business
    business_result = supabase_db.table('businesses').select('*').eq('owner_user_id', client_id).execute()
    business = business_result.data[0] if business_result.data else None
    
    # Get client's subscriptions
    subscriptions = supabase_db.table('subscriptions').select('*').eq('client_id', client_id).order('created_at', desc=True).execute().data
    
    # Fetch industries and business types for the form
    industries = supabase_db.table('industries').select('*').eq('status', 'active').execute().data
    business_types = supabase_db.table('business_types').select('*').eq('status', 'active').execute().data
    
    return render_template('owner_edit_client.html', 
                         client=client, 
                         business=business, 
                         subscriptions=subscriptions,
                         industries=industries,
                         business_types=business_types)



@app.route('/owner/clients/<client_id>/update', methods=['POST'])
@owner_required
def update_client(client_id):
    """Update client profile."""
    user = get_current_user()
    
    new_status = request.form.get('status')
    new_role = request.form.get('role')
    
    try:
        update_data = {'updated_at': 'now()'}
        
        if new_status:
            update_data['status'] = new_status
        if new_role:
            update_data['role'] = new_role
        
        supabase_db.table('profiles').update(update_data).eq('auth_user_id', client_id).execute()
        
        # Log the action
        log_audit_event(
            user.id,
            'updated_client',
            'profile',
            client_id,
            {'status': new_status, 'role': new_role}
        )
        
        flash('Client updated successfully!', 'success')
    except Exception as e:
        print(f"Update client error: {e}")
        flash('Failed to update client.', 'danger')
    
    return redirect(url_for('edit_client', client_id=client_id))


@app.route('/owner/clients/<client_id>/update-business', methods=['POST'])
@owner_required
def update_client_business(client_id):
    """Update client's business information."""
    user = get_current_user()
    
    # Get form data
    business_name = request.form.get('business_name')
    location = request.form.get('location')
    industry_id = request.form.get('industry_id') or None
    business_type_id = request.form.get('business_type_id')
    custom_business_type = request.form.get('custom_business_type') or None
    google_review_url = request.form.get('google_review_url') or None
    keywords = request.form.get('keywords') or None
    description = request.form.get('description') or None
    
    # Validation
    if not business_name:
        flash('Business name is required.', 'danger')
        return redirect(url_for('edit_client', client_id=client_id))
    
    # If business type is "other", require custom text
    if business_type_id == 'other' and not custom_business_type:
        flash('Please specify your business type.', 'danger')
        return redirect(url_for('edit_client', client_id=client_id))
    
    try:
        # Check if business exists
        existing_business = supabase_db.table('businesses').select('id').eq('owner_user_id', client_id).execute()
        
        update_data = {
            'business_name': business_name,
            'location': location,
            'industry_id': industry_id if industry_id and industry_id != 'other' else None,
            'business_type_id': business_type_id if business_type_id and business_type_id != 'other' else None,
            'custom_business_type': custom_business_type if business_type_id == 'other' else None,
            'google_review_url': google_review_url,
            'keywords': keywords,
            'description': description,
            'updated_at': 'now()'
        }
        
        if existing_business.data:
            # Update existing business
            supabase_db.table('businesses').update(update_data).eq('owner_user_id', client_id).execute()
        else:
            # Create new business
            update_data['owner_user_id'] = client_id
            update_data['status'] = 'active'
            supabase_db.table('businesses').insert(update_data).execute()
        
        # Log the action
        log_audit_event(
            user.id,
            'updated_client_business',
            'business',
            client_id,
            {'business_name': business_name}
        )
        
        flash('Business information updated successfully!', 'success')
    except Exception as e:
        print(f"Update client business error: {e}")
        flash('Failed to update business information.', 'danger')
    
    return redirect(url_for('edit_client', client_id=client_id))

@app.route('/owner/clients/<client_id>/send-alert', methods=['POST'])
@owner_required
def send_client_alert(client_id):
    """Send a warning/notification to a client."""
    user = get_current_user()
    message = request.form.get('message')
    alert_type = request.form.get('alert_type', 'warning')
    
    if message:
        # DELETE all old alerts for this client first (keep only latest)
        supabase_db.table('client_alerts').delete().eq('client_id', client_id).execute()
        
        # Insert the new alert
        supabase_db.table('client_alerts').insert({
            'client_id': client_id,
            'message': message,
            'alert_type': alert_type
        }).execute()
        flash('Alert sent to client.', 'success')
    return redirect(url_for('owner_clients'))

@app.route('/owner/clients/<client_id>/toggle-restrict', methods=['POST'])
@owner_required
def toggle_client_restriction(client_id):
    """Restrict or Unrestrict a client."""
    user = get_current_user()
    
    # Get current status
    profile = supabase_db.table('profiles').select('is_restricted').eq('auth_user_id', client_id).single().execute().data
    
    new_status = not profile['is_restricted']
    reason = request.form.get('reason', 'High usage detected') if new_status else None
    
    supabase_db.table('profiles').update({
        'is_restricted': new_status,
        'restriction_reason': reason
    }).eq('auth_user_id', client_id).execute()
    
    # DELETE all old alerts first
    supabase_db.table('client_alerts').delete().eq('client_id', client_id).execute()
    
    # Send new alert based on action
    if new_status:
        supabase_db.table('client_alerts').insert({
            'client_id': client_id,
            'message': f'Your account has been temporarily restricted. Reason: {reason}. Please contact support.',
            'alert_type': 'urgent'
        }).execute()
    else:
        supabase_db.table('client_alerts').insert({
            'client_id': client_id,
            'message': 'Your account restriction has been lifted. You can resume normal operations.',
            'alert_type': 'info'
        }).execute()

    flash(f'Client {"restricted" if new_status else "unrestricted"}.', 'success')
    return redirect(url_for('owner_clients'))


import os






# ==========================================
# CONTACT US ROUTES
# ==========================================

@app.route('/contact', methods=['GET', 'POST'])
def contact_page():
    """Public contact form page."""
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone', '')
        subject = request.form.get('subject', 'General Inquiry')
        message = request.form.get('message')
        
        if not name or not email or not message:
            flash('Please fill in all required fields.', 'danger')
            return redirect(url_for('contact_page'))
        
        try:
            supabase_db.table('contact_messages').insert({
                'name': name,
                'email': email,
                'phone': phone,
                'subject': subject,
                'message': message,
                'status': 'new',
                'is_read': False
            }).execute()
            
            flash('Thank you! Your message has been sent successfully. We will get back to you soon.', 'success')
            return redirect(url_for('contact_page'))
            
        except Exception as e:
            print(f"Contact form error: {e}")
            flash('Failed to send message. Please try again.', 'danger')
            return redirect(url_for('contact_page'))
    
    return render_template('contact.html')

@app.route('/owner/contact-messages')
@owner_required
def owner_contact_messages():
    """View all contact messages in owner panel."""
    # Get messages
    messages = supabase_db.table('contact_messages').select('*').order('created_at', desc=True).execute().data
    
    # Count unread
    unread_count = len([m for m in messages if not m.get('is_read')])
    
    return render_template('owner_contact_messages.html', 
                         messages=messages, 
                         unread_count=unread_count)

@app.route('/owner/contact-messages/<message_id>/update-status', methods=['POST'])
@owner_required
def update_contact_message_status(message_id):
    """Update message status (read/replied/archived)."""
    new_status = request.form.get('status')
    
    try:
        supabase_db.table('contact_messages').update({
            'status': new_status,
            'is_read': True if new_status != 'new' else False,
            'updated_at': 'now()'
        }).eq('id', message_id).execute()
        
        flash('Message status updated.', 'success')
    except Exception as e:
        print(f"Update status error: {e}")
        flash('Failed to update status.', 'danger')
    
    return redirect(url_for('owner_contact_messages'))







# ==========================================
# PUBLIC PAGES ROUTES
# ==========================================

@app.route('/about')
def about_page():
    """About page."""
    return render_template('about.html')

@app.route('/privacy')
def privacy_page():
    """Privacy Policy page."""
    return render_template('privacy.html')

@app.route('/terms')
def terms_page():
    """Terms of Service page."""
    return render_template('terms.html')

@app.route('/refund')
def refund_page():
    """Refund Policy page."""
    return render_template('refund.html')




@app.route('/tutorial')
def tutorial_page():
    """Tutorial/Setup guide page."""
    return render_template('tutorial.html')





if __name__ == '__main__':
    # Railway provides a PORT environment variable. 
    # We use that, or default to 5000 for local development.
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)