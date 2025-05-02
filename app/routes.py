from flask import render_template, flash, redirect, url_for, request, abort, session, current_app, Blueprint
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.utils import secure_filename
from urllib.parse import urlparse
from app import db, oauth
from app.forms import *
from app.models import *
from app.data import *
from datetime import datetime
from sqlalchemy import func, or_, case, desc, distinct
from authlib.integrations.flask_client import OAuth, OAuthError
import os
import secrets
import uuid
from flask_wtf.csrf import generate_csrf





bp = Blueprint('main', __name__)



@bp.context_processor
def inject_csrf_token():
    return dict(csrf_token=generate_csrf)

# Configure Google OAuth
CONF_URL = 'https://accounts.google.com/.well-known/openid-configuration'
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url=CONF_URL,
    client_kwargs={
        'scope': 'openid email profile' # Request basic user info
    }
)


# --- Authentication Routes ---
@bp.route('/login/google')
def google_login():
    """
    Initiates the Google OAuth login flow.
    """
    nonce = uuid.uuid4().hex
    session['oauth_nonce'] = nonce # Store nonce in session BEFORE redirect

    redirect_uri = url_for('main.authorize', _external=True)
    current_app.logger.info(f"Redirect URI for Google: {redirect_uri}")
    current_app.logger.info(f"Generated Nonce: {nonce}")

    # *** FIX 1: Pass the nonce to the authorization request ***
    return oauth.google.authorize_redirect(redirect_uri, nonce=nonce)


@bp.route('/authorize')
def authorize():
    try:
        # 1) Exchange code for token dictionary
        # This typically contains {'access_token': '...', 'id_token': '...', ...}
        token_response = oauth.google.authorize_access_token()
        current_app.logger.debug(f"Received token response: {token_response}") # Be careful logging tokens in production

        # *** Add Check: Ensure id_token exists ***
        if 'id_token' not in token_response:
            current_app.logger.error("ID token not found in Google response.")
            flash('Authentication failed: ID token missing.', 'danger')
            return redirect(url_for('main.login')) # Or your login route name

        # 2) Pull the original nonce back out of session
        nonce = session.pop('oauth_nonce', None)
        if not nonce:
            current_app.logger.error("Nonce missing from session during callback.")
            flash('Authentication failed: Session state lost.', 'danger')
            return redirect(url_for('main.login')) # Or your login route name
        current_app.logger.info(f"Retrieved Nonce from session: {nonce}")

        # 3) Parse the ID token, supplying the nonce and the ID token *string*
        # *** FIX 2: Pass the actual id_token string from the response ***
        userinfo = oauth.google.parse_id_token(token_response, nonce=nonce)
        # Alternatively, using userinfo endpoint (requires access token, less secure for auth):
        # userinfo = oauth.google.get('userinfo', token=token_response).json()

        current_app.logger.info(f"Successfully parsed ID token. User info: {userinfo}")

        # 4) Extract user details (use .get for safety)
        email = userinfo.get('email')
        first_name = userinfo.get('given_name')
        last_name = userinfo.get('family_name')
        # You might also want 'sub' (Google's unique ID)
        google_sub = userinfo.get('sub')

        if not email:
            current_app.logger.error("Email not found in userinfo.")
            flash('Authentication failed: Email not provided by Google.', 'danger')
            return redirect(url_for('main.login')) # Or your login route name

        # Store details needed later (optional, depends on your flow)
        session['google_auth_email'] = email # Use distinct session keys
        session['google_auth_first_name'] = first_name
        session['google_auth_last_name'] = last_name
        session['google_auth_sub'] = google_sub # Good practice to store the unique ID


        # 5) Check if user exists by email (or better, by google_sub if available)
        # It's generally more reliable to link accounts via the 'sub' claim
        user = User.query.filter_by(email=email).first()
        if not user:
            return redirect(url_for('main.complete_form'))
        
        else:
            login_user(user) # Assuming your User model is compatible with Flask-Login
            flash(f'Welcome back, {user.first_name}!', 'success')
            current_app.logger.info(f"Existing user logged in: {user.email} (ID: {user.id})")
            # Redirect to a logged-in area, maybe a 'next' URL if stored
            next_page = session.pop('next_url', None) # Example for redirecting after login
            return redirect(next_page or url_for('main.home')) # Or your main app page

    except OAuthError as oe:
        current_app.logger.error(f"OAuth error during authorization: {oe}", exc_info=True)
        flash(f'External authentication failed: {oe.description or oe.error}', 'danger')
        return redirect(url_for('main.login')) # Or your login route name

    except Exception as e:
        current_app.logger.error(f"Unexpected error during authorization: {e}", exc_info=True) # Log traceback
        flash('An unexpected error occurred during authorization.', 'danger')
        return redirect(url_for('main.login')) # Or your login route name


@bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.role == 'client':
            return redirect(url_for('main.dashboard_client'))
        elif current_user.role == 'driver':
            return redirect(url_for('main.dashboard_driver'))
        else:
            return redirect(url_for('main.home'))  # Fallback for other roles if added

    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid email or password', 'danger')
            return redirect(url_for('main.login'))

        login_user(user, remember=form.remember_me.data)
        flash(f'Welcome back, {user.first_name}!', 'success')

        # Redirect logic
        if user.role_id == Role.query.filter_by(name='Client').first().id:
            return redirect(url_for('main.dashboard_client'))
        elif user.role_id == Role.query.filter_by(name='Driver').first().id:
            return redirect(url_for('main.dashboard_driver'))
        else:
            # Redirect to intended page if available, otherwise index
            next_page = request.args.get('next')
            if not next_page or urlparse(next_page).netloc != '':
                next_page = url_for('main.home')
            return redirect(next_page)

    return render_template('auth/login.html', title='Sign In', heading='Sign In', form=form)


@bp.route('/complete-form', methods=['GET', 'POST'])
def complete_form():
    form = CompleteForm()
    form.first_name.data = session.get('google_auth_first_name')
    form.last_name.data = session.get('google_auth_last_name')
    form.email.data = session.get('google_auth_email')
    if form.validate_on_submit():
        fname = form.first_name.data
        lname = form.last_name.data
        email = form.email.data
        role = form.role.data
        if not User.query.filter_by(email=email).first():
            try:
                new_user = User(
                    first_name=fname,
                    last_name=lname,
                    email=email,
                    role=role
                )
                db.session.add(new_user)
                db.session.commit()
                flash('User created!', 'success')
                user_to_log = User.query.filter_by(email=email).first()
                if user_to_log:
                    login_user(user_to_log)
                    flash('Login successful', 'success')
                    return redirect(url_for('main.login'))
            except Exception as e:
                flash(f"Error: {e}", 'danger')
                return redirect(url_for('main.login'))
        else:
            flash('User exists!', 'info')
    return render_template('auth/register.html', title='Complete Profile', heading='User Type', form=form)


@bp.route('/logout')
def logout():
    logout_user()
    session.pop('user', None) # Remove user info from session
    flash('You have been logged out.', 'info')
    return redirect(url_for('main.home'))



@bp.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('main.home'))
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            email=form.email.data,
            role=form.role.data
        )
        user.set_password(form.password.data)
        # TODO: Capture GPS here in future version
        db.session.add(user)
        db.session.commit()
        flash('Congratulations, you are now a registered user!')
        # Log in the user immediately after registration
        login_user(user)
        if user.role == 'client':
            return redirect(url_for('main.dashboard_client'))
        elif user.role == 'driver':
            return redirect(url_for('main.dashboard_driver'))
        else:
            return redirect(url_for('main.home'))
    return render_template('auth/register.html', title='Register', heading='Sign Up', form=form)



@bp.route('/users/create')
def create_users():
    for user in user_data:
        role = Role.query.filter_by(name=user['role']).first()
        if role:
            try:
                role_id = role.id
                if not User.query.filter_by(email=user['email'], phone=user['phone_number']).first():
                    db.session.add(
                        User(
                            first_name=user['first_name'],
                            last_name=user['last_name'],
                            phone=user['phone_number'],
                            password_hash=generate_password_hash(user['password'], method='scrypt', salt_length=8),
                            email=user['email'],
                            role_id=role_id
                        )
                    )
            except Exception as e:
                msg = flash(f"Error: {e}", 'danger')
                return redirect(request.referrer)
    db.session.commit()
    flash('Users created!', 'success')
    return redirect(request.referrer)


@bp.route('/user/create-admin', methods=['GET','POST'])
def create_admin():
    form = AdminUserForm()
    admin_role = "Admin"
    if form.validate_on_submit():
        if not Role.query.filter_by(name=admin_role).first():
            db.session.add(Role(name=admin_role))
            db.session.commit()
        admin = User(
            email      = form.email.data,
            first_name = form.first_name.data,
            last_name  = form.last_name.data,
            is_admin   = True,
            is_manager = True,
            phone = form.phone.data,
            password_hash = generate_password_hash(form.password.data, method='scrypt', salt_length=8),
            role_id=Role.query.filter_by(name=admin_role).first().id
        )
        db.session.add(admin)
        db.session.commit()   # ← don’t forget this!
        flash('Admin user created', 'success')
        return redirect(url_for('main.home'))
    return render_template('auth/register.html', title='Register', heading='Create Admin User', form=form)


@bp.route('/user/edit/<int:user_id>', methods=['GET', 'POST'])
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user) 
    if form.validate_on_submit():
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.email = form.email.data
        user.phone = form.phone.data
        user.role_id = form.role.data.id
        db.session.commit()
        return redirect(url_for('main.home'))
    return render_template('auth/register.html', title='Edit User', heading='Edit User', form=form)
        

@bp.route('/user/edit-admin/<int:user_id>', methods=['GET', 'POST'])
def edit_admin_user(user_id):
    user = User.query.get_or_404(user_id)
    form = EditAdminUserForm(obj=user) 
    if form.validate_on_submit():
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.email = form.email.data
        user.phone = form.phone.data
        db.session.commit()
        return redirect(url_for('main.admin'))
    return render_template('auth/register.html', title='Edit User', heading='Edit Admin User', form=form)
      

# --- Core Application Routes ---

@bp.route('/')
def home():
    if User.query.first() is None:
        flash(f'First time launch. Create Admin User.', 'info')
        return redirect(url_for('main.create_admin'))
    moment = datetime.now().year
    return render_template('index.html', title='Home', moment=moment)


@bp.route('/admin-panel')
def admin():
    jobs = Job.query.order_by(desc(Job.id)).all()
    users = User.query.all()
    return render_template('admin_panel.html', title='Admin Panel', jobs=jobs, users=users)


@bp.route('/settings/create-roles')
def create_roles():
    for role in role_list:
        if not Role.query.filter_by(name=role).first():
            db.session.add(
                Role(name=role)
            )
    db.session.commit()
    flash('Roles created!', 'success')
    return redirect(request.referrer)


@bp.route('/settings/create-statuses')
def create_statuses():
    for status in status_list:
        if not Status.query.filter_by(status=status).first():
            db.session.add(
                Status(status=status)
            )
    db.session.commit()
    flash('Statuses created!', 'success')
    return redirect(request.referrer)


@bp.route('/dashboard/client')
@login_required
def dashboard_client():
    if current_user.role.name != 'Client':
        flash('Access denied. Clients only.')
        return redirect(url_for('main.home'))  # Or driver dashboard if applicable

    # Fetch jobs posted by the current client
    jobs = Job.query.filter_by(client_id=current_user.id).order_by(Job.created_at.desc()).all()
    return render_template('dashboard_client.html', title='Client Dashboard', jobs=jobs)


@bp.route('/dashboard/driver')
@login_required
def dashboard_driver():
    if current_user.role.name != 'Driver':
        flash('Access denied. Drivers only.')
        return redirect(url_for('main.home'))

    # Fetch jobs that are 'posted' and not yet accepted
    available_jobs = Job.query.filter_by(status_id=Status.query.filter_by(status='Posted').first().id, driver_id=None).order_by(Job.created_at.desc()).all()
    accepted_jobs = Job.query.filter_by(driver_id=current_user.id, status_id=Status.query.filter_by(status='Accepted').first().id).order_by(
        Job.accepted_at.desc()).all()

    return render_template('dashboard_driver.html', title='Driver Dashboard',
                           available_jobs=available_jobs, accepted_jobs=accepted_jobs)


@bp.route('/jobs/post', methods=['GET', 'POST'])
@login_required
def post_job():
    if current_user.role != 'client':
        flash('Only clients can post jobs.', 'warning')
        return redirect(url_for('main.home'))

    form = PostJobForm()
    if form.validate_on_submit():
        job = Job(
            client_id    = current_user.id,
            description  = form.description.data,
            location_text= form.location_text.data,
            price        = form.price.data,
            status       = 'posted'
        )

        # 1) Handle image upload
        image_file = form.image.data
        if image_file:
            # secure the original filename
            orig = secure_filename(image_file.filename)
            name, ext = os.path.splitext(orig)

            # generate a 16-char random hex string
            rand = secrets.token_hex(8)

            # build the new filename
            new_filename = f"{name}_{rand}{ext}"

            # ensure upload folder exists
            upload_folder = current_app.config['UPLOAD_FOLDER']
            os.makedirs(upload_folder, exist_ok=True)

            # save to disk
            save_path = os.path.join(upload_folder, new_filename)
            image_file.save(save_path)

            # record it on the job
            job.image = new_filename

        # 2) Persist job
        db.session.add(job)
        db.session.commit()

        flash('Your job has been posted successfully!', 'success')
        return redirect(url_for('main.dashboard_client'))

    return render_template(
        'jobs/post_job.html',
        title='Post New Job',
        form=form
    )


@bp.route('/jobs/<int:job_id>/accept', methods=['POST'])  # Use POST for actions
@login_required
def accept_job(job_id):
    if current_user.role != 'driver':
        flash('Only drivers can accept jobs.')
        abort(403)  # Forbidden access

    job = db.session.get(Job, job_id)  # Use db.session.get
    if job is None:
        flash('Job not found.')
        abort(404)  # Not found

    if job.status != 'posted' or job.driver_id is not None:
        flash('Job is no longer available.')
        return redirect(url_for('main.dashboard_driver'))

    # Accept the job
    job.driver_id = current_user.id
    job.status = 'accepted'
    job.accepted_at = datetime.utcnow()
    db.session.commit()

    flash(f'You have accepted job #{job.id}!')
    # TODO: Add notification logic here later
    return redirect(url_for('main.dashboard_driver'))


# Add a simple job detail view (optional but helpful)
@bp.route('/jobs/<int:job_id>')
@login_required
def view_job(job_id):
    job = db.session.get(Job, job_id)
    if job is None:
        abort(404)

    # Basic authorization check: only involved parties or admin (later) can see
    if job.client_id != current_user.id and job.driver_id != current_user.id:
        # Allow drivers to see 'posted' jobs they haven't accepted yet
        if not (current_user.role == 'driver' and job.status == 'posted'):
            flash('You do not have permission to view this job.')
            abort(403)
    if job.image:
        image_url = url_for('static', filename=f'uploads/{job.image}')
        print(image_url)
    else:
        image_url = url_for('static', filename='images/dustbin_silhouette.png')
    return render_template('jobs/job_details.html', title=f'Job #{job.id}', job=job, image_url=image_url)  # You'll need to create this template



#create_roles()



