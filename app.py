"""
Flask-based website gateway application
-------------------------------------

This application provides a simple portal where users can save links to external
websites and display them as cards.  Each card shows an image (if provided) and
the name of the website.  Clicking a card opens the target site in a new tab.

Features
========

* User authentication with username and password.  Passwords are hashed using
  Werkzeug's built‑in helpers and never stored in plain text.
* Two roles: **admin** and **user**.  Admins can create other users and add
  links for themselves or globally.  Users can only add and manage their own
  links.
* Modern, mobile‑friendly UI built with HTML, CSS and a pinch of JavaScript.
  The colour scheme follows a dark theme with red accents.
* Pages:
  - **Home**: display saved websites in a 2×3 grid.  Global links appear first
    followed by the current user's personal links.
  - **Add Website**: form to add a new link and an interface to remove
    existing ones.  Admins can choose to create a personal or global link.
  - **Account**: change your username or password.
  - **Users** (admin only): add new users, edit user roles, remove users and
    view simple activity statistics (last login, last activity and number of
    saved websites).

Usage
-----

To initialise the database, run this module directly with the ``initdb``
argument:

.. code-block:: bash

   python app.py initdb

This will create the SQLite database at ``database.db`` in the same
directory.  Afterwards, you can start the development server:

.. code-block:: bash

   FLASK_APP=app.py flask run

On the first run you should log in as the admin.  Since there are no users
initially, you'll be prompted to create an admin account.

The application is intended as a starting point and does not include all
possible security hardening measures.  You should not use it as‑is in a
production environment without further review.
"""

import os
import sqlite3
from datetime import datetime
from functools import wraps

from flask import (
    Flask, render_template, request, redirect, url_for, session, g, flash
)

# Import secure_filename to safely handle uploaded filenames
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.getenv("SECRET_KEY", "change_me"),
    DATABASE=os.path.join(os.path.dirname(os.path.abspath(__file__)), "database.db"),
)

# Configure upload folder for storing uploaded images.  Images will be saved
# under the "static/uploads" directory within this project.  If the folder
# does not exist it will be created at runtime.
app.config['UPLOAD_FOLDER'] = os.path.join(app.static_folder, 'uploads')

# Allowed image extensions for uploads.  Only files with these extensions
# will be accepted to prevent arbitrary file uploads.
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

# Ensure the upload folder exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)


def allowed_file(filename: str) -> bool:
    """Check if a filename has an allowed image extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def get_db() -> sqlite3.Connection:
    """Return a connection to the SQLite database.

    The connection is stored on Flask's ``g`` object so that it is reused
    throughout the request lifecycle.
    """
    if 'db' not in g:
        db = sqlite3.connect(app.config['DATABASE'])
        db.row_factory = sqlite3.Row
        g.db = db
    return g.db


@app.teardown_appcontext
def close_db(exception: Exception | None) -> None:
    """Close the database connection at the end of the request."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db() -> None:
    """Initialise the database by executing the schema script."""
    db = get_db()
    schema_path = os.path.join(os.path.dirname(__file__), 'schema.sql')
    with open(schema_path, 'r', encoding='utf-8') as f:
        db.executescript(f.read())
    db.commit()


def query_db(query: str, args: tuple = (), one: bool = False):
    """Utility helper to execute a query and return results.

    :param query: SQL statement with placeholders
    :param args: values for the placeholders
    :param one: whether to return just one record
    :return: list of rows or single row
    """
    cur = get_db().execute(query, args)
    rv = cur.fetchall()
    cur.close()
    return (rv[0] if rv else None) if one else rv


def execute_db(query: str, args: tuple = ()) -> None:
    """Execute a write query (INSERT/UPDATE/DELETE)."""
    db = get_db()
    db.execute(query, args)
    db.commit()


def login_required(view):
    """Decorator to ensure a user is logged in before accessing a route."""
    @wraps(view)
    def wrapped_view(**kwargs):
        # Only proceed if a valid user is logged in.  If the session does not
        # contain a user_id or the user referenced in the session no longer
        # exists (e.g., was deleted), redirect to the login page.  Without
        # this check, accessing attributes on a None current_user would
        # raise a TypeError.
        if 'user_id' not in session:
            return redirect(url_for('login'))
        user = current_user()
        if user is None:
            # clear any stale session and redirect to login
            session.pop('user_id', None)
            return redirect(url_for('login'))
        return view(**kwargs)
    return wrapped_view


def admin_required(view):
    """Decorator to ensure the current user is an admin."""
    @wraps(view)
    def wrapped_view(**kwargs):
        user = current_user()
        if not user or not user['is_admin']:
            flash('You do not have permission to access that page.', 'error')
            return redirect(url_for('home'))
        return view(**kwargs)
    return wrapped_view


def current_user():
    """Return the currently logged in user row or None."""
    if 'user_id' not in session:
        return None
    user = query_db('SELECT * FROM users WHERE id = ?', (session['user_id'],), one=True)
    return user


@app.before_request
def update_last_activity():
    """Update user's last_activity timestamp before each request."""
    if 'user_id' in session:
        now = datetime.utcnow().isoformat(timespec='seconds')
        execute_db('UPDATE users SET last_activity = ? WHERE id = ?', (now, session['user_id']))


@app.route('/', methods=['GET', 'POST'])
def login():
    """Login page.  If no users exist, prompt to create an admin account."""
    # redirect to home if already logged in
    if 'user_id' in session:
        return redirect(url_for('home'))

    db = get_db()
    # If there are no users, force creation of an admin account
    user_count = query_db('SELECT COUNT(*) as count FROM users', one=True)['count']
    if user_count == 0:
        flash('No users found.  Please create an admin account.', 'info')
        return redirect(url_for('register_admin'))

    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        user = query_db('SELECT * FROM users WHERE username = ?', (username,), one=True)
        if user and check_password_hash(user['password_hash'], password):
            # correct credentials
            session.clear()
            session['user_id'] = user['id']
            now = datetime.utcnow().isoformat(timespec='seconds')
            execute_db('UPDATE users SET last_login = ? WHERE id = ?', (now, user['id']))
            return redirect(url_for('home'))
        flash('Invalid username or password', 'error')
    return render_template('login.html', title='Login')


@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    """Initial registration view for the first admin.

    This route is only accessible when there are no users in the database.  It
    allows the creation of the first account which will automatically be
    granted admin privileges.
    """
    # If there are already users, disallow access
    user_count = query_db('SELECT COUNT(*) as count FROM users', one=True)['count']
    if user_count > 0:
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']
        confirm = request.form['confirm']
        if not username or not password:
            flash('Username and password are required', 'error')
        elif password != confirm:
            flash('Passwords do not match', 'error')
        else:
            password_hash = generate_password_hash(password)
            execute_db(
                'INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, 1, ?)',
                (username, password_hash, datetime.utcnow().isoformat(timespec='seconds'))
            )
            flash('Admin account created. Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('register_admin.html', title='Create Admin')


@app.route('/logout')
def logout():
    """Log out the current user."""
    session.clear()
    return redirect(url_for('login'))


@app.route('/home')
@login_required
def home():
    """Main page showing website cards in a 2×3 grid."""
    user = current_user()
    # load global websites (user_id IS NULL) first then user-specific
    global_sites = query_db('SELECT * FROM websites WHERE user_id IS NULL ORDER BY created_at DESC')
    personal_sites = query_db('SELECT * FROM websites WHERE user_id = ? ORDER BY created_at DESC', (user['id'],))
    websites = global_sites + personal_sites
    return render_template('home.html', title='Home', websites=websites, default_image=url_for('static', filename='no-image.png'))


@app.route('/add', methods=['GET', 'POST'])
@login_required
def add_website():
    """Page to add a new website and delete existing ones."""
    user = current_user()
    if request.method == 'POST':
        # handle deletion
        if 'delete_id' in request.form:
            site_id = request.form.get('delete_id')
            # ensure user is allowed to delete: admin can delete any, user can delete own
            site = query_db('SELECT * FROM websites WHERE id = ?', (site_id,), one=True)
            if site:
                if user['is_admin'] or site['user_id'] == user['id']:
                    execute_db('DELETE FROM websites WHERE id = ?', (site_id,))
                    flash('Website removed.', 'success')
                else:
                    flash('You do not have permission to remove that site.', 'error')
            return redirect(url_for('add_website'))
        # handle addition
        name = request.form['name'].strip()
        url = request.form['url'].strip()
        # The optional image is now a file upload.  Retrieve the file from
        # request.files.  If a file is provided and it has an allowed
        # extension, save it to the uploads folder and build a URL to it.
        uploaded_file = request.files.get('image')
        image_url = None
        if uploaded_file and uploaded_file.filename:
            if allowed_file(uploaded_file.filename):
                # Create a secure filename and prepend a timestamp to avoid
                # collisions.  The timestamp format ensures uniqueness down to
                # microseconds.
                timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S%f')
                filename = secure_filename(uploaded_file.filename)
                unique_name = f"{timestamp}_{filename}"
                # Save the file into the configured upload folder
                save_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_name)
                uploaded_file.save(save_path)
                # Construct the URL for the saved image relative to the static folder.
                # We avoid using url_for here to reduce dependency on request context.
                image_url = f"/static/uploads/{unique_name}"
            else:
                flash('Invalid image file type. Allowed types: png, jpg, jpeg, gif, webp.', 'error')
                return redirect(url_for('add_website'))
        scope = request.form.get('scope', 'personal')  # only used for admin
        if not name or not url:
            flash('Name and URL are required.', 'error')
        else:
            # insert; user_id null if admin and scope=global
            target_user_id = None if (user['is_admin'] and scope == 'global') else user['id']
            execute_db(
                'INSERT INTO websites (user_id, name, url, image_url, created_at) VALUES (?, ?, ?, ?, ?)',
                (target_user_id, name, url, image_url, datetime.utcnow().isoformat(timespec='seconds'))
            )
            flash('Website added.', 'success')
            return redirect(url_for('add_website'))
    # GET: show form
    # fetch user websites; admin sees all
    if user['is_admin']:
        sites = query_db('SELECT websites.*, users.username FROM websites LEFT JOIN users ON websites.user_id = users.id ORDER BY created_at DESC')
    else:
        sites = query_db('SELECT * FROM websites WHERE user_id = ? ORDER BY created_at DESC', (user['id'],))
    return render_template('add.html', title='Add Website', sites=sites, is_admin=user['is_admin'])


@app.route('/account', methods=['GET', 'POST'])
@login_required
def account():
    """Manage account: change username or password."""
    user = current_user()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'change_username':
            new_username = request.form['new_username'].strip()
            if not new_username:
                flash('Username cannot be empty.', 'error')
            else:
                # check if taken
                existing = query_db('SELECT id FROM users WHERE username = ? AND id != ?', (new_username, user['id']), one=True)
                if existing:
                    flash('That username is already taken.', 'error')
                else:
                    execute_db('UPDATE users SET username = ? WHERE id = ?', (new_username, user['id']))
                    flash('Username updated.', 'success')
                    # update session
                    session['user_id'] = user['id']
        elif action == 'change_password':
            current = request.form['current_password']
            new = request.form['new_password']
            confirm = request.form['confirm_password']
            if not check_password_hash(user['password_hash'], current):
                flash('Current password is incorrect.', 'error')
            elif not new:
                flash('New password cannot be empty.', 'error')
            elif new != confirm:
                flash('Passwords do not match.', 'error')
            else:
                password_hash = generate_password_hash(new)
                execute_db('UPDATE users SET password_hash = ? WHERE id = ?', (password_hash, user['id']))
                flash('Password updated.', 'success')
        return redirect(url_for('account'))
    return render_template('account.html', title='Account')


@app.route('/users', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_users():
    """Admin page to manage users: add, edit and remove."""
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_user':
            username = request.form['username'].strip()
            password = request.form['password']
            confirm = request.form['confirm']
            role = request.form.get('role', 'user')
            if not username or not password:
                flash('Username and password are required.', 'error')
            elif password != confirm:
                flash('Passwords do not match.', 'error')
            elif query_db('SELECT id FROM users WHERE username = ?', (username,), one=True):
                flash('Username already exists.', 'error')
            else:
                password_hash = generate_password_hash(password)
                execute_db(
                    'INSERT INTO users (username, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?)',
                    (username, password_hash, 1 if role == 'admin' else 0, datetime.utcnow().isoformat(timespec='seconds'))
                )
                flash('User created.', 'success')
        elif action == 'delete_user':
            user_id = int(request.form['user_id'])
            # prevent deletion of self
            if user_id == session['user_id']:
                flash('You cannot delete your own account.', 'error')
            else:
                execute_db('DELETE FROM users WHERE id = ?', (user_id,))
                flash('User removed.', 'success')
        elif action == 'toggle_role':
            user_id = int(request.form['user_id'])
            user_row = query_db('SELECT * FROM users WHERE id = ?', (user_id,), one=True)
            if user_row:
                new_role = 0 if user_row['is_admin'] else 1
                # avoid demoting self from admin
                if user_row['id'] == session['user_id'] and user_row['is_admin']:
                    flash('You cannot remove your own admin privileges.', 'error')
                else:
                    execute_db('UPDATE users SET is_admin = ? WHERE id = ?', (new_role, user_id))
                    flash('User role updated.', 'success')
        return redirect(url_for('manage_users'))
    # GET: show lists
    users = query_db('SELECT *, (SELECT COUNT(*) FROM websites WHERE user_id = users.id) as site_count FROM users ORDER BY username')
    return render_template('manage_users.html', title='Manage Users', users=users)


@app.cli.command('initdb')
def initdb_command():  # type: ignore[misc]
    """Initialise the database from the command line."""
    init_db()
    print('Initialised the database.')


# Make the current_user function available in templates
@app.context_processor
def inject_current_user():
    return {'current_user': current_user}


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'initdb':
        with app.app_context():
            init_db()
            print('Database initialised.')
    else:
        app.run(debug=True)