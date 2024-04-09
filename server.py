from datetime import timedelta
from flask import Flask, session, request, redirect, url_for, render_template, flash, make_response, jsonify
from flask_wtf.csrf import CSRFProtect, CSRFError
import os, hashlib, functools, re, hashlib, html
from functools import wraps

#An Incredibly Annoying, Insufferable Authentication Implementation v1.0
#Made by ChatGPT4 and Andrej Šimko of Accenture
#Feel free to practice or contribute:)
#The initial goal is to have a complex session management to learn how to establish session, and use Macros in Burp Suite

app = Flask(__name__)
app.secret_key = 'your_secret_key'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=30)
csrf = CSRFProtect(app)

USERNAME = 'admin'
PASSWORD = 'password'
SECRET_KEY = 'secret123'
names_list = []

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if 'logged_in' not in session:
        # Custom message if the user is not logged in or session is invalid
        return 'You are not authenticated', 401
    else:
        # If the session exists but the CSRF token is missing or incorrect
        return 'The CSRF session token is missing or is incorrect.', 400


def login_required(f):
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('logged_in'):
            return redirect(url_for('login_step1'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/logout', methods=['GET', 'POST'])
def logout():
    session.clear()
    response = make_response(redirect(url_for('login_step1')))
 #   response.set_cookie('login1_success', '', expires=0)
 #   response.set_cookie('login2_status', '', expires=0)
 #   response.set_cookie('tracking_cookie', '', expires=0)
    return response


@app.route('/login_step1', methods=['GET', 'POST'])
def login_step1():
    if request.method == 'POST':
        # Assuming hidden4 is used for CSRF-like protection, validate it against hidden3
        if session.get('hidden4') != request.form.get('hidden3'):
            flash('Session validation failed. Please try again.')
            return redirect(url_for('login_step1'))
        
        if request.form['username'] == USERNAME:
            # Correct username, proceed to step 2
            session['step_completed'] = 1  # Indicate the current step as completed
            session['step1_completed'] = True  # Explicitly mark step 1 as completed
            session['valid_cookies'] = True  # This might be part of your additional validation/logic
            
            # Prepare a new hidden4 value for the next step
            session['hidden4'] = os.urandom(16).hex()
            response = make_response(redirect(url_for('login_step2')))
            response.set_cookie('login1_success', 'true')  # Consider if this cookie is necessary for your logic
            return response
        else:
            flash('Invalid login attempt. Please start over.')
    
    # For GET request or initial loading, generate hidden4 for CSRF-like protection
    session['hidden4'] = os.urandom(16).hex()
    return render_template('login_step1.html', hidden3=session['hidden4'])



@app.route('/login_step2', methods=['GET', 'POST'])
def login_step2():
    # Check if the user has completed step 1 before accessing step 2
    if 'step1_completed' not in session or not session['step1_completed']:
        flash('Please complete step 1 first.')
        return redirect(url_for('login_step1'))

    if request.method == 'GET':
        # Generate a new hidden3 value for CSRF-like protection
        new_hidden3_value = hashlib.sha1(os.urandom(16)).hexdigest()
        session['hidden3_value'] = new_hidden3_value
        return render_template('login_step2.html', hidden3=new_hidden3_value)

    elif request.method == 'POST':
        # Ensuring step 1 was completed based on 'step_completed' session flag
        if session.get('step_completed') == 1:
            if request.form['password'] == PASSWORD:
                # Retrieve the submitted hidden3 value and validate it
                submitted_hidden3 = request.form.get('hidden3', None)
                if submitted_hidden3 and submitted_hidden3 == session.pop('hidden3_value', None):
                    # Mark step 2 as completed and prepare for step 3
                    session['step2_completed'] = True
                    session['step_completed'] = 2
                    session['hidden4'] = os.urandom(16).hex()
                    response = make_response(redirect(url_for('login_step3')))
                    response.set_cookie('login2_status', 'passed')
                    return response
                else:
                    flash('Invalid or missing hidden value.')
                    return redirect(url_for('login_step1'))
            else:
                flash('Invalid password. Please try again.')
                return redirect(url_for('login_step1'))
        else:
            flash('Please complete step 1 first.')
            return redirect(url_for('login_step1'))

    # Handle any other cases by redirecting to the first step
    return redirect(url_for('login_step1'))




from flask import session, redirect, url_for, flash, render_template, request, make_response
import hashlib

@app.route('/login_step3', methods=['GET', 'POST'])
def login_step3():
    # Check if the user has completed step 2 before accessing step 3
    if 'step2_completed' not in session or not session['step2_completed']:
        flash('Please complete step 2 first.')
        return redirect(url_for('login_step2'))

    if request.method == 'POST':
        # This check ensures that only users who have completed step 2 can attempt step 3
        if session.get('step_completed') == 2:
            if request.form['secret_key'] == SECRET_KEY:
                # Successfully authenticated, set user as logged in
                session['logged_in'] = True
                # Clearing step completion flags as the user has successfully logged in
                session.pop('step_completed', None)
                session.pop('step2_completed', None)  # Ensure this flag is cleared after successful completion
                # Generate a random hash for tracking or other purposes
                random_hash = hashlib.sha1(os.urandom(16)).hexdigest()
                response = make_response(redirect(url_for('hi')))
                response.set_cookie('tracking_cookie', random_hash)
                return response
            else:
                flash('Invalid secret key. Please try again.')
                return redirect(url_for('login_step3'))
        else:
            flash('Please complete the previous steps first.')
            return redirect(url_for('login_step1'))
    else:
        # GET request: Prepare for a retry or first-time access
        # Generate a new hidden4 value every time the page is loaded to maintain a fresh state
        session['hidden4'] = os.urandom(16).hex()
        return render_template('login_step3.html')


@app.route('/hi', methods=['GET', 'POST'])
def hi():
    # Check if user is logged in
    if not session.get('logged_in'):
        return redirect(url_for('login_step1'))

    submitted_token = request.form.get('hi_token') if request.method == 'POST' else None
    stored_token = session.pop('hi_token', None)  # Remove the token to prevent reuse

    if request.method == 'POST':
        # Check the submitted token against the stored token
        if not stored_token or stored_token != submitted_token:
            flash('Invalid or expired token. Please try again.')
            return redirect(url_for('hi'))
        
        # Token is valid; process the submission
        name = request.form.get('name')
        encoded_name = html.escape(name)
        names_list.append(encoded_name)  # Append the submitted name to the list
        flash(f'Hi {name}, welcome to AIAIAI (An Incredibly Annoying, Insufferable Authentication Implementation)! Would you like to say hi to another user? If so, who?')

    # Generate and store a new token for the next request
    new_token = hashlib.sha256(os.urandom(16)).hexdigest()
    session['hi_token'] = new_token

    return render_template('hi.html', hi_token=new_token)

@app.route('/hi2', methods=['GET', 'POST'])
def hi2():
    # Check if the user is not logged in
    if 'logged_in' not in session or not session['logged_in']:
        # Instead of redirecting, return a 401 Unauthorized response
        response = make_response(jsonify({"error": "You are not authenticated"}), 401)
        return response

    if request.method == 'GET':
        # Display the form initially
        return render_template('hi2.html')
    
    elif request.method == 'POST':
        name = request.form.get('name')
        submitted_signature = request.form.get('signature')
        
        # Calculate the SHA1 checksum of the "name" parameter
        expected_signature = hashlib.sha1(name.encode()).hexdigest()

        # Validate the submitted signature against the expected one
        if submitted_signature != expected_signature:
            flash('Invalid signature detected')
            session.clear()  # Log user off by clearing the session
            return redirect(url_for('login_step1'))
        
        # If signature is valid, proceed with functionality
        names_list.append(name)  # Assuming names_list is globally defined
        flash(f'Hi, {name}! Your signature is valid.')
        
        return redirect(url_for('hi2'))

    # Fallback to redirect to the form if the method is not GET or POST
    return redirect(url_for('hi2'))


@app.route('/names')
def names():
    # Check if the user is not logged in by looking for a specific key in the session
    if 'logged_in' not in session or not session['logged_in']:
        # User is not logged in, return 401 Unauthorized
        response = make_response(jsonify({"error": "Unauthorized access"}), 401)
        return response
    
    # If the user is logged in, proceed to render the template with names
    return render_template('names.html', names=names_list)

if __name__ == '__main__':
    app.run(debug=True)
