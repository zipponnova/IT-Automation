import os
from slack_sdk import WebClient
import csv
import pandas as pd
from openpyxl.styles import PatternFill
import requests
from slack_sdk.webhook import WebhookClient
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_bolt import App
from slack_bolt.adapter.socket_mode import SocketModeHandler
from flask import request
import ssl
from flask import jsonify
from falconpy import Hosts
from io import BytesIO
import base64
import matplotlib.pyplot as plt
import plotly.graph_objs as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import numpy as np
from collections import defaultdict
import matplotlib
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, send_file, Response, render_template_string, get_flashed_messages, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask import flash
import platform
from falconpy import APIHarness
import plotly.io as pio
import plotly.graph_objects as go
import time
import json
import plotly
import random
from wtforms import Form, StringField, PasswordField, validators
import re
from flask_wtf import FlaskForm
import requests.exceptions
from flask_wtf.csrf import generate_csrf
import pdfkit


matplotlib.use('Agg')

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('FLASK_APP_SECRET_KEY', 'default_secret_key')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('FLASK_APP_SQLALCHEMY_DATABASE_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


# # Add email configuration
# app.config.update(
#     MAIL_SERVER='smtp.example.com',
#     MAIL_PORT=587,
#     MAIL_USE_TLS=True,
#     MAIL_USERNAME='your_email@example.com',
#     MAIL_PASSWORD='your_email_password',
# )

# mail = Mail(app)
# serializer = URLSafeTimedSerializer(app.config['SECRET_KEY'])

db = SQLAlchemy(app)

# Set up the Flask-Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(db.Model, UserMixin):
    id = db.Column(db.String(80), primary_key=True)
    password = db.Column(db.String(120))
    role = db.Column(db.String(80))

    def __init__(self, username, password, role):
        self.id = username
        self.password = generate_password_hash(password)
        self.role = role

    def check_password(self, password):
        return check_password_hash(self.password, password)

    def is_admin(self):
        return self.role == 'admin'

    def is_superadmin(self):
        return self.role == 'superadmin'
    
    def update_password(self, new_password):
        self.password = generate_password_hash(new_password)

    def set_password(self, password):
        self.password = generate_password_hash(password)

db.create_all()

@login_manager.user_loader
def load_user(username):
    return User.query.get(username)

# Add users to the database
def add_user(username, password, role):
    user = User.query.get(username)
    if not user:
        if role in ['admin', 'user', 'superadmin']:
            user = User(username=username, password=password, role=role)
            db.session.add(user)
            db.session.commit()
        else:
            raise ValueError("Invalid role: {}".format(role))


ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE


@app.route('/index')
@login_required
def index():
    return render_template('index.html', user=current_user.id)


@app.route('/', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.get(username)
        if user and user.check_password(password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid username or password.')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'superadmin':
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def admin_or_superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not (current_user.is_admin() or current_user.is_superadmin()):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


# Registration route
@app.route('/register', methods=['GET', 'POST'])
@superadmin_required  # Use the superadmin_required decorator here
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']

        if User.query.get(username):
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))

        if not is_strong_password(password):
            flash('Password must be at least 8 characters long, contain at least one uppercase letter, one lowercase letter, and one number.', 'error')
            return redirect(url_for('register'))

        try:
            add_user(username, password, role)
        except ValueError as e:
            flash(str(e), 'error')
            return redirect(url_for('register'))

        flash('User successfully registered!', 'success')
        return redirect(url_for('index'))

    return render_template('register.html')


@app.route('/users')
@superadmin_required
def view_users():
    users = User.query.all()
    return render_template('users.html', users=users)


@app.route('/users/delete/<user_id>', methods=['POST'])
@superadmin_required
def delete_user(user_id):
    user = User.query.get(user_id)
    if user:
        db.session.delete(user)
        db.session.commit()
        flash('User deleted successfully.', 'success')
    else:
        flash('User not found.', 'error')
    return redirect(url_for('view_users'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if not current_user.check_password(current_password):
            flash('Current password is incorrect.', 'error')
            return render_template('change_password.html')

        if new_password != confirm_password:
            flash('New password and confirm password do not match.', 'error')
            return render_template('change_password.html')

        if not is_strong_password(new_password):
            flash('Password must be at least 8 characters long and contain an uppercase letter, a lowercase letter, and a digit.', 'error')
            return render_template('change_password.html')

        current_user.set_password(new_password)
        db.session.commit()
        flash('Password changed successfully.', 'success')
        return redirect(url_for('index'))

    csrf_token = generate_csrf()
    return render_template('change_password.html')

def is_strong_password(password):
    if len(password) < 8:
        return False

    if not re.search(r'[A-Z]', password) or not re.search(r'[a-z]', password) or not re.search(r'[0-9]', password):
        return False

    return True


# add_user('Username-here', 'Password-here', 'Role-here')
# add_user('Username-here', 'Password-here', 'Role-here')



# # Forgot password route
# @app.route('/forgot_password', methods=['GET', 'POST'])
# def forgot_password():
#     if request.method == 'POST':
#         email = request.form['email']
#         user = User.query.filter_by(email=email).first()
#         if user:
#             token = serializer.dumps(user.id, salt='password-reset')
#             msg = Message('Password Reset Request',
#                           sender='noreply@example.com',
#                           recipients=[email])

#             reset_url = url_for('reset_password', token=token, _external=True)
#             msg.body = f'Click the following link to reset your password: {reset_url}'
#             mail.send(msg)

#             flash('An email has been sent with instructions to reset your password.', 'info')
#             return redirect(url_for('login'))

#         flash('No account found with that email address.', 'danger')

#     return render_template('forgot_password.html')

# # Reset password route
# @app.route('/reset_password/<token>', methods=['GET', 'POST'])
# def reset_password(token):
#     try:
#         user_id = serializer.loads(token, salt='password-reset', max_age=3600)
#     except:
#         flash('The password reset link is invalid or has expired.', 'danger')
#         return redirect(url_for('forgot_password'))

#     user = User.query.get(user_id)

#     if request.method == 'POST':
#         new_password = request.form['password']
#         user.password = generate_password_hash(new_password)
#         db.session.commit()

#         flash('Your password has been updated!', 'success')
#         return redirect(url_for('login'))

#     return render_template('reset_password.html')



def falcon_paginate(endpoint_func, *args, **kwargs):
    offset = 0
    limit = kwargs.get("LIMIT", 500)
    result = endpoint_func(offset, limit, *args)
    yield result
    while result[0] + limit < result[1]:
        offset += limit
        result = endpoint_func(offset, limit, *args)
        yield result


@app.route('/compare', methods=['GET', 'POST'])
@login_required
def compare():
    if request.method == 'GET':
        return render_template('index.html')

    # Get uploaded files
    jamf = request.files.get('jamf')
    intune = request.files.get('intune')

    # Read CSV data from uploaded files
    jamf_data = [row for row in csv.DictReader(jamf.read().decode('utf-8').splitlines())] if jamf else None
    intune_data = [row for row in csv.DictReader(intune.read().decode('utf-8').splitlines())] if intune else None

    # Get JumpCloud users
    users_dict = get_jumpcloud_users()
    
    # Get JumpCloud data using the users_dict
    jumpcloud_data = get_jumpcloud_data_v1(users_dict)

    # Get all device serial numbers for the CID and their last_seen timestamp
    serial_numbers = {}
    for filter in (FILTER1, FILTER2, FILTER3):
        offset = 0
        total = 1
        limit = 5000
        while offset < total:
            new_offset, total, devices = device_list(offset, limit, SORT, filter)
            details = device_detail(devices)
            for detail in details:
                last_seen = detail['last_seen']
                last_seen_readable = parse_crowdstrike_timestamp(last_seen)
                serial_numbers[detail['serial_number']] = last_seen_readable

            # Update the offset with the new_offset value returned from the device_list function
            offset = new_offset + limit

    # Output table headers
    headers = ['Serial Numbers in MDM', 'Platform', 'Name/Email', 'Serial Numbers in Crowdstrike', 'Last Seen in MDM', 'Last Seen in Crowdstrike', 'Last Seen Since Days in MDM', 'Last Seen Since Days in Crowdstrike']
    na_rows = []

    # Create dictionaries to store counts of present and missing devices for each platform
    mac_counts = {
        'Present': 0,
        'Missing': 0,
        'total_days_since_last_seen_mdm': 0,
        'total_days_since_last_seen_crowdstrike': 0,
        'bins': [0, 0, 0, 0]  # Add bins to the dictionary
    }

    linux_counts = {
        'Present': 0,
        'Missing': 0,
        'total_days_since_last_seen_mdm': 0,
        'total_days_since_last_seen_crowdstrike': 0,
        'bins': [0, 0, 0, 0]  # Add bins to the dictionary
    }

    windows_counts = {
        'Present': 0,
        'Missing': 0,
        'total_days_since_last_seen_mdm': 0,
        'total_days_since_last_seen_crowdstrike': 0,
        'bins': [0, 0, 0, 0]  # Add bins to the dictionary
    }



    # Check for missing serial numbers in Jamf
    if jamf_data:
        jamf_serial_numbers = {row['Serial Number'] for row in jamf_data}
        for row in jamf_data:
            serial_number = row['Serial Number']
            last_checkin = row['Last Check-in']
            last_checkin_readable = datetime.strptime(last_checkin, '%d/%m/%y %H:%M').strftime('%Y-%m-%d %H:%M:%S')
            last_seen_crowdstrike = serial_numbers.get(serial_number, 'Not Found')
            last_seen_mdm_days = days_since_checkin(datetime.strptime(last_checkin_readable, '%Y-%m-%d %H:%M:%S'))
            last_seen_crowdstrike_days = days_since_checkin(datetime.strptime(last_seen_crowdstrike, '%Y-%m-%d %H:%M:%S')) if last_seen_crowdstrike != 'Not Found' else 'Not Found'
            if serial_number in serial_numbers:
                na_rows.append([serial_number, 'Mac', row['Email Address'], 'Present', last_checkin_readable, last_seen_crowdstrike, last_seen_mdm_days, last_seen_crowdstrike_days])
                mac_counts['Present'] += 1
                mac_counts['total_days_since_last_seen_mdm'] += last_seen_mdm_days
                mac_counts['total_days_since_last_seen_crowdstrike'] += last_seen_crowdstrike_days
            else:
                na_rows.append([serial_number, 'Mac', row['Email Address'], 'Missing', last_checkin_readable, 'N/A', last_seen_mdm_days, 'N/A'])
                mac_counts['Missing'] += 1

    # Check for missing serial numbers in JumpCloud
    if jumpcloud_data:
        jumpcloud_serial_numbers = {row['serialNumber'] for row in jumpcloud_data}
        for row in jumpcloud_data:
            serial_number = row['serialNumber']
            last_contact = row['lastContact']
            last_contact_readable = datetime.strptime(last_contact, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%d %H:%M:%S')
            last_seen_mdm = last_contact_readable
            last_seen_crowdstrike = serial_numbers.get(serial_number, 'Not Found')
            last_seen_mdm_days = days_since_checkin(datetime.strptime(last_seen_mdm, '%Y-%m-%d %H:%M:%S'))
            last_seen_crowdstrike_days = days_since_checkin(datetime.strptime(last_seen_crowdstrike, '%Y-%m-%d %H:%M:%S')) if last_seen_crowdstrike != 'Not Found' else 'Not Found'
            if serial_number in serial_numbers:
                na_rows.append([serial_number, 'Linux', row['hostname'], 'Present', last_seen_mdm, last_seen_crowdstrike, last_seen_mdm_days, last_seen_crowdstrike_days])
                linux_counts['Present'] += 1
                linux_counts['total_days_since_last_seen_mdm'] += last_seen_mdm_days
                linux_counts['total_days_since_last_seen_crowdstrike'] += last_seen_crowdstrike_days
            else:
                na_rows.append([serial_number, 'Linux', row['hostname'], 'Missing', last_seen_mdm, 'N/A', last_seen_mdm_days, 'N/A'])
                linux_counts['Missing'] += 1


    # Check for missing serial numbers in Intune
    if intune_data:
        intune_serial_numbers = {row['Serial number'] for row in intune_data}
        for row in intune_data:
            serial_number = row['Serial number']
            last_seen_mdm = serial_numbers.get(serial_number, 'Not Found')
            last_seen_crowdstrike = serial_numbers.get(serial_number, 'Not Found')
            last_seen_mdm_days = days_since_checkin(datetime.strptime(last_seen_mdm, '%Y-%m-%d %H:%M:%S')) if last_seen_mdm != 'Not Found' else 'Not Found'
            last_seen_crowdstrike_days = days_since_checkin(datetime.strptime(last_seen_crowdstrike, '%Y-%m-%d %H:%M:%S')) if last_seen_crowdstrike != 'Not Found' else 'Not Found'
            if serial_number in serial_numbers:
                na_rows.append([serial_number, 'Windows', row['Primary user email address'], 'Present', last_seen_mdm, last_seen_crowdstrike, last_seen_mdm_days, last_seen_crowdstrike_days])
                windows_counts['Present'] += 1
                windows_counts['total_days_since_last_seen_mdm'] += last_seen_mdm_days
                windows_counts['total_days_since_last_seen_crowdstrike'] += last_seen_crowdstrike_days
            else:
                na_rows.append([serial_number, 'Windows', row['Primary user email address'], 'Missing', 'N/A', 'N/A', 'N/A', 'N/A'])
                windows_counts['Missing'] += 1
    time_bins = [5, 10, 15, 21]

    for row in na_rows:
        if row[1] == 'Mac':
            for i, bin_limit in enumerate(time_bins):
                try:
                    row_6_int = int(row[6])
                except ValueError:
                    continue

                if i == 0 and row_6_int > bin_limit:  # Consider lower limit for the first bin
                    continue

                if row_6_int <= bin_limit:
                    mac_counts['bins'][i] += 1
                    break
        elif row[1] == 'Linux':
            for i, bin_limit in enumerate(time_bins):
                try:
                    row_6_int = int(row[6])
                except ValueError:
                    continue

                if i == 0 and row_6_int > bin_limit:  # Consider lower limit for the first bin
                    continue

                if row_6_int <= bin_limit:
                    linux_counts['bins'][i] += 1
                    break
        elif row[1] == 'Windows':
            for i, bin_limit in enumerate(time_bins):
                try:
                    row_6_int = int(row[6])
                except ValueError:
                    continue

                if i == 0 and row_6_int > bin_limit:  # Consider lower limit for the first bin
                    continue

                if row_6_int <= bin_limit:
                    windows_counts['bins'][i] += 1
                    break

    mac_counts['avg_days_since_last_seen_mdm'] = mac_counts['total_days_since_last_seen_mdm'] / mac_counts['Present'] if mac_counts['Present'] > 0 else 0
    mac_counts['avg_days_since_last_seen_crowdstrike'] = mac_counts['total_days_since_last_seen_crowdstrike'] / mac_counts['Present'] if mac_counts['Present'] > 0 else 0

    linux_counts['avg_days_since_last_seen_mdm'] = linux_counts['total_days_since_last_seen_mdm'] / linux_counts['Present'] if linux_counts['Present'] > 0 else 0
    linux_counts['avg_days_since_last_seen_crowdstrike'] = linux_counts['total_days_since_last_seen_crowdstrike'] / linux_counts['Present'] if linux_counts['Present'] > 0 else 0

    windows_counts['avg_days_since_last_seen_mdm'] = windows_counts['total_days_since_last_seen_mdm'] / windows_counts['Present'] if windows_counts['Present'] > 0 else 0
    windows_counts['avg_days_since_last_seen_crowdstrike'] = windows_counts['total_days_since_last_seen_crowdstrike'] / windows_counts['Present'] if windows_counts['Present'] > 0 else 0

    return render_template('results.html', headers=headers, rows=na_rows, mac_counts=mac_counts, linux_counts=linux_counts, windows_counts=windows_counts, time_bins=time_bins, na_rows=na_rows)




@app.route('/report', methods=['POST', 'GET'])
@login_required
def report():
    if request.method == 'GET':
        return render_template('index.html')

    # Get uploaded files
    jamf = request.files.get('jamf')
    intune = request.files.get('intune')

    # Read CSV data from uploaded files
    jamf_data = [row for row in csv.DictReader(jamf.read().decode('utf-8').splitlines())] if jamf else None
    intune_data = [row for row in csv.DictReader(intune.read().decode('utf-8').splitlines())] if intune else None

    # Get JumpCloud users
    users_dict = get_jumpcloud_users()
    
    # Get JumpCloud data using the users_dict
    jumpcloud_data = get_jumpcloud_data_v1(users_dict)

    # Get all device serial numbers for the CID
    serial_numbers = set()
    for filter, data in ((FILTER1, intune_data), (FILTER2, jamf_data), (FILTER3, jumpcloud_data)):
        offset = 0
        total = 1
        limit = 5000
        displayed = 0
        while offset < total:
            # Get devices for the filter and print serials
            offset, total, devices = device_list(offset, limit, SORT, filter)
            details = device_detail(devices)
            for detail in details:
                displayed += 1
                serial_numbers.add(detail['serial_number'])

        if not displayed:
            print(f"No results returned for filter {filter}.")

    # Output table headers
    headers = ['Serial Numbers in MDM', 'Platform', 'Name/Email', 'Serial Numbers in Crowdstrike']
    na_rows = []

        # Create dictionaries to store counts of present and missing devices for each platform
    mac_counts = {'Missing': 0}
    linux_counts = {'Missing': 0}
    windows_counts = {'Missing': 0}

    # Check for missing serial numbers in Jamf
    if jamf_data:
        jamf_serial_numbers = {row['Serial Number'] for row in jamf_data}
        missing_serial_numbers = jamf_serial_numbers - serial_numbers
        for row in jamf_data:
            if row['Serial Number'] in missing_serial_numbers:
                na_rows.append([row['Serial Number'], 'Mac', row['Email Address'], 'Missing'])
                mac_counts['Missing'] += 1

    # Check for missing serial numbers in JumpCloud
    if jumpcloud_data:
        jumpcloud_serial_numbers = {row['serialNumber'] for row in jumpcloud_data}
        missing_serial_numbers = jumpcloud_serial_numbers - serial_numbers  # compare the set of serial numbers
        for row in jumpcloud_data:
            if row['serialNumber'] in missing_serial_numbers:
                na_rows.append([row['serialNumber'], 'Linux', row['hostname'], 'Missing'])
                linux_counts['Missing'] += 1

    # Check for missing serial numbers in Intune
    if intune_data:
        intune_serial_numbers = {row['Serial number'] for row in intune_data}
        missing_serial_numbers = intune_serial_numbers - serial_numbers
        for row in intune_data:
            if row['Serial number'] in missing_serial_numbers:
                na_rows.append([row['Serial number'], 'Windows', row['Primary user email address'], 'Missing'])
                windows_counts['Missing'] += 1


    return render_template('report.html', headers=headers, rows=na_rows, mac_counts=mac_counts, linux_counts=linux_counts, windows_counts=windows_counts)





client = WebClient(token=os.environ["SLACK_API_TOKEN"], ssl=ssl_context)

def slack(row):
    email = row[2]
    user_id = None
    try:
        user_info = client.users_lookupByEmail(email=email)
        user_id = user_info['user']['id']
        response = client.chat_postMessage(channel=user_id, text='Hey! this is a message from the 6sense security team. Your system does not have crowdstrike antivirus running. Please download and install it from here (https://6sense.sharepoint.com/:f:/s/Security/EgyLAHM_Kx9DofIMKXrLwxQBKi8MechB7pGTQXMibasWgw?e=sX84GS).')
        row[3] = user_id
    except SlackApiError as e:
        if e.response['error'] == 'users_not_found':
            print(f"Error: User with email {email} not found in Slack workspace.")
        else:
            print(f"Error: {e}")
            print(f"Response: {e.response}")
        row[3] = 'Message Not Sent'
    return row





@app.route('/slack', methods=['POST'])
@login_required
@admin_or_superadmin_required
def send_slack():
    row_index = int(request.form['row_index'])
    row = json.loads(request.form['row'])
    updated_row = slack(row)
    return jsonify({'row_index': row_index, 'updated_row': updated_row})


@app.route('/mac_slack', methods=['POST'])
@login_required
@admin_or_superadmin_required
def mac_slack():
    # Get uploaded Jamf file
    jamf = request.files['jamf']
    
    # Read CSV data from uploaded Jamf file
    jamf_data = [row for row in csv.DictReader(jamf.read().decode('utf-8').splitlines())] if jamf else None
    
    # Get all device serial numbers for the CID
    OFFSET = 0
    DISPLAYED = 0
    TOTAL = 1
    LIMIT = 5000

    serial_numbers = []
    while OFFSET < TOTAL:

        # Get devices for FILTER2 and print serials
        OFFSET, TOTAL, devices = device_list(OFFSET, LIMIT, SORT, FILTER2)
        details = device_detail(devices)
        for detail in details:
            DISPLAYED += 1
            serial_numbers.append(detail['serial_number'])
    
    if not DISPLAYED:
        print("No results returned.")
    
    # Output table headers
    headers = ['Serial Numbers in MDM','Platform', 'Name/Email', 'Slack ID']
    na_rows = []
    
    if jamf_data:
        jamf_serial_numbers = {row['Serial Number'] for row in jamf_data}
        missing_serial_numbers = jamf_serial_numbers - set(serial_numbers)
        for row in jamf_data:
            if row['Serial Number'] in missing_serial_numbers:
                na_rows.append([row['Serial Number'], 'Mac', row['Email Address'], 'N/A'])
                
        # Call slack() function with each row and update the rows with user_id or 'Message Sent'
        for row in na_rows:
            updated_row = slack(row)
            row[3] = updated_row[3]
  
    if not na_rows:
        na_rows = []

    return render_template('report_mac.html', headers=headers, rows=na_rows)



@app.route('/mac', methods=['POST'])
@login_required
def mac():
    # Get uploaded Jamf file
    jamf = request.files['jamf']
    
    # Read CSV data from uploaded Jamf file
    jamf_data = [row for row in csv.DictReader(jamf.read().decode('utf-8').splitlines())] if jamf else None
    
    # Get all device serial numbers for the CID
    OFFSET = 0
    DISPLAYED = 0
    TOTAL = 1
    LIMIT = 5000

    serial_numbers = []
    while OFFSET < TOTAL:

        # Get devices for FILTER2 and print serials
        OFFSET, TOTAL, devices = device_list(OFFSET, LIMIT, SORT, FILTER2)
        details = device_detail(devices)
        for detail in details:
            DISPLAYED += 1
            serial_numbers.append(detail['serial_number'])
    
    if not DISPLAYED:
        print("No results returned.")
    
    # Output table headers
    headers = ['Serial Numbers in MDM','Platform', 'Name/Email', 'Serial Numbers in Crowdstrike']
    na_rows = []
    
    if jamf_data:
        jamf_serial_numbers = {row['Serial Number'] for row in jamf_data}
        missing_serial_numbers = jamf_serial_numbers - set(serial_numbers)
        for row in jamf_data:
            if row['Serial Number'] in missing_serial_numbers:
                na_rows.append([row['Serial Number'], 'Mac', row['Email Address'], 'N/A'])
  
    if not na_rows:
        na_rows = []

    
    # Prepare data for pie chart
    # jamf_serial_numbers = [row.get('Serial Number', '') for row in jamf_data]
    # crowdstrike_mac_serial_numbers = [row.get('Serial Number', '') for row in crowdstrike_mac_data]

    # jamf_count = len(jamf_serial_numbers)
    # crowdstrike_mac_count = len(crowdstrike_mac_serial_numbers)

    # intersection_jamf_crowdstrike_mac_count = len(set(jamf_serial_numbers) & set(crowdstrike_mac_serial_numbers))

    # Create results_mac .txt file
    # with open('results_mac.txt', 'w') as f:
    #     f.write(f"Jamf Count: {jamf_count}\n")
    #     f.write(f"CrowdStrike Mac Count: {crowdstrike_mac_count}\n")

    return render_template('report_mac.html', headers=headers, rows=na_rows)


@app.route('/linux_slack', methods=['POST'])
@login_required
@admin_or_superadmin_required
def linux_slack():
    # Get JumpCloud users
    users_dict = get_jumpcloud_users()
    
    # Get JumpCloud data using the users_dict
    jumpcloud_data = get_jumpcloud_data_v1(users_dict)

    # Get all device serial numbers for the CID
    OFFSET = 0
    DISPLAYED = 0
    TOTAL = 1
    LIMIT = 5000
    serial_numbers = set()  # create a set to hold all serial numbers

    while OFFSET < TOTAL:
        # Get devices for FILTER1 and print serials
        OFFSET, TOTAL, devices = device_list(OFFSET, LIMIT, SORT, FILTER3)
        details = device_detail(devices)
        for detail in details:
            DISPLAYED += 1
            if not any(detail['serial_number'].startswith(prefix) for prefix in ('ec2', '0000-')):
                serial_numbers.add(detail['serial_number'])  # add each serial number to the set

    if not DISPLAYED:
        print("No results returned.")

    # Output table headers
    headers = ['Serial Numbers in MDM', 'Platform', 'Name/Email', 'Slack ID']
    na_rows = []

    if jumpcloud_data:
        jumpcloud_serial_numbers = {row['serialNumber'] for row in jumpcloud_data}
        missing_serial_numbers = jumpcloud_serial_numbers - serial_numbers  # compare the set of serial numbers
        for row in jumpcloud_data:
            if row['serialNumber'] in missing_serial_numbers:
                na_rows.append([row['serialNumber'], 'Linux', row['hostname'], 'N/A'])

        # Call slack() function with each row and update the rows with user_id or 'Message Sent'
        for row in na_rows:
            updated_row = slack(row)
            row[3] = updated_row[3]
            

    if not na_rows:
        na_rows = []
  
    
    return render_template('report_linux.html', headers=headers, rows=na_rows)


@app.route('/linux', methods=['POST'])
@login_required
def linux():
    # Get JumpCloud users
    users_dict = get_jumpcloud_users()
    
    # Get JumpCloud data using the users_dict
    jumpcloud_data = get_jumpcloud_data_v1(users_dict)

    # Get all device serial numbers for the CID
    OFFSET = 0
    DISPLAYED = 0
    TOTAL = 1
    LIMIT = 5000
    serial_numbers = set()  # create a set to hold all serial numbers

    while OFFSET < TOTAL:
        # Get devices for FILTER1 and print serials
        OFFSET, TOTAL, devices = device_list(OFFSET, LIMIT, SORT, FILTER3)
        details = device_detail(devices)
        for detail in details:
            DISPLAYED += 1
            if not any(detail['serial_number'].startswith(prefix) for prefix in ('ec2', '0000-')):
                serial_numbers.add(detail['serial_number'])  # add each serial number to the set

    if not DISPLAYED:
        print("No results returned.")

    # Output table headers
    headers = ['Serial Numbers in MDM', 'Platform', 'Name/Email', 'Serial Numbers in Crowdstrike']
    na_rows = []

    if jumpcloud_data:
        jumpcloud_serial_numbers = {row['serialNumber'] for row in jumpcloud_data}
        missing_serial_numbers = jumpcloud_serial_numbers - serial_numbers  # compare the set of serial numbers
        for row in jumpcloud_data:
            if row['serialNumber'] in missing_serial_numbers:
                na_rows.append([row['serialNumber'], 'Linux', row['hostname'], 'N/A'])            

    if not na_rows:
        na_rows = []
  
    
    return render_template('report_linux.html', headers=headers, rows=na_rows)



@app.route('/windows_slack', methods=['POST'])
@login_required
@admin_or_superadmin_required
def windows_slack():
    # Get uploaded files
    intune = request.files['intune']

    # Read CSV data from uploaded files
    intune_data = [row for row in csv.DictReader(intune.read().decode('utf-8').splitlines())] if intune else None

    # Get all device serial numbers for the CID
    OFFSET = 0
    DISPLAYED = 0
    TOTAL = 1
    LIMIT = 5000
    serial_numbers = set()  # create a set to hold all serial numbers

    while OFFSET < TOTAL:
        # Get devices for FILTER1 and print serials
        OFFSET, TOTAL, devices = device_list(OFFSET, LIMIT, SORT, FILTER1)
        details = device_detail(devices)
        for detail in details:
            DISPLAYED += 1
            serial_numbers.add(detail['serial_number'])  # add each serial number to the set

    if not DISPLAYED:
        print("No results returned.")

    # Output table headers
    headers = ['Serial Numbers in MDM', 'Platform', 'Name/Email', 'Slack ID']
    na_rows = []

    if intune_data:
        intune_serial_numbers = {row['Serial number'] for row in intune_data}
        missing_serial_numbers = intune_serial_numbers - serial_numbers  # compare the set of serial numbers
        for row in intune_data:
            if row['Serial number'] in missing_serial_numbers:
                na_rows.append([row['Serial number'], 'Windows', row['Primary user email address'], 'N/A'])

        # Call slack() function with each row and update the rows with user_id or 'Message Sent'
        for row in na_rows:
            updated_row = slack(row)
            row[3] = updated_row[3]

    if not na_rows:
        na_rows = []

    return render_template('report_windows.html', headers=headers, rows=na_rows)



@app.route('/windows', methods=['POST'])
@login_required
def windows():
    # Get uploaded files
    intune = request.files['intune']

    # Read CSV data from uploaded files
    intune_data = [row for row in csv.DictReader(intune.read().decode('utf-8').splitlines())] if intune else None

    # Get all device serial numbers for the CID
    OFFSET = 0
    DISPLAYED = 0
    TOTAL = 1
    LIMIT = 5000
    serial_numbers = set()  # create a set to hold all serial numbers

    while OFFSET < TOTAL:
        # Get devices for FILTER1 and print serials
        OFFSET, TOTAL, devices = device_list(OFFSET, LIMIT, SORT, FILTER1)
        details = device_detail(devices)
        for detail in details:
            DISPLAYED += 1
            serial_numbers.add(detail['serial_number'])  # add each serial number to the set

    if not DISPLAYED:
        print("No results returned.")

    # Output table headers
    headers = ['Serial Numbers in MDM', 'Platform', 'Name/Email', 'Serial Numbers in Crowdstrike']
    na_rows = []

    if intune_data:
        intune_serial_numbers = {row['Serial number'] for row in intune_data}
        missing_serial_numbers = intune_serial_numbers - serial_numbers  # compare the set of serial numbers
        for row in intune_data:
            if row['Serial number'] in missing_serial_numbers:
                na_rows.append([row['Serial number'], 'Windows', row['Primary user email address'], 'N/A'])

    if not na_rows:
        na_rows = []
    

    return render_template('report_windows.html', headers=headers, rows=na_rows)


def device_list(off: int, limit: int, sort: str, filter: str) -> tuple:
    """Return a list of all devices for the CID, paginating when necessary."""
    result = falcon.query_devices_by_filter(limit=limit, offset=off, sort=sort, filter=filter)
    new_offset = 0
    total = 0
    returned_device_list = []
    if result["status_code"] == 200:
        new_offset = result["body"]["meta"]["pagination"]["offset"]
        total = result["body"]["meta"]["pagination"]["total"]
        returned_device_list = result["body"]["resources"]

    return new_offset, total, returned_device_list


def device_detail(aids: list) -> list:
    """Return the device_id and serial_number for a list of AIDs provided."""
    result = falcon.get_device_details(ids=aids)
    device_details = []
    if result["status_code"] == 200:
        for device in result["body"]["resources"]:
            res = {}
            res["platform_name"] = device.get("platform_name", None)
            res["serial_number"] = device.get("serial_number", None)
            res["last_seen"] = device.get("last_seen", None)
            res["hostname"] = device.get("hostname", None)
            device_details.append(res)
    return device_details


BASE = "auto"
CHILD = None
SORT = "hostname.asc"
FILTER1 = "platform_name:'Windows'"
FILTER2 = "platform_name:'Mac'"
FILTER3 = "platform_name:'Linux'"

falcon = Hosts(client_id=os.environ["FALCON_CLIENT_ID"],
               client_secret=os.environ["FALCON_CLIENT_SECRET"],
               base_url=BASE,
               member_cid=CHILD)

JUMPCLOUD_API_KEY = os.environ["JUMPCLOUD_API_KEY"]
def get_jumpcloud_users():
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-api-key": JUMPCLOUD_API_KEY
    }
    
    users_url = "https://console.jumpcloud.com/api/systemusers"
    users_response = requests.get(users_url, headers=headers)
    
    if users_response.status_code != 200:
        print("Error: Unable to fetch users from JumpCloud API")
        return
    
    users_data = users_response.json()["results"]
    users_dict = {user["id"]: user for user in users_data}
    return users_dict

def get_jumpcloud_data_v1(users_dict):
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "x-api-key": JUMPCLOUD_API_KEY
    }
    
    devices_url = "https://console.jumpcloud.com/api/systems"
    devices_response = requests.get(devices_url, headers=headers)
    
    if devices_response.status_code != 200:
        print("Error: Unable to fetch devices from JumpCloud API")
        return
    
    devices_data = devices_response.json()["results"]
    jumpcloud_data = []

    for device in devices_data:
        device_serial = device.get("serialNumber", "N/A")
        last_seen = device.get("lastContact", "N/A")
        hostname = device.get("hostname", "N/A")
        
        user_email = "N/A"
        for user_id in device.get("user", []):
            user_email = users_dict.get(user_id, {}).get("email", "N/A")
            break

        jumpcloud_data.append({
            "serialNumber": device_serial,
            "hostname": hostname,
            "lastContact": last_seen,
            "email": user_email
        })

    return jumpcloud_data

@app.route('/compare_time_stamps', methods=['GET', 'POST'])
@login_required
def compare_time_stamps():
    if request.method == 'GET':
        return render_template('index.html')

    # Get uploaded files
    jamf = request.files.get('jamf')
    intune = request.files.get('intune')

    # Read CSV data from uploaded files
    jamf_data = [row for row in csv.DictReader(jamf.read().decode('utf-8').splitlines())] if jamf else None
    intune_data = [row for row in csv.DictReader(intune.read().decode('utf-8').splitlines())] if intune else None

    # Get JumpCloud data using the API
    users_dict = get_jumpcloud_users()
    jumpcloud_data = get_jumpcloud_data_v1(users_dict)

    # Get all device serial numbers for the CID and their last_seen timestamp
    serial_numbers = {}
    for filter in (FILTER1, FILTER2, FILTER3):
        offset = 0
        total = 1
        limit = 5000
        while offset < total:
            new_offset, total, devices = device_list(offset, limit, SORT, filter)
            details = device_detail(devices)
            for detail in details:
                last_seen = detail['last_seen']
                last_seen_readable = parse_crowdstrike_timestamp(last_seen)
                serial_numbers[detail['serial_number']] = last_seen_readable

            # Update the offset with the new_offset value returned from the device_list function
            offset = new_offset + limit

    # Prepare the output data
    output_data = []

    # Process Jamf data
    if jamf_data:
        for row in jamf_data:
            serial_number = row['Serial Number']
            user_name = row['Email Address']
            last_checkin = row['Last Check-in']
            last_checkin_readable = datetime.strptime(last_checkin, '%d/%m/%y %H:%M').strftime('%Y-%m-%d %H:%M:%S')
            last_seen_crowdstrike = serial_numbers.get(serial_number, 'Not Found')
            last_seen_mdm_days = days_since_checkin(datetime.strptime(last_checkin_readable, '%Y-%m-%d %H:%M:%S'))
            last_seen_crowdstrike_days = days_since_checkin(datetime.strptime(last_seen_crowdstrike, '%Y-%m-%d %H:%M:%S')) if last_seen_crowdstrike != 'Not Found' else 'Not Found'
            output_data.append([serial_number, 'Mac', user_name, last_checkin_readable, last_seen_crowdstrike, last_seen_mdm_days, last_seen_crowdstrike_days])

   # Process JumpCloud data
    if jumpcloud_data:
        for row in jumpcloud_data:
            serial_number = row['serialNumber']
            user_name = row['hostname']
            last_contact = row['lastContact']
            last_contact_readable = datetime.strptime(last_contact, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%d %H:%M:%S')
            last_seen_crowdstrike = serial_numbers.get(serial_number, 'Not Found')
            last_seen_mdm_days = days_since_checkin(datetime.strptime(last_contact_readable, '%Y-%m-%d %H:%M:%S'))
            last_seen_crowdstrike_days = days_since_checkin(datetime.strptime(last_seen_crowdstrike, '%Y-%m-%d %H:%M:%S')) if last_seen_crowdstrike != 'Not Found' else 'Not Found'
            output_data.append([serial_number, 'Linux', user_name, last_contact_readable, last_seen_crowdstrike, last_seen_mdm_days, last_seen_crowdstrike_days])

    # Process Intune data
    if intune_data:
        for row in intune_data:
            serial_number = row['Serial number']
            user_name = row['Primary user email address']
            last_checkin = row['Last check-in']
            last_checkin_readable = parse_timestamp(last_checkin)
            last_seen_crowdstrike = serial_numbers.get(serial_number, 'Not Found')
            last_seen_mdm_days = days_since_checkin(datetime.strptime(last_checkin_readable, '%Y-%m-%d %H:%M:%S'))
            last_seen_crowdstrike_days = days_since_checkin(datetime.strptime(last_seen_crowdstrike, '%Y-%m-%d %H:%M:%S')) if last_seen_crowdstrike != 'Not Found' else 'Not Found'
            output_data.append([serial_number, 'Windows', user_name, last_checkin_readable, last_seen_crowdstrike, last_seen_mdm_days, last_seen_crowdstrike_days])



    # Display headers
    headers = ['Serial Number', 'Platform','Name/Email', 'Last Seen in MDM', 'Last Seen in Crowdstrike', 'Last Seen Since Days in MDM', 'Last Seen Since Days in Crowdstrike']

    # Generate the chart and save it as an HTML file
    fig = plot_chart(output_data)
    fig.write_html('templates/chart.html', full_html=False)

    not_found_count = sum([1 for row in output_data if row[4] == 'Not Found'])

    # Save the output data as an HTML file
    with open('templates/time_stamp_report.html', 'w') as f:
        f.write(render_template('time_stamp_report_template.html', headers=headers, rows=output_data))

    return render_template('time_stamp_report.html', headers=headers, rows=output_data, not_found_count=not_found_count)


def get_last_seen_crowdstrike(crowdstrike_data, serial_number):
    for device in crowdstrike_data:
        if device['serial_number'] == serial_number:
            last_seen = device['last_seen']
            last_seen_readable = datetime.strptime(last_seen, '%Y-%m-%dT%H:%M:%S.%fZ').strftime('%Y-%m-%d %H:%M:%S')
            return last_seen_readable
    return 'Not Found'

def parse_timestamp(timestamp):
    parts = timestamp.split('.')
    date_time = datetime.strptime(parts[0], '%Y-%m-%d %H:%M:%S')
    if len(parts) > 1:
        microseconds = int(parts[1][:6])
        date_time = date_time.replace(microsecond=microseconds)
    return date_time.strftime('%Y-%m-%d %H:%M:%S')

def parse_crowdstrike_timestamp(timestamp):
    return datetime.strptime(timestamp, '%Y-%m-%dT%H:%M:%SZ').strftime('%Y-%m-%d %H:%M:%S')

def days_since_checkin(checkin_time):
    current_time = datetime.now()
    delta = current_time - checkin_time
    return delta.days


def plot_chart(output_data):
    data_by_platform = defaultdict(lambda: defaultdict(list))
    not_found_by_platform = defaultdict(int)

    # Define custom bins
    bins = [(1, 4), (5, 10), (11, 15), (16, 20), (21, np.inf)]
    bin_labels = ['1-4', '5-10', '11-15', '16-20', '21+']

    for row in output_data:
        platform = row[1]
        mdm_days_since = row[5]
        cs_days_since = row[6]

        data_by_platform[platform]['MDM'].append(mdm_days_since)
        if cs_days_since != 'Not Found':
            data_by_platform[platform]['Crowdstrike'].append(cs_days_since)
        else:
            not_found_by_platform[platform] += 1

    fig = make_subplots(rows=2, cols=2, specs=[[{}, {'type': 'domain'}], [{}, {'type': 'domain'}]], subplot_titles=("Days Since Last Seen - MDM", "Not Found by Platform - MDM", "Days Since Last Seen - Crowdstrike", "Not Found by Platform - Crowdstrike"))

    # Create line chart with pre-calculated counts for each bin for MDM
    for platform, days_since_by_source in data_by_platform.items():
        counts = [sum(lower <= d <= upper for d in days_since_by_source['MDM']) for lower, upper in bins]
        name = f"{platform} - MDM"
        legendgroup = f"{platform}-MDM"
        fig.add_trace(go.Scatter(x=bin_labels, y=counts, name=name, legendgroup=legendgroup, mode='lines+markers'), row=1, col=1)

    # Pie chart for not found systems by platform for MDM
    fig.add_trace(go.Pie(labels=list(not_found_by_platform.keys()), values=list(not_found_by_platform.values()), name="Not Found by Platform - MDM", legendgroup="Not Found-MDM"), row=1, col=2)

    # Create line chart with pre-calculated counts for each bin for Crowdstrike
    for platform, days_since_by_source in data_by_platform.items():
        counts = [sum(lower <= d <= upper for d in days_since_by_source['Crowdstrike']) for lower, upper in bins]
        name = f"{platform} - Crowdstrike"
        legendgroup = f"{platform}-Crowdstrike"
        fig.add_trace(go.Scatter(x=bin_labels, y=counts, name=name, legendgroup=legendgroup, mode='lines+markers'), row=2, col=1)

    fig.update_layout(
        title='Days Since Last Seen and Not Found Systems by Platform',
        showlegend=True,
        plot_bgcolor='#1C1C1C',
        title_font=dict(color='#1C1C1C'),  # Update the main title color
        legend=dict(font=dict(color='#1C1C1C')),  # Update the legend color
        annotations=[
            dict(text='Days Since Last Seen - MDM', x=0.225, y=1.05, showarrow=False, font=dict(color='#1C1C1C'), xref='paper', yref='paper'),
            dict(text='Not Found by Platform - MDM', x=0.775, y=1.05, showarrow=False, font=dict(color='#1C1C1C'), xref='paper', yref='paper'),
            dict(text='Days Since Last Seen - Crowdstrike', x=0.225, y=0.45, showarrow=False, font=dict(color='#1C1C1C'), xref='paper', yref='paper'),
            dict(text='Not Found by Platform - Crowdstrike', x=0.775, y=0.45, showarrow=False, font=dict(color='#1C1C1C'), xref='paper', yref='paper')
        ]
    )

    # Pie chart for not found systems by platform for Crowdstrike
    fig.add_trace(go.Pie(labels=list(not_found_by_platform.keys()), values=list(not_found_by_platform.values()), name="Not Found by Platform - Crowdstrike", legendgroup="Not Found-Crowdstrike"), row=2, col=2)

    fig.update_xaxes(showgrid=True, gridwidth=1, gridcolor='gray', tickfont=dict(color='#1C1C1C'))
    fig.update_yaxes(showgrid=True, gridwidth=1, gridcolor='gray', tickfont=dict(color='#1C1C1C'))

    # Update the subplot titles
    return fig

@app.route('/download_report', methods=['POST'])
@login_required
def download_report():
    report_type = request.form.get('report_type')

    # Get the data from the form
    headers = request.form.getlist('headers[]')
    rows = [request.form.getlist(f'row{i}[]') for i in range(len(request.form) - 1) if f'row{i}' in request.form]

    # Create a DataFrame from the rows
    df = pd.DataFrame(rows, columns=headers)

    if report_type == 'csv':
        csv = df.to_csv(index=False)
        response = make_response(csv)
        response.headers['Content-Disposition'] = 'attachment; filename=report.csv'
        response.headers['Content-Type'] = 'text/csv'
        return response

    elif report_type == 'pdf':
        html = df.to_html(index=False)
        pdf = pdfkit.from_string(html, False)
        response = make_response(pdf)
        response.headers['Content-Disposition'] = 'attachment; filename=report.pdf'
        response.headers['Content-Type'] = 'application/pdf'
        return response

    elif report_type == 'html':
        html = df.to_html(index=False)
        response = make_response(html)
        response.headers['Content-Disposition'] = 'attachment; filename=report.html'
        response.headers['Content-Type'] = 'text/html'
        return response

    return "Invalid report type", 400


# client_id = os.getenv("FALCON_CLIENT_ID")
# client_secret = os.getenv("FALCON_CLIENT_SECRET")

# falcon2 = APIHarness(client_id=client_id, client_secret=client_secret)

# OS_MAPPING = {
#     "Windows": ("{{add the hash from crowdstrike. DO NOT HARDCODE OR YOU'LL LOSE JOB.}}", "WindowsSensor.exe"),
#     "macOS": ("{{add the hash from crowdstrike. DO NOT HARDCODE OR YOU'LL LOSE JOB.}}", "FalconSensorMacOS.pkg"),
#     "Linux": ("{{add the hash from crowdstrike. DO NOT HARDCODE OR YOU'LL LOSE JOB.}}", "falcon-sensor.deb"),
#     "Linux_arm64": ("{{add the hash from crowdstrike. DO NOT HARDCODE OR YOU'LL LOSE JOB.}}", "falcon-sensor.deb"),
# }

# @app.route("/download_falcon_sensor")
# def download_falcon_sensor():
#     user_agent = request.headers.get("User-Agent")

#     os_id, filename = None, None

#     if "Windows" in user_agent:
#         os_id, filename = OS_MAPPING["Windows"]
#     elif "Mac" in user_agent:
#         os_id, filename = OS_MAPPING["macOS"]
#     elif "Linux" in user_agent:
#         os_id, filename = OS_MAPPING["Linux"]

#     if os_id and filename:
#         response = falcon2.command("DownloadSensorInstallerById", id=os_id)
#         if not isinstance(response, dict):
#             with open(filename, "wb") as download_file:
#                 download_file.write(response)
#             return send_file(filename, as_attachment=True)
#         else:
#             success_message = "Error downloading Falcon Sensor."
#             return render_template("download_success.html", message=error_message), 400

#     error_message = "Operating system not supported."
#     return render_template("download_error.html", message=error_message), 400

@app.route('/api/health-check', methods=['GET'])
def health_check():
    jumpcloud_status = check_jumpcloud_api()
    crowdstrike_status = check_crowdstrike_api()
    jamf_status = 'Inactive'
    intune_status = 'Inactive'

    return jsonify({
        'jumpcloud': jumpcloud_status,
        'crowdstrike': crowdstrike_status,
        'jamf': jamf_status,
        'intune': intune_status
    })

def check_jumpcloud_api():
    users_dict = get_jumpcloud_users()
    if users_dict:
        return 'Active'
    return 'Inactive'

def check_crowdstrike_api():
    try:
        offset, total, devices = device_list(0, 1, SORT, FILTER1)
        if devices:
            return 'Active'
        else:
            return 'Inactive'
    except Exception as e:
        print(f"CrowdStrike API check failed: {e}")
        return False


if __name__ == '__main__':
    app.run(port=8040, debug=True)
