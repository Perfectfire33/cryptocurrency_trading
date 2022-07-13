from __future__ import print_function
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from flaskr.auth import login_required
from flaskr.db import get_db
from werkzeug.security import generate_password_hash, check_password_hash
import requests

import os.path
from datetime import datetime
import time
from hashlib import sha512
import hmac
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# If modifying these scopes, delete the file token.json.
SCOPES = ['https://www.googleapis.com/auth/spreadsheets.readonly']

# The ID and range of a sample spreadsheet.
SAMPLE_SPREADSHEET_ID = '1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms'
SAMPLE_RANGE_NAME = 'Class Data!A2:E'

bp = Blueprint('admin', __name__)

#Display Data - Dashboard
@bp.route('/admin')
@login_required
def index():
    return render_template('admin/admin.html')


@bp.route('/admin/get_data')
@login_required
def get_data():
    api_url = "https://jsonplaceholder.typicode.com/todos/1"
    response = requests.get(api_url)
    print(response.json())
    print(response.status_code)
    print(response.headers["Content-Type"])
    return render_template('admin/admin.html')

@bp.route('/admin/post_data')
@login_required
def post_data():
    api_url = "https://jsonplaceholder.typicode.com/todos"
    todo = {"userId": 1, "title": "Buy milk", "completed": False}
    response = requests.post(api_url, json=todo)
    print(response.json())
    print(response.status_code)
    print(response.headers["Content-Type"])
    return render_template('admin/admin.html')


@bp.route('/admin/sheet_api_test')
@login_required
def sheet_api_test():
    """Shows basic usage of the Sheets API.
    Prints values from a sample spreadsheet.
    """
    dirname = os.path.dirname(__file__)
    credentials_file = os.path.join(dirname, 'credentials.json')
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists('token.json'):
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('sheets', 'v4', credentials=creds)

        # Call the Sheets API
        sheet = service.spreadsheets()
        result = sheet.values().get(spreadsheetId=SAMPLE_SPREADSHEET_ID,
                                    range=SAMPLE_RANGE_NAME).execute()
        values = result.get('values', [])

        if not values:
            print('No data found.')
            return

        print('Name, Major:')
        for row in values:
            # Print columns A and E, which correspond to indices 0 and 4.
            print('%s, %s' % (row[0], row[4]))
    except HttpError as err:
        print(err)

    return render_template('admin/admin.html')


@bp.route('/admin/get_bittrex_markets')
@login_required
def get_bittrex_markets():
    api_url = "https://api.bittrex.com/v3/markets"
    response = requests.get(api_url)
    print(response.json())
    print(response.status_code)
    print(response.headers["Content-Type"])
    return render_template('admin/admin.html')


@bp.route('/admin/get_bittrex_balances')
@login_required
def get_bittrex_balances():
    api_url = "https://api.bittrex.com/v3/balances"
    #timestamp = datetime.now()
    timestamp = time.time()
    timestamp_ms = int(timestamp * 1000)
    timestamp_ms_str = str(timestamp_ms)
    print("timestamp")
    print(timestamp_ms)
    print("timestamp")
    hash = sha512(''.encode()).hexdigest()
    print("hash")
    print(hash)
    print("hash")
    api_signature = timestamp_ms_str + api_url + "GET" + hash
    secret = "a262963c6aac43e99e169b38f5979e5e"
    signature = hmac.new(secret.encode(), api_signature.encode(), sha512).hexdigest()

    headers = {
        'Api-Key': '0246a69ab2554e08800a01195937c3d9',
        'Api-Timestamp': timestamp_ms_str,
        'Api-Content-Hash': hash,
        'Api-Signature': signature
               }
    response = requests.get(api_url, headers=headers)
    print(response.json())
    print(response.status_code)
    #print(response.headers["Content-Type"])
    return render_template('admin/admin.html')



@bp.route('/users_list')
@login_required
def get_users():
    db = get_db()
    users = db.execute(
        'SELECT xuser_id, xuser_username, xuser_firstname, xuser_lastname, xuser_email'
        ' FROM xuser'
    ).fetchall()

    return render_template('admin/user_list.html', users=users)

@bp.route('/user_delete', methods=['POST'])
def delete_user():
    db = get_db()
    db.execute(
        'DELETE FROM xuser WHERE xuser_id = ?', [request.form['user_to_delete']]
    )
    db.commit()
    return redirect(url_for('admin.get_users'))

def get_user(user_id):
    user = get_db().execute(
        'SELECT xuser_id, xuser_username, xuser_password, xuser_firstname, xuser_lastname, xuser_email'
        ' FROM xuser'
        ' WHERE xuser_id = ?',
        (user_id,)
    ).fetchone()

    return user


@bp.route('/<int:user_id>/user_update', methods=['GET', 'POST'])
@login_required
def update_user(user_id):
    user = get_user(user_id)
    if request.method == 'POST':
        username = request.form['username']
        firstname = request.form['firstname']
        lastname = request.form['lastname']
        email = request.form['email']
        password = request.form['password']
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'

        if error is not None:
            flash(error)
        else:
            db = get_db()
            db.execute(
                'UPDATE xuser SET xuser_username = ?, xuser_password = ?, xuser_firstname = ?, xuser_lastname = ?, xuser_email = ? WHERE xuser_id = ?',
                [username,
                 generate_password_hash(password),
                 firstname,
                 lastname,
                 email,
                 user_id]
            )
            db.commit()
            return redirect(url_for('admin.index'))

    return render_template('admin/user_edit.html', user=user)


@bp.route('/messages')
@login_required
def get_messages():
    db = get_db()
    messages = db.execute(
        'SELECT message_id, message_name, message_email, message_subject, message_body'
        ' FROM message'
    ).fetchall()

    return render_template('admin/messages.html', messages=messages)

@bp.route('/message_delete', methods=['POST'])
def delete_message():
    db = get_db()
    db.execute(
        'DELETE FROM message WHERE message_id = ?', [request.form['message_to_delete']]
    )
    db.commit()
    return redirect(url_for('admin.get_messages'))