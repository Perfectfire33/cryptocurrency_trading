from __future__ import print_function
from flask import (
    Blueprint, flash, g, redirect, render_template, request, url_for
)
from flaskr.auth import login_required
from flaskr.db import get_db
from werkzeug.security import generate_password_hash, check_password_hash
import requests
import json
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

# New Imports for Writing to a sheet
import google.auth
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError


bp = Blueprint('bittrexSheets', __name__)


@bp.route('/admin/bittrexSheets')
@login_required
def index():
    return render_template('admin/bittrexSheets.html')


@bp.route('/admin/writeToFromSheetsX')
@login_required
def writeToFromSheetsX():
    # If modifying these scopes, delete the file token.json.
    SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

    # The ID and range of a sample spreadsheet.
    SPREADSHEET_ID = '1LfD5_7n1IcUXadVt4-4eo8XVbjm8dcwturBqCJ96sAY'
    #RANGE_NAME = 'Class Data!A2:E'
    RANGE_NAME = 'Sheet1!A2:A2'

    """Shows basic usage of the Sheets API.
    Prints values from a sample spreadsheet.
    """
    dirname = os.path.dirname(__file__)
    credentials_file = os.path.join(dirname, 'credentials.json')
    token_file = os.path.join(dirname, 'token.json')
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists(token_file):
        creds = Credentials.from_authorized_user_file(token_file, SCOPES)
    # If there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file(
                credentials_file, SCOPES)
            creds = flow.run_local_server(port=0)
        # Save the credentials for the next run
        with open(token_file, 'w') as token:
            token.write(creds.to_json())

    try:
        service = build('sheets', 'v4', credentials=creds)

        # Call the Sheets API
        sheet = service.spreadsheets()
        result = sheet.values().get(spreadsheetId=SPREADSHEET_ID,
                                    range=RANGE_NAME).execute()
        values = result.get('values', [])

        if not values:
            print('No data found.')
            return

        print('Market Ticker:')
        for row in values:
            # Print columns A Row 2, which correspond to indices 0.
            print('%s' % (row[0]))

            api_url = "https://api.bittrex.com/v3/markets/" + row[0] + "/ticker"
            response = requests.get(api_url)
            print(response.json())
            json_response = response.json()
            print(response.status_code)
            print(response.headers["Content-Type"])



            print("AAAAAAAAAAAAA")
            print(json_response["symbol"])
            print(json_response["lastTradeRate"])
            print(json_response["bidRate"])
            print(json_response["askRate"])
            print("AAAAAAAAAAAAA")

        #Update Cells with Bittrex Data
        RANGE_NAME = 'Sheet1!A3:A3'
        value_input_option = "USER_ENTERED"

        values = [
            [
                json_response["symbol"]
            ],
            # Additional rows ...
        ]
        body = {
            'values': values
        }
        result = service.spreadsheets().values().update(
            spreadsheetId=SPREADSHEET_ID, range=RANGE_NAME,
            valueInputOption=value_input_option, body=body).execute()





    except HttpError as err:
        print(err)






    return render_template('admin/bittrexSheets.html')