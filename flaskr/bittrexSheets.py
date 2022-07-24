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



@bp.route('/admin/writeToFromSheetsBatchGet')
@login_required
def writeToFromSheetsBatchGet():
    # If modifying these scopes, delete the file token.json.
    SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

    # The ID and range of a sample spreadsheet.
    SPREADSHEET_ID = '1LfD5_7n1IcUXadVt4-4eo8XVbjm8dcwturBqCJ96sAY'
    #RANGE_NAME = 'Class Data!A2:E'
    RANGE_NAME = ['Sheet1!C1:C1', 'Sheet1!D1:D1']

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
        result = sheet.values().batchGet(spreadsheetId=SPREADSHEET_ID,
                                    ranges=RANGE_NAME).execute()
        values = result.get('valueRanges', [])

        if not values:
            print('No data found.')
            return result


        for row in values:
            # Print columns A Row 2, which correspond to indices 0.
            #print('%s' % (row[0]))
            print("AAAAAAA")
            print(row['values'][0][0])
            print("AAAAAAA")

    except HttpError as err:
        print(err)
        return err

    return render_template('admin/bittrexSheets.html')



@bp.route('/admin/writeToFromSheetsBatchUpdate')
@login_required
def writeToFromSheetsBatchUpdate():
    # If modifying these scopes, delete the file token.json.
    SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

    # The ID and range of a sample spreadsheet.
    SPREADSHEET_ID = '1LfD5_7n1IcUXadVt4-4eo8XVbjm8dcwturBqCJ96sAY'
    RANGE_NAME1 = 'E2:F'
    RANGE_NAME2 = 'G1:H1'
    value_input_option = "USER_ENTERED"

    """Shows basic usage of the Sheets API.
    Prints values from a sample spreadsheet.
    """
    dirname = os.path.dirname(__file__)
    credentials_file = os.path.join(dirname, 'credentials.json')
    token_file = os.path.join(dirname, 'token.json')
    print(token_file)
    creds = None
    # The file token.json stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first
    # time.
    if os.path.exists(token_file):
        #creds = Credentials.from_authorized_user_file('token.json', SCOPES)
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
        #with open('token.json', 'w') as token:
        with open(token_file, 'w') as token:
            token.write(creds.to_json())


    try:

        service = build('sheets', 'v4', credentials=creds)
        values1 = [
            [
                "A", "B"
            ],
            [
                "C", "D"
            ]
            # Additional rows ...
        ]
        values2 = [
            [
                "E", "E"
            ]
            # Additional rows ...
        ]
        data = [
            {
                'range': RANGE_NAME1,
                'values': values1
            },
            {
                'range': RANGE_NAME2,
                'values': values2
            }
        ]
        body = {
            'valueInputOption': value_input_option,
            'data': data
        }
        result = service.spreadsheets().values().batchUpdate(
            spreadsheetId=SPREADSHEET_ID, body=body).execute()

        print("AAAAAAAAAA")
        print(result)
        print("AAAAAAAAAA")
        #print(f"{result.get('updatedCells')} cells updated.")
        #return result
    except HttpError as error:
        print(f"An error occurred: {error}")
        return error


    return render_template('admin/bittrexSheets.html')


@bp.route('/admin/writeToFromSheetsGetTickers')
@login_required
def writeToFromSheetsGetTickers():

    api_url = "https://api.bittrex.com/v3/markets/tickers"
    response = requests.get(api_url)
    print(response.json())
    #print(response.status_code)
    #print(response.headers["Content-Type"])
    json_response = response.json()
    #dirname = os.path.dirname(__file__)
    #tickerfile = os.path.join(dirname, 'tickerSymbols.json')
    #f = open(tickerfile, "w")
    #f.write(str(json_response))

    #print("AAAAAAAAAAA")
    #print(json_response[0])
    #print("AAAAAAAAAAA")

    #for ticker in json_response:
        #print("AAAAAAAAAAA")
        #print(ticker)
        #print(json_response[0])

        #if ticker["symbol"] == "ETH-BTC":
            #print("AAAAAAAAAAA")
            #print(ticker)
            #print(ticker["symbol"])
            #print(ticker["lastTradeRate"])
            #print("AAAAAAAAAAA")



    return render_template('admin/bittrexSheets.html')



@bp.route('/admin/writeToFromSheetsTest1a')
@login_required
def writeToFromSheetsTest1a():

    #Get Ticker Symbols from Sheets
    # If modifying these scopes, delete the file token.json.
    SCOPES = ['https://www.googleapis.com/auth/spreadsheets']

    # The ID and range of a sample spreadsheet.
    SPREADSHEET_ID = '1P_uedgcCTJbXHfwUU4yTZMI2jPvyXS4StYfnjCrvPGw'
    #RANGE_NAME = 'Class Data!A2:E'
    RANGE_NAME = ['Sheet1!C4:C4', 'Sheet1!K4:K4']

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
        result = sheet.values().batchGet(spreadsheetId=SPREADSHEET_ID,
                                    ranges=RANGE_NAME).execute()
        values = result.get('valueRanges', [])

        if not values:
            print('No data found.')
            return result


        #print("BBBBBBB")
        #print(values)
        #print("BBBBBBB")

        #print("CCCCCCCCC")
        #print(values[0]['values'][0][0])
        #print(values[1])
        #print("CCCCCCCCC")
        #i = 0
        #print("BBBBBBBBB")
        #print(len(values))
        #print("BBBBBBBBB")
        #while i < len(values):
            #if 'values' in values[i]:
            #    print("CCCCCCCC")
            #    print(i)
            #    print("CCCCCCCC")

            #i = i + 1


        if 'values' in values[0]:
            currencyPair1 = values[0]['values'][0][0]
        else:
            currencyPair1 = ""

        if 'values' in values[1]:
            currencyPair2 = values[1]['values'][0][0]
        else:
            currencyPair2 = ""

        #for row in values:
            # Print columns A Row 2, which correspond to indices 0.
            #print('%s' % (row[0]))
            #print("AAAAAAA")
            #print(row['values'][0][0])
            #print("AAAAAAA")

    except HttpError as err:
        print(err)
        return err

    # Hit Bittrex API and get all ticker symbols
    api_url = "https://api.bittrex.com/v3/markets/tickers"
    response = requests.get(api_url)
    #print(response.json())
    #print(response.status_code)
    #print(response.headers["Content-Type"])
    json_response = response.json()

    currencyPair1_lastTradeRate = ""
    currencyPair2_lastTradeRate = ""

    for ticker in json_response:
        #print("AAAAAAAAAAA")
        #print(ticker)
        #print(json_response[0])

        if ticker["symbol"] == currencyPair1:
            #print("AAAAAAAAAAA")
            #print(ticker)
            #print(ticker["symbol"])
            #print(ticker["lastTradeRate"])
            #print("AAAAAAAAAAA")

            currencyPair1_lastTradeRate = ticker["lastTradeRate"]


        if ticker["symbol"] == currencyPair2:

            currencyPair2_lastTradeRate = ticker["lastTradeRate"]


    # Write data to sheet
    RANGE_NAME1 = 'F4:F4'
    RANGE_NAME2 = 'N4:N4'
    value_input_option = "USER_ENTERED"



    try:
        values1 = [
            [
                currencyPair1_lastTradeRate
            ]
            # Additional rows ...
        ]
        values2 = [
            [
                currencyPair2_lastTradeRate
            ]
            # Additional rows ...
        ]
        data = [
            {
                'range': RANGE_NAME1,
                'values': values1
            },
            {
                'range': RANGE_NAME2,
                'values': values2
            }
        ]
        body = {
            'valueInputOption': value_input_option,
            'data': data
        }
        result = service.spreadsheets().values().batchUpdate(
            spreadsheetId=SPREADSHEET_ID, body=body).execute()

        print("AAAAAAAAAA")
        print(result)
        print("AAAAAAAAAA")
        #print(f"{result.get('updatedCells')} cells updated.")
        #return result
    except HttpError as error:
        print(f"An error occurred: {error}")
        return error




    return render_template('admin/bittrexSheets.html')