import os
from slack_sdk import WebClient
from flask import Flask, render_template, request, send_file
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


app = Flask(__name__)

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE



# Initialize Slack bot client with the webhook URL
webhook_url = 'https://hooks.slack.com/services/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'
client = WebClient(token=os.environ["SLACK_API_TOKEN"], ssl=ssl_context)

@app.route('/')
def index():
    return render_template('index.html')

def falcon_paginate(endpoint_func, *args, **kwargs):
    offset = 0
    limit = kwargs.get("LIMIT", 500)
    result = endpoint_func(offset, limit, *args)
    yield result
    while result[0] + limit < result[1]:
        offset += limit
        result = endpoint_func(offset, limit, *args)
        yield result


@app.route('/compare', methods=['POST'])
def compare():
    # Get uploaded files
    jamf = request.files['jamf']
    crowdstrike_mac = request.files['crowdstrike_mac']
    crowdstrike_linux = request.files['crowdstrike_linux']
    crowdstrike_windows = request.files['crowdstrike_windows']
    jumpcloud = request.files['jumpcloud']
    intune = request.files['intune']

    # Read CSV data from uploaded files
    jamf_data = [row for row in csv.DictReader(jamf.read().decode('utf-8').splitlines())] if jamf else None
    crowdstrike_mac_data = [row for row in csv.DictReader(crowdstrike_mac.read().decode('utf-8').splitlines())] if crowdstrike_mac else None
    crowdstrike_linux_data = [row for row in csv.DictReader(crowdstrike_linux.read().decode('utf-8').splitlines())] if crowdstrike_linux else None
    crowdstrike_windows_data = [row for row in csv.DictReader(crowdstrike_windows.read().decode('utf-8').splitlines())] if crowdstrike_windows else None
    jumpcloud_data = [row for row in csv.DictReader(jumpcloud.read().decode('utf-8').splitlines())] if jumpcloud else None
    intune_data = [row for row in csv.DictReader(intune.read().decode('utf-8').splitlines())] if intune else None

    # Output table headers
    headers = []
    rows = []

    if crowdstrike_mac_data:
        headers.extend(['Serial Numbers in MDM', 'Name/Email', 'Serial Numbers in Crowdstrike'])
        jamf_rows = [[row.get('Serial Number', 'N/A'), row.get('Full Name', 'N/A'),
                       next((cs_row['Serial Number'] for cs_row in crowdstrike_mac_data if cs_row['Serial Number'] == row['Serial Number']), 'N/A')]
                     for row in jamf_data]
        rows.extend(jamf_rows)
    if crowdstrike_linux_data:
        jumpcloud_rows = [[row.get('serialNumber', 'N/A'), row.get('hostname', 'N/A'),
                       next((cs_row['Serial Number'] for cs_row in crowdstrike_linux_data if cs_row['Serial Number'] == row['serialNumber']), 'N/A')]
                     for row in jumpcloud_data]
        rows.extend(jumpcloud_rows)
    if crowdstrike_windows_data:
        intune_rows = [[row.get('Serial number', 'N/A'), row.get('Primary user email address', 'N/A'),
                       next((cs_row['Serial Number'] for cs_row in crowdstrike_windows_data if cs_row['Serial Number'] == row['Serial number']), 'N/A')]
                     for row in intune_data]
        rows.extend(intune_rows)

    if not rows:
        rows = []


    # Prepare data for pie chart
    jamf_serial_numbers = [row.get('Serial Number', '') for row in jamf_data]
    crowdstrike_mac_serial_numbers = [row.get('Serial Number', '') for row in crowdstrike_mac_data]
    crowdstrike_linux_serial_numbers = [row.get('Serial Number', '') for row in crowdstrike_linux_data]
    crowdstrike_windows_serial_numbers = [row.get('Serial Number', '') for row in crowdstrike_windows_data]
    jumpcloud_serial_numbers = [row.get('serialNumber', '') for row in jumpcloud_data]
    intune_serial_numbers = [row.get('Serial number', '') for row in intune_data]

    jamf_count = len(jamf_serial_numbers)
    crowdstrike_linux_count = len(crowdstrike_linux_serial_numbers)
    crowdstrike_mac_count = len(crowdstrike_mac_serial_numbers)
    crowdstrike_windows_count = len(crowdstrike_windows_serial_numbers)
    jumpcloud_count = len(jumpcloud_serial_numbers)
    intune_count = len(intune_serial_numbers)

    intersection_jamf_crowdstrike_mac_count = len(set(jamf_serial_numbers) & set(crowdstrike_mac_serial_numbers))
    intersection_jumpcloud_crowdstrike_linux_count = len(set(jumpcloud_serial_numbers) & set(crowdstrike_linux_serial_numbers))
    intersection_intune_crowdstrike_windows_count = len(set(intune_serial_numbers) & set(crowdstrike_windows_serial_numbers))

    # Create results.txt file
    with open('results.txt', 'w') as f:
        f.write(f"Jamf Count: {jamf_count}\n")
        f.write(f"CrowdStrike Mac Count: {crowdstrike_mac_count}\n")
        f.write(f"CrowdStrike Linux Count: {crowdstrike_linux_count}\n")
        f.write(f"CrowdStrike Windows Count: {crowdstrike_windows_count}\n")
        f.write(f"JumpCloud Count: {jumpcloud_count}\n")
        f.write(f"Intune Count: {intune_count}\n")

    # Render results template with table and pie chart data
    return render_template('results.html', headers=headers, rows=rows,
                           jamf_count=jamf_count, crowdstrike_mac_count=crowdstrike_mac_count, intersection_jamf_crowdstrike_mac_count=intersection_jamf_crowdstrike_mac_count, jumpcloud_count=jumpcloud_count, crowdstrike_linux_count=crowdstrike_linux_count, intersection_jumpcloud_crowdstrike_linux_count=intersection_jumpcloud_crowdstrike_linux_count, intune_count=intune_count, crowdstrike_windows_count=crowdstrike_windows_count, intersection_intune_crowdstrike_windows_count=intersection_intune_crowdstrike_windows_count)


@app.route('/report', methods=['POST'])
def report():
    # Get uploaded files
    jamf = request.files['jamf']
    crowdstrike_mac = request.files['crowdstrike_mac']
    crowdstrike_linux = request.files['crowdstrike_linux']
    crowdstrike_windows = request.files['crowdstrike_windows']
    jumpcloud = request.files['jumpcloud']
    intune = request.files['intune']

    # Read CSV data from uploaded files
    jamf_data = [row for row in csv.DictReader(jamf.read().decode('utf-8').splitlines())] if jamf else None
    crowdstrike_mac_data = [row for row in csv.DictReader(crowdstrike_mac.read().decode('utf-8').splitlines())] if crowdstrike_mac else None
    crowdstrike_linux_data = [row for row in csv.DictReader(crowdstrike_linux.read().decode('utf-8').splitlines())] if crowdstrike_linux else None
    crowdstrike_windows_data = [row for row in csv.DictReader(crowdstrike_windows.read().decode('utf-8').splitlines())] if crowdstrike_windows else None
    jumpcloud_data = [row for row in csv.DictReader(jumpcloud.read().decode('utf-8').splitlines())] if jumpcloud else None
    intune_data = [row for row in csv.DictReader(intune.read().decode('utf-8').splitlines())] if intune else None

    # Output table headers
    headers = []
    na_rows = []

    if crowdstrike_mac_data:
        headers.extend(['Serial Numbers in MDM', 'Name/Email', 'Serial Numbers Missing in Crowdstrike'])
        jamf_rows = [[row.get('Serial Number', 'N/A'), row.get('Full Name', 'N/A'),
                       next((cs_row['Serial Number'] for cs_row in crowdstrike_mac_data if cs_row['Serial Number'] == row['Serial Number']), 'N/A')]
                     for row in jamf_data]
        na_rows.extend([row for row in jamf_rows if 'N/A' in row])
    if crowdstrike_linux_data:
        jumpcloud_rows = [[row.get('serialNumber', 'N/A'), row.get('hostname', 'N/A'),
                       next((cs_row['Serial Number'] for cs_row in crowdstrike_linux_data if cs_row['Serial Number'] == row['serialNumber']), 'N/A')]
                     for row in jumpcloud_data]
        na_rows.extend([row for row in jumpcloud_rows if 'N/A' in row])
    if crowdstrike_windows_data:
        intune_rows = [[row.get('Serial number', 'N/A'), row.get('Primary user email address', 'N/A'),
                       next((cs_row['Serial Number'] for cs_row in crowdstrike_windows_data if cs_row['Serial Number'] == row['Serial number']), 'N/A')]
                     for row in intune_data]
        na_rows.extend([row for row in intune_rows if 'N/A' in row])

    if not na_rows:
        na_rows = []
    
    # Prepare data for pie chart
    jamf_serial_numbers = [row.get('Serial Number', '') for row in jamf_data]
    crowdstrike_mac_serial_numbers = [row.get('Serial Number', '') for row in crowdstrike_mac_data]
    crowdstrike_linux_serial_numbers = [row.get('Serial Number', '') for row in crowdstrike_linux_data]
    crowdstrike_windows_serial_numbers = [row.get('Serial Number', '') for row in crowdstrike_windows_data]
    jumpcloud_serial_numbers = [row.get('serialNumber', '') for row in jumpcloud_data]
    intune_serial_numbers = [row.get('Serial number', '') for row in intune_data]

    jamf_count = len(jamf_serial_numbers)
    crowdstrike_linux_count = len(crowdstrike_linux_serial_numbers)
    crowdstrike_mac_count = len(crowdstrike_mac_serial_numbers)
    crowdstrike_windows_count = len(crowdstrike_windows_serial_numbers)
    jumpcloud_count = len(jumpcloud_serial_numbers)
    intune_count = len(intune_serial_numbers)

    intersection_jamf_crowdstrike_mac_count = len(set(jamf_serial_numbers) & set(crowdstrike_mac_serial_numbers))
    intersection_jumpcloud_crowdstrike_linux_count = len(set(jumpcloud_serial_numbers) & set(crowdstrike_linux_serial_numbers))
    intersection_intune_crowdstrike_windows_count = len(set(intune_serial_numbers) & set(crowdstrike_windows_serial_numbers))

    # Create results_missing_all.txt file
    with open('results_missing_all.txt', 'w') as f:
        f.write(f"Jamf Count: {jamf_count}\n")
        f.write(f"CrowdStrike Mac Count: {crowdstrike_mac_count}\n")
        f.write(f"CrowdStrike Linux Count: {crowdstrike_linux_count}\n")
        f.write(f"CrowdStrike Windows Count: {crowdstrike_windows_count}\n")
        f.write(f"JumpCloud Count: {jumpcloud_count}\n")
        f.write(f"Intune Count: {intune_count}\n")

    return render_template('report.html', headers=headers, rows=na_rows)

def slack(row):
    # Initialize Slack bot client with the webhook URL
    webhook_url = 'https://hooks.slack.com/services/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'
    client = WebClient(token=os.environ["SLACK_API_TOKEN"], ssl=ssl_context)

    email = row[1]  # assuming the email address is in the second column
    user_id = None  # initialize user_id to None
    try:
        user_info = client.users_lookupByEmail(email=email)
        user_id = user_info['user']['id']
        response = client.chat_postMessage(channel=user_id, text='Hey! this is a messsage from security team. Your system does not have crowdstrike running. Please download and install it from here.')
        row[3] = user_id  # update the user ID in the row
    except SlackApiError as e:
        print(f"Error: {e}")
        row[3] = 'Message Sent'  # if the email is not found or message sending failed, update with 'Message Sent'
    return row





@app.route('/slack', methods=['POST'])
def send_slack():
    row_index = int(request.form['row_index'])
    row = json.loads(request.form['row'])
    updated_row = slack(row)
    return jsonify({'row_index': row_index, 'updated_row': updated_row})


@app.route('/mac_slack', methods=['POST'])
def mac_slack():
    # Get uploaded Jamf file
    jamf = request.files['jamf']
    
    # Read CSV data from uploaded Jamf file
    jamf_data = [row for row in csv.DictReader(jamf.read().decode('utf-8').splitlines())] if jamf else None
    
    # Get all device serial numbers for the CID
    serial_numbers = get_device_serial_numbers()
    
    # Output table headers
    headers = ['Serial Numbers in MDM', 'Name/Email', 'Serial Numbers Missing in Falcon', 'Send Slack Message']
    na_rows = []
    
    if jamf_data:
        jamf_rows = [[row.get('Serial Number', 'N/A'), row.get('Email Address', 'N/A'),
                       'Missing' if row['Serial Number'] not in serial_numbers else '', None]
                     for row in jamf_data]
        na_rows = [row for row in jamf_rows if row[2] == 'Missing']
        
        # Call slack() function with each row and update the rows with user_id or 'Message Sent'
        for row in na_rows:
            updated_row = slack(row)
            row[3] = updated_row[3]
    
    if not na_rows:
        na_rows = []   

    return render_template('report_mac.html', headers=headers, rows=na_rows)



@app.route('/mac', methods=['POST'])
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
def linux_slack():
    # Get uploaded files
    crowdstrike_linux = request.files['crowdstrike_linux']
    jumpcloud = request.files['jumpcloud']

    # Read CSV data from uploaded files
    crowdstrike_linux_data = [row for row in csv.DictReader(crowdstrike_linux.read().decode('utf-8').splitlines())] if crowdstrike_linux else None
    jumpcloud_data = [row for row in csv.DictReader(jumpcloud.read().decode('utf-8').splitlines())] if jumpcloud else None
    
    # Output table headers
    headers = []
    na_rows = []

    if crowdstrike_linux_data:
        headers.extend(['Serial Numbers in MDM', 'Name/Email', 'Serial Numbers Missing in Crowdstrike', 'Send Slack Message'])
        jumpcloud_rows = [[row.get('serialNumber', 'N/A'), row.get('hostname', 'N/A'),
                       next((cs_row['Serial Number'] for cs_row in crowdstrike_linux_data if cs_row['Serial Number'] == row['serialNumber']), 'N/A')]
                     for row in jumpcloud_data]
        na_rows.extend([row for row in jumpcloud_rows if 'N/A' in row])

        # Call slack() function with each row and update the rows with user_id or 'Message Sent'
        for row in na_rows:
            updated_row = slack(row)
            row[3] = updated_row[3]

    if not na_rows:
        na_rows = []    
            
    return render_template('report_linux.html', headers=headers, rows=na_rows)


@app.route('/linux', methods=['POST'])
def linux():
    # Get uploaded files
    crowdstrike_linux = request.files['crowdstrike_linux']
    jumpcloud = request.files['jumpcloud']

    # Read CSV data from uploaded files
    crowdstrike_linux_data = [row for row in csv.DictReader(crowdstrike_linux.read().decode('utf-8').splitlines())] if crowdstrike_linux else None
    jumpcloud_data = [row for row in csv.DictReader(jumpcloud.read().decode('utf-8').splitlines())] if jumpcloud else None
    
    # Output table headers
    headers = []
    na_rows = []

    if crowdstrike_linux_data:
        headers.extend(['Serial Numbers in MDM', 'Name/Email', 'Serial Numbers Missing in Crowdstrike'])
        jumpcloud_rows = [[row.get('serialNumber', 'N/A'), row.get('hostname', 'N/A'),
                       next((cs_row['Serial Number'] for cs_row in crowdstrike_linux_data if cs_row['Serial Number'] == row['serialNumber']), 'N/A')]
                     for row in jumpcloud_data]
        na_rows.extend([row for row in jumpcloud_rows if 'N/A' in row])

    if not na_rows:
        na_rows = []    

    # Prepare data for pie chart
    crowdstrike_linux_serial_numbers = [row.get('Serial Number', '') for row in crowdstrike_linux_data]
    jumpcloud_serial_numbers = [row.get('serialNumber', '') for row in jumpcloud_data]
    
    crowdstrike_linux_count = len(crowdstrike_linux_serial_numbers)
    jumpcloud_count = len(jumpcloud_serial_numbers)
    
    intersection_jumpcloud_crowdstrike_linux_count = len(set(jumpcloud_serial_numbers) & set(crowdstrike_linux_serial_numbers))
    
    # Create results_linux.txt file
    with open('results_linux.txt', 'w') as f:
        f.write(f"CrowdStrike Linux Count: {crowdstrike_linux_count}\n")
        f.write(f"JumpCloud Count: {jumpcloud_count}\n")
    
    return render_template('report_linux.html', headers=headers, rows=na_rows)


@app.route('/windows_slack', methods=['POST'])
def windows_slack():
    # Get uploaded files
    crowdstrike_windows = request.files['crowdstrike_windows']
    intune = request.files['intune']

    # Read CSV data from uploaded files
    crowdstrike_windows_data = [row for row in csv.DictReader(crowdstrike_windows.read().decode('utf-8').splitlines())] if crowdstrike_windows else None
    intune_data = [row for row in csv.DictReader(intune.read().decode('utf-8').splitlines())] if intune else None

    # Output table headers
    headers = []
    na_rows = []

    if crowdstrike_windows_data:
        headers.extend(['Serial Numbers in MDM', 'Name/Email', 'Serial Numbers Missing in Crowdstrike', 'Send Slack Message'])
        intune_rows = [[row.get('Serial number', 'N/A'), row.get('Primary user email address', 'N/A'),
                       next((cs_row['Serial Number'] for cs_row in crowdstrike_windows_data if cs_row['Serial Number'] == row['Serial number']), 'N/A')]
                     for row in intune_data]
        na_rows.extend([row for row in intune_rows if 'N/A' in row])

        # Call slack() function with each row and update the rows with user_id or 'Message Sent'
        for row in na_rows:
            updated_row = slack(row)
            row[3] = updated_row[3]

    if not na_rows:
        na_rows = []

    return render_template('report_windows.html', headers=headers, rows=na_rows)



@app.route('/windows', methods=['POST'])
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
            device_details.append(res)
    return device_details


BASE = "auto"
CLIENT_ID = "YOUR_API_KEY_ID_HERE"
CLIENT_SECRET = "YOUR_API_KEY_SECRET_HERE"
CHILD = None
SORT = "hostname.asc"
FILTER1 = "platform_name:'Windows'"
FILTER2 = "platform_name:'Mac'"

falcon = Hosts(client_id="9dc17bc03b0e47c289d6c444b3174de0",
               client_secret="1be9VSpPKA5yn4saL8hHzi6d20IqZ3Gc7DfmtMXv",
               base_url=BASE,
               member_cid=CHILD)



if __name__ == '__main__':
    app.run(port=8040)
