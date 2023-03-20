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
from io import BytesIO
import base64
import matplotlib.pyplot as plt
import plotly.graph_objs as go
from plotly.subplots import make_subplots
from datetime import datetime, timedelta
import numpy as np
from collections import defaultdict
import matplotlib
matplotlib.use('Agg')

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


@app.route('/compare', methods=['GET', 'POST'])
def compare():
    if request.method == 'GET':
        return render_template('index.html')

    # Get uploaded files
    jamf = request.files.get('jamf')
    jumpcloud = request.files.get('jumpcloud')
    intune = request.files.get('intune')

    # Read CSV data from uploaded files
    jamf_data = [row for row in csv.DictReader(jamf.read().decode('utf-8').splitlines())] if jamf else None
    jumpcloud_data = [row for row in csv.DictReader(jumpcloud.read().decode('utf-8').splitlines())] if jumpcloud else None
    intune_data = [row for row in csv.DictReader(intune.read().decode('utf-8').splitlines())] if intune else None

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
    mac_counts = {'Present': 0, 'Missing': 0}
    linux_counts = {'Present': 0, 'Missing': 0}
    windows_counts = {'Present': 0, 'Missing': 0}

    # Check for missing serial numbers in Jamf
    if jamf_data:
        jamf_serial_numbers = {row['Serial Number'] for row in jamf_data}
        for row in jamf_data:
            if row['Serial Number'] in serial_numbers:
                na_rows.append([row['Serial Number'], 'Mac', row['Email Address'], 'Present'])
                mac_counts['Present'] += 1
            else:
                na_rows.append([row['Serial Number'], 'Mac', row['Email Address'], 'Missing'])
                mac_counts['Missing'] += 1

    # Check for missing serial numbers in JumpCloud
    if jumpcloud_data:
        jumpcloud_serial_numbers = {row['serialNumber'] for row in jumpcloud_data}
        for row in jumpcloud_data:
            if row['serialNumber'] in serial_numbers:
                na_rows.append([row['serialNumber'], 'Linux', row['hostname'], 'Present'])
                linux_counts['Present'] += 1
            else:
                na_rows.append([row['serialNumber'], 'Linux', row['hostname'], 'Missing'])
                linux_counts['Missing'] += 1

    # Check for missing serial numbers in Intune
    if intune_data:
        intune_serial_numbers = {row['Serial number'] for row in intune_data}
        for row in intune_data:
            if row['Serial number'] in serial_numbers:
                na_rows.append([row['Serial number'], 'Windows', row['Primary user email address'], 'Present'])
                windows_counts['Present'] += 1
            else:
                na_rows.append([row['Serial number'], 'Windows', row['Primary user email address'], 'Missing'])
                windows_counts['Missing'] += 1


    # Create a pie chart of the number of devices present in Crowdstrike
    labels = ['Jamf', 'JumpCloud', 'Intune']
    values = [len(jamf_serial_numbers & serial_numbers), len(jumpcloud_serial_numbers & serial_numbers), len(intune_serial_numbers & serial_numbers)]
    colors = ['#ff9999', '#66b3ff', '#99ff99']

    fig1 = go.Figure(data=[go.Pie(labels=labels, values=values, hole=.3)])
    fig1.update_traces(marker=dict(colors=colors))
    fig1.update_layout(title='Number of Devices Present in Crowdstrike')


    # Create a pie chart of the number of devices present for each platform
    labels = ['Mac', 'Linux', 'Windows']
    present_values = [mac_counts['Present'], linux_counts['Present'], windows_counts['Present']]
    colors = ['#ff9999', '#66b3ff', '#99ff99']

    fig2 = go.Figure(data=[go.Pie(labels=labels, values=present_values, name='Present', hole=.3)])
    fig2.update_traces(marker=dict(colors=colors))
    fig2.update_layout(title='No. of Hosts Present in Crowdstrike')


    # Create a pie chart of the number of devices missing for each platform
    labels = ['Mac', 'Linux', 'Windows']
    missing_values = [mac_counts['Missing'], linux_counts['Missing'], windows_counts['Missing']]
    colors = ['#ff9999', '#66b3ff', '#99ff99']

    fig4 = go.Figure(data=[go.Pie(labels=labels, values=missing_values, name='Missing', hole=.5)])
    fig4.update_traces(marker=dict(colors=colors))
    fig4.update_layout(title='No. of Hosts Missing in Crowdstrike')


    # Create a bar chart of the number of devices present in each platform
    platforms = ['Mac', 'Linux', 'Windows']
    counts = {'Mac': 0, 'Linux': 0, 'Windows': 0}
    for row in na_rows:
        counts[row[1]] += 1
    platform_counts = [counts[platform] for platform in platforms]

    fig3 = go.Figure(data=[go.Bar(x=platforms, y=platform_counts, marker=dict(color=colors))])
    fig3.update_layout(title='Number of Devices Present in Each Platform', xaxis_title='Platform', yaxis_title='Count')

    # Combine both charts into a single plot
    fig = make_subplots(rows=1, cols=2, specs=[[{'type':'domain'}, {'type':'domain'}]])
    fig.add_trace(fig1.data[0], row=1, col=1)
    fig.add_trace(fig2.data[0], row=1, col=2)
    fig.add_trace(fig4.data[0], row=1, col=2)

    # Update the layout of the combined plot
    fig.update_layout(title='Results', height=500)

    # Add bar chart to the combined plot
    fig.update_traces(row=1, col=2, marker=dict(color=colors), selector=dict(type='bar'))

    # Create a directory for the HTML and CSS files
    if not os.path.exists('html'):
        os.mkdir('html')

    # Output the plot to an HTML file
    with open('html/graphs.html', 'w') as f:
        f.write(fig.to_html(full_html=False))

    # Create a CSS file for styling
    with open('html/style.css', 'w') as f:
        f.write('body {background-color: #f0f0f0;}')

    # Add a link to the CSS file in the head section of the HTML file
    with open('html/graphs.html', 'r+') as f:
        content = f.read()
        f.seek(0, 0)
        f.write('<!DOCTYPE html>\n<html>\n<head>\n<meta charset="utf-8">\n<title>Results</title>\n<link rel="stylesheet" type="text/css" href="static/style.css">\n</head>\n<body>\n')
        f.write(content)

    return render_template('results.html', headers=headers, rows=na_rows, pie_chart=fig1.to_html(), present_pie_chart=fig2.to_html(), missing_pie_chart=fig4.to_html(), bar_chart=fig3.to_html())





@app.route('/report', methods=['POST', 'GET'])
def report():
    if request.method == 'GET':
        return render_template('index.html')

    # Get uploaded files
    jamf = request.files.get('jamf')
    jumpcloud = request.files.get('jumpcloud')
    intune = request.files.get('intune')

    # Read CSV data from uploaded files
    jamf_data = [row for row in csv.DictReader(jamf.read().decode('utf-8').splitlines())] if jamf else None
    jumpcloud_data = [row for row in csv.DictReader(jumpcloud.read().decode('utf-8').splitlines())] if jumpcloud else None
    intune_data = [row for row in csv.DictReader(intune.read().decode('utf-8').splitlines())] if intune else None

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

    # Check for missing serial numbers in Jamf
    if jamf_data:
        jamf_serial_numbers = {row['Serial Number'] for row in jamf_data}
        missing_serial_numbers = jamf_serial_numbers - serial_numbers
        for row in jamf_data:
            if row['Serial Number'] in missing_serial_numbers:
                na_rows.append([row['Serial Number'], 'Mac', row['Email Address'], 'N/A'])

    # Check for missing serial numbers in JumpCloud
    if jumpcloud_data:
        jumpcloud_serial_numbers = {row['serialNumber'] for row in jumpcloud_data}
        missing_serial_numbers = jumpcloud_serial_numbers - serial_numbers
        for row in jumpcloud_data:
            if row['serialNumber'] in missing_serial_numbers:
                na_rows.append([row['serialNumber'], 'Linux', row['hostname'], 'N/A'])

    # Check for missing serial numbers in Intune
    if intune_data:
        intune_serial_numbers = {row['Serial number'] for row in intune_data}
        missing_serial_numbers = intune_serial_numbers - serial_numbers
        for row in intune_data:
            if row['Serial number'] in missing_serial_numbers:
                na_rows.append([row['Serial number'], 'Windows', row['Primary user email address'], 'N/A'])

    if not na_rows:
        na_rows = []

    else:
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
        response = client.chat_postMessage(channel=user_id, text='Hey! this is a messsage from 6sense security team. Your system does not have crowdstrike antivirus running. Please download and install it from here (https://6sense.sharepoint.com/:f:/s/Security/EgyLAHM_Kx9DofIMKXrLwxQBKi8MechB7pGTQXMibasWgw?e=sX84GS).')
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
    jumpcloud = request.files['jumpcloud']

    # Read CSV data form uploaded files
    jumpcloud_data = [row for row in csv.DictReader(jumpcloud.read().decode('utf-8').splitlines())] if jumpcloud else None
    
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
    jumpcloud = request.files['jumpcloud']

    # Read CSV data form uploaded files
    jumpcloud_data = [row for row in csv.DictReader(jumpcloud.read().decode('utf-8').splitlines())] if jumpcloud else None
    
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
    headers = ['Serial Numbers in MDM', 'Platform', 'Name/Email', 'Serial Numbers in Crowdstrike']
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
FALCON_CLIENT_ID = "YOUR_API_KEY_ID_HERE"
FALCON_CLIENT_SECRET = "YOUR_API_KEY_SECRET_HERE"
CHILD = None
SORT = "hostname.asc"
FILTER1 = "platform_name:'Windows'"
FILTER2 = "platform_name:'Mac'"
FILTER3 = "platform_name:'Linux'"

falcon = Hosts(client_id=os.environ["FALCON_CLIENT_ID"],
               client_secret=os.environ["FALCON_CLIENT_SECRET"],
               base_url=BASE,
               member_cid=CHILD)



@app.route('/compare_time_stamps', methods=['GET', 'POST'])
def compare_time_stamps():
    if request.method == 'GET':
        return render_template('index.html')

    # Get uploaded files
    jamf = request.files.get('jamf')
    jumpcloud = request.files.get('jumpcloud')
    intune = request.files.get('intune')

    # Read CSV data from uploaded files
    jamf_data = [row for row in csv.DictReader(jamf.read().decode('utf-8').splitlines())] if jamf else None
    jumpcloud_data = [row for row in csv.DictReader(jumpcloud.read().decode('utf-8').splitlines())] if jumpcloud else None
    intune_data = [row for row in csv.DictReader(intune.read().decode('utf-8').splitlines())] if intune else None

    # Get all device serial numbers for the CID and their last_seen timestamp
    serial_numbers = {}
    for filter in (FILTER1, FILTER2, FILTER3):
        offset = 0
        total = 1
        limit = 5000
        while offset < total:
            offset, total, devices = device_list(offset, limit, SORT, filter)
            details = device_detail(devices)
            for detail in details:
                last_seen = detail['last_seen']
                last_seen_readable = parse_crowdstrike_timestamp(last_seen)
                serial_numbers[detail['serial_number']] = last_seen_readable

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

    fig = make_subplots(rows=1, cols=2, specs=[[{}, {'type': 'domain'}]], subplot_titles=("Days Since Last Seen", "Not Found by Platform"))

    # Create stacked bar chart with pre-calculated counts for each bin
    for source in ['MDM', 'Crowdstrike']:
        for platform, days_since_by_source in data_by_platform.items():
            counts = [sum(lower <= d <= upper for d in days_since_by_source[source]) for lower, upper in bins]
            name = f"{platform} - {source}"
            legendgroup = f"{platform}-{source}"
            fig.add_trace(go.Bar(x=bin_labels, y=counts, name=name, legendgroup=legendgroup), row=1, col=1)

    fig.update_layout(barmode='stack')  # Stacked bar chart

    # Pie chart for not found systems by platform
    fig.add_trace(go.Pie(labels=list(not_found_by_platform.keys()), values=list(not_found_by_platform.values()), name="Not Found by Platform", legendgroup="Not Found"), row=1, col=2)

    fig.update_layout(title='Days Since Last Seen and Not Found Systems by Platform', showlegend=True)

    return fig



if __name__ == '__main__':
    app.run(port=8040)
