#!/usr/bin/env python

from flask import Flask, render_template, redirect, url_for, request, session
from functools import wraps
from pandas import DataFrame
import pandas as pd
import json
import http.client
import base64
import plotly
import os

app = Flask(__name__)
app.secret_key = os.urandom(256)

graphable_list = ['FLOAT', 'INTEGER', 'LONG', 'DOUBLE']
stream_filters = "cval, bat, tmp, temperature, temp1/val"


def RMGet(username, password, url):
    # create HTTP basic authentication string, this consists of
    # "username:password" base64 encoded
    bauth = base64.encodestring(('%s:%s' % (username, password)).encode())[:-1]
    auth = str(bauth)[2:-1]
    webservice = http.client.HTTPSConnection("remotemanager.digi.com")

    # to what URL to send the request with a given HTTP method
    webservice.putrequest("GET", url)

    # add the authorization string into the HTTP header
    webservice.putheader("Authorization", "Basic %s" % auth)

    webservice.endheaders()

    # get the response
    response = webservice.getresponse()
    statuscode = response.status
    statusmessage = response.reason
    response_body = response.read()

    # print the output to standard out
    # print((statuscode, statusmessage))
    # print(response_body)
    if statuscode == 200 and statusmessage == 'OK':
        return response_body
    else:
        return "error"


def get_full_inventory(username, password, url):
    raw_json = RMGet(username, password, url)
    raw_inventory = json.loads(raw_json)
    inventory_list = raw_inventory['list']
    while 'next_uri' in raw_inventory:
        raw_json = RMGet(username, password, raw_inventory['next_uri'])
        raw_inventory = json.loads(raw_json)
        inventory_list = inventory_list + (raw_inventory['list'])
        print (len(inventory_list))
    print ("while loop finished")
    streams_df = DataFrame(inventory_list)
    return streams_df


def parsed_devices_inventory(raw_json):
    devices_data = json.loads(raw_json)
    devices_df = DataFrame(devices_data['list'])
    if 'description' in devices_df.columns:
        devices_df.description.fillna(devices_df.id, inplace=True)
    else:
        devices_df['description'] = devices_df['id']
    devices_df['DisplayName'] = devices_df['description'] + ' - ' + devices_df['id']
    return devices_df['DisplayName'].values.tolist()


def all_streams_frame(streams_df, Desc_DeviceID, stream_filter):
    Desc_DeviceID = Desc_DeviceID[-35:]
    stream_filter = stream_filter.replace(', ', '|')
    streams_df = streams_df.loc[streams_df['id'].str.contains(stream_filter)]
    streams_df['DeviceID'] = streams_df['id'].str[:35]
    streams_df['Stream'] = '<a href="' + streams_df['history_uri'] + '">' + streams_df['id'].str[36:] + '</a>'
    streams_df = streams_df.loc[streams_df['DeviceID'].str.contains(Desc_DeviceID)]
    streams_df = streams_df.filter(['Stream', 'value', 'units', 'timestamp'], axis=1)
    streams_df.set_index('Stream', inplace=True)
    pd.set_option('display.max_colwidth', 512)
    data = streams_df.to_html(escape=False, classes='table table-hover table-bordered')
    pd.set_option('display.max_colwidth', 50)
    return data


def process_history(raw_json):
    history_json = json.loads(raw_json)
    history_df = DataFrame(history_json['list'])
    return history_df.filter(['timestamp', 'value', 'units'], axis=1)


# login required decorator
def login_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            # flash('You need to login first.')
            return redirect(url_for('home'))
    return wrap


@app.route('/logout')
@login_required
def logout():
    session.pop('logged_in', None)
    session.pop('username', None)
    session.pop('password', None)
    # flash('You were logged out.')
    return redirect(url_for('home'))


# route for handling the login page logic
@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        session['username'] = request.form['username']
        session['password'] = request.form['password']
        login_process = RMGet(session['username'], session['password'], '/ws/v1/devices/inventory.json')
        if login_process == 'error':
            return redirect(url_for('home'))
        session['logged_in'] = True
        return redirect(url_for('devices'))
    return render_template('login.html')


@app.route('/devices', methods=['GET', 'POST'])
@login_required
def devices():
    if request.method == 'POST':
        Desc_DeviceID = request.form['Desc_DeviceID']
        stream_filter = request.form['stream_filter']
        streams_inventory_json = get_full_inventory(session['username'], session['password'], '/ws/v1/streams/inventory.json')
        streams_list = all_streams_frame(streams_inventory_json, Desc_DeviceID, stream_filter)
        Desc = Desc_DeviceID[:-38]
        return render_template('table.html', tables=[streams_list], heading=Desc, title='DataStreams:')

    devices_inventory_json = RMGet(session['username'], session['password'], '/ws/v1/devices/inventory.json')
    devices_list = parsed_devices_inventory(devices_inventory_json)
    return render_template("devices.html",
                           title='Select your device:',
                           devices_list=devices_list,
                           stream_filters=stream_filters)


@app.route('/ws/v1/streams/history/<path:stream_url>')
@login_required
def stream_history(stream_url):
    get_stream_type_raw = RMGet(session['username'], session['password'], '/ws/v1/streams/inventory/' + stream_url + '.json')
    get_stream_type_json = json.loads(get_stream_type_raw)
    history_stream_json = RMGet(session['username'], session['password'], '/ws/v1/streams/history/' + stream_url + '.json?order=desc')
    history_table = process_history(history_stream_json)
    if 'timestamp' not in history_table:
        return render_template('nodata.html')
    elif get_stream_type_json['type'] in graphable_list:
        graphs = [
            dict(
                data=[
                    dict(
                        x=(history_table['timestamp']),
                        y=(history_table['value'])
                    )
                ]
            )
        ]

        # Add "ids" to each of the graphs to pass up to the client
        # for templating
        ids = ['graph-{}'.format(i) for i, _ in enumerate(graphs)]

        # Convert the figures to JSON
        # PlotlyJSONEncoder appropriately converts pandas, datetime, etc
        # objects to their JSON equivalents
        graphJSON = json.dumps(graphs, cls=plotly.utils.PlotlyJSONEncoder)

        return render_template('graph.html',
                               ids=ids,
                               graphJSON=graphJSON,
                               heading='DataStream:',
                               title=stream_url)

    else:
        history_table.set_index('timestamp', inplace=True)
        pd.set_option('display.max_colwidth', 512)
        history_table_html = history_table.to_html(escape=False, classes='table table-hover table-bordered')
        pd.set_option('display.max_colwidth', 50)
        return render_template('table.html', tables=[history_table_html], heading='DataStream:', title=stream_url)


if __name__ == "__main__":
    app.run()
