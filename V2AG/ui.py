#!/usr/bin/env python
"""
 AUTHOR: Gabriel Bassett
 DATE: <01-23-2015>
 DEPENDENCIES: <a list of modules requiring installation>
 Copyright 2015 Gabriel Bassett

 LICENSE:
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.

 DESCRIPTION:
 <A description of the software>

 NOTES:
 <No Notes>

 ISSUES:
 <No Issues>

 TODO:
 <No TODO>

"""
# PRE-USER SETUP
import logging

########### NOT USER EDITABLE ABOVE THIS POINT #################


# USER VARIABLES
LOCATION = "./"
CONFIG_FILE = "./verisag.cfg"
LOGLEVEL = logging.DEBUG
LOG = None
FLASK_DEBUG = True
HOST = '0.0.0.0'
PORT = 8080
VERISR = "~/dbir20150226.csv"
FILTERS = "./filter.txt"

########### NOT USER EDITABLE BELOW THIS POINT #################


## IMPORTS
import networkx as nx  # CHANGEME
import argparse
import ConfigParser
from flask import Flask, jsonify, render_template, request
from flask.ext.restful import reqparse, Resource, Api, abort
import pandas as pd
import imp

## SETUP
__author__ = "Gabriel Bassett"

# Load VERISAG module
fp, pathname, description = imp.find_module("V2AG", [LOCATION])
V2AG = imp.load_module("V2AG", fp, pathname, description)
analysis = V2AG.attack_graph_analysis.analyze()

# Parse Arguments (should correspond to user variables)
parser = argparse.ArgumentParser(description='This script processes a graph.')
parser.add_argument('-d', '--debug',
                    help='Print lots of debugging statements',
                    action="store_const", dest="loglevel", const=logging.DEBUG,
                    default=LOGLEVEL
                   )
parser.add_argument('-v', '--verbose',
                    help='Be verbose',
                    action="store_const", dest="loglevel", const=logging.INFO
                   )
parser.add_argument('--log', help='Location of log file', default=LOG)
parser.add_argument('--config', help='The location of the config file', default=CONFIG_FILE)
parser.add_argument('--host', help='ip address to use for hosting', default=None)
parser.add_argument('--port', help='port to host the app on', default=None)
parser.add_argument('--data_file', help='CSV file containing the verisr data.', default=None)
parser.add_argument('--filters', help='File containing one regex per line to filter. Ex. Environmental, Unknown, and Notes.', default=None)
args = parser.parse_args()

# add config arguments
CONFIG_FILE = args.config
try:
  config = ConfigParser.SafeConfigParser()
  config.readfp(open(CONFIG_FILE))
  config_exists = True
except:
  config_exists = False
if config_exists:
    if config.has_section('LOGGING'):
        if 'level' in config.options('LOGGING'):
            level = config.get('LOGGING', 'level')
            if level == 'debug':
                loglevel = logging.DEBUG
            elif level == 'verbose':
                loglevel = logging.INFO
            else:
                loglevel = logging.WARNING
        else:
            loglevel = logging.WARNING
        if 'log' in config.options('LOGGING'):
            log = config.get('LOGGING', 'log')
        else:
            log = None
    if config.has_section('SERVER'):
        #print 'config arules'  # DEBUG
        if 'host' in config.options('SERVER'):
            #print 'config rules'  # DEBUG
            HOST = config.get('SERVER', 'host')
        if 'port' in config.options('SERVER'):
            PORT = int(config.get('SERVER', 'port'))
    if config.has_section('APPLICATION'):
        if 'data_file' in config.options('APPLICATION'):
            DATA = config.et('APPLICATION', 'data_file')
        if 'filter' in config.options('APPLICATION'):
            DATA = config.et('APPLICATION', 'filters')

## Set up Logging
if args.log is not None:
    logging.basicConfig(filename=args.log, level=args.loglevel)
else:
    logging.basicConfig(level=args.loglevel)
if args.loglevel == logging.DEBUG:
    FLASK_DEBUG = True
if args.host is not None:
    HOST = args.host
if args.port is not None:
    PORT = int(args.port)
if args.data_file is not None:
    DATA = args.data_file
if args.filter is not None:
    FILTERS = args.filters


## GLOBAL EXECUTION
# TODO: Import the data
data = pd.read_csv(DATA)

cache = dict()

## FUNCTION DEFINITION
# Set up the app
app = Flask(__name__)

# define the API
# Initialize the arguements
api_parser = reqparse.RequestParser()
api_parser.add_argument('worries', type=int, help="Pattern or Industry used to subset the data.", default=None)
api_parser.add_argument('attributes', type=str, help="Filter paths to a subset of attributes.", default=None)

# Initialize the API class
class analyze(Resource):
    api_parser = None
    data = None

    def __init__(self):
    global data
    self.data = data

    def get(self):
        self.api_parser = api_parser
        api_args = self.api_parser.parse_args(strict=False)
        # Subset the data based on 'worries'
        # check cache
        if api_args['worry'] in cache:
            atk_graph = cache[api_args['worry']]
        #cache miss
        else:     
            # if we're not using the entire data set, subset it.
            if api_args['worry'] is 'all':
                query_data = data
            else:
                # handle patterns
                if api_args['worry'][:7] is "pattern":
                    query_data = data[data[api_args['worry']] == True]
                # handle naics codes
                else:
                    naics_codes = api_args['worry'].split(",")
                    query_data = data[(int(naics_codes[0] <= data["victim.industry2"]) & (data["victim.industry2"] <= int(naics_code[1]))]


        # Create the attack graph
        ATK = V2AG.attack_graph(None, FILTERS)
        ATK.build(data=query_data)

        # Do the analysis
        if api_args['attributes'] is None:
            attributes = None
        else:
            attributes = api_args['attributes'].split(",")
        node_to_mitigate, removed_paths, paths, before_score, after_score = analysis.one_graph_multiple_paths(ATK.g, dst=attributes)

        # Format the data for output
        analysis = dict()
        analysis['controls'] = node_to_mitigate
        analysis['removed_paths'] = round(len(removed_paths)/float(len(paths)) * 100, 1)
        analysis['dist_increase'] = round((after_score - before_score)/before_score * 100, 1)

        # TODO: Remove below line
        analysis = {"controls": "Nuke it from orbit.",
                    "removed_paths": 50,
                    "dist_increase ": 50
                   }  # TODO: Replace this default data

        return analysis

# Set up the API
api = Api(app)
api.add_resource(analyze, '/analyze/')

# Set up the GUI
@app.route("/")
def gui():
    return render_template('index.html')

## MAIN LOOP EXECUTION
def main():
    logging.info('Beginning main loop.')
    app.run(host=HOST, port=PORT, debug=FLASK_DEBUG)
    logging.info('Ending main loop.')

if __name__ == "__main__":
    main()