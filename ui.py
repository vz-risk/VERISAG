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
FILTERS = "./filter.txt"
CACHE = "./static"
DATA = None

########### NOT USER EDITABLE BELOW THIS POINT #################


## IMPORTS
import argparse
import ConfigParser
from flask import Flask, jsonify, render_template, request
from flask.ext.restful import reqparse, Resource, Api, abort
import pandas as pd
import imp
import pprint
from inspect import getmembers
import glob
import networkx as nx
import os

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
            DATA = config.get('APPLICATION', 'data_file')
        if 'filters' in config.options('APPLICATION'):
            DATA = config.get('APPLICATION', 'filters')

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
if args.filters is not None:
    FILTERS = args.filters

# Set up Heroku port
PORT = int(os.environ.get("PORT", PORT))


## GLOBAL EXECUTION
# Import the data
if DATA is not None:
    logging.info("Importing data.")
    data = pd.read_csv(DATA)
    logging.info("Data import complete.")

# build cache
logging.info("Populating Cache.")
cache = dict()
for filename in glob.glob(CACHE.rstrip("/") + "/*.graphml"):
    #logging.debug("Filename: {0}".format(filename))
    ATK = V2AG.attack_graph(None, FILTERS)
    ATK.g = nx.read_graphml(filename)
    cache[filename.rstrip("graphml").rstrip(".").split("/")[-1]] = ATK
logging.debug("Cached graphs are {0}".format(cache.keys()))
logging.info("Cache population complete.")

## FUNCTION DEFINITION
# Set up the app
app = Flask(__name__)

# define the API
# Initialize the arguements
api_parser = reqparse.RequestParser()
api_parser.add_argument('worry', type=str, help="Pattern or Industry used to subset the data.", default='all', location='args')
api_parser.add_argument('attributes', type=str, action='append', help="Filter paths to a subset of attributes.", default='Everything', location='args')

# Initialize the API class
class analyze(Resource):
    api_parser = None
    data = None
    cache = None

    def __init__(self):
        global data, cache, analysis
        self.data = data
        self.cache = cache


    def get(self):
        logging.info("Request Received")
        logging.debug("Request argument string: {0}".format(request.args))
        api_args = dict()
        api_args['worry'] = request.args['worry']
        api_args['attributes'] = request.args.getlist('attributes')
        """
        self.api_parser = api_parser
        api_args = self.api_parser.parse_args()
        """  # F the parser.  didn't work at all
        logging.info("Parsed arguments: {0}".format(api_args))

        analysis = V2AG.attack_graph_analysis.analyze()
        # Subset the data based on 'worries'
        # check cache
        if api_args['worry'] in cache:
            logging.info("Cache hit. Retrieving attack graph.")
            ATK = cache[api_args['worry']]
        #cache miss
        elif data is not None:
            logging.info("Cache miss.  Building attack graph.")
            # if we're not using the entire data set, subset it.
            if api_args['worry'] == 'all':
                query_data = data
            else:
                # handle patterns
                if api_args['worry'][:7] == "pattern":
                    query_data = data[data[api_args['worry']] == True]
                # handle naics codes
                else:
                    naics_codes = api_args['worry'].split(",")
                    query_data = data[(int(naics_codes[0]) <= data["victim.industry2"]) & (data["victim.industry2"] <= int(naics_codes[1]))]

            # Create the attack graph
            ATK = V2AG.attack_graph(None, FILTERS)
            ATK.build(data=query_data)
            cache[api_args['worry']] = ATK

        else:
            raise LookupError("Graph not cached and no data exists to build graph from.")

        # Do the analysis
        logging.info("Doing the analysis.")
        if api_args['attributes'] is "Everything":
            attributes = None
        else:
            attributes = api_args['attributes']
            # add in the aggregate groups
            if "Availability" in attributes:
                attributes = list(set(attributes).union(set([
                    "attribute.availability.variety.Destruction",
                    "attribute.availability.variety.Loss",
                    "attribute.availability.variety.Interruption",
                    "attribute.availability.variety.Degradation",
                    "attribute.availability.variety.Acceleration",
                    "attribute.availability.variety.Obscuration",
                    "attribute.availability.variety.Other"
                ])))
            if "Confidentiality" in attributes:
                attributes = list(set(attributes).union(set([
                    "attribute.confidentiality.data.variety.Credentials",
                    "attribute.confidentiality.data.variety.Bank",
                    "attribute.confidentiality.data.variety.Classified",
                    "attribute.confidentiality.data.variety.Copyrighted",
                    "attribute.confidentiality.data.variety.Digital certificate",
                    "attribute.confidentiality.data.variety.Medical",
                    "attribute.confidentiality.data.variety.Payment",
                    "attribute.confidentiality.data.variety.Personal",
                    "attribute.confidentiality.data.variety.Internal",
                    "attribute.confidentiality.data.variety.Source code",
                    "attribute.confidentiality.data.variety.System",
                    "attribute.confidentiality.data.variety.Secrets",
                    "attribute.confidentiality.data.variety.Virtual currency",
                    "attribute.confidentiality.data.variety.Other"
                ])))
            if "Integrity" in attributes:
                attributes = list(set(attributes).union(set([
                    "attribute.integrity.variety.Created account",
                    "attribute.integrity.variety.Defacement",
                    "attribute.integrity.variety.Hardware tampering",
                    "attribute.integrity.variety.Alter behavior",
                    "attribute.integrity.variety.Fraudulent transaction",
                    "attribute.integrity.variety.Log tampering",
                    "attribute.integrity.variety.Repurpose",
                    "attribute.integrity.variety.Misrepresentation",
                    "attribute.integrity.variety.Modify configuration",
                    "attribute.integrity.variety.Modify privileges",
                    "attribute.integrity.variety.Modify data",
                    "attribute.integrity.variety.Software installation",
                    "attribute.integrity.variety.Other"
                ])))
            # Remove the dash
            attributes = list(set(attributes).difference(set(["-"])))

        node_to_mitigate, removed_paths, paths, before_score, after_score = analysis.one_graph_multiple_paths(ATK.g, dst=attributes, output="return")

        # Format the data for output
        logging.info("Formatting the output.")
        analysis = dict()
        analysis['controls'] = node_to_mitigate
        analysis['removed_paths'] = round(len(removed_paths)/float(len(paths)) * 100, 1)
        analysis['dist_increase'] = round((after_score - before_score)/before_score * 100, 1)
        
        '''
        # TODO: Remove below line
        analysis = {"controls": "Nuke it from orbit.",
                    "removed_paths": 50,
                    "dist_increase": 50
                   }  # TODO: Replace this default data
        '''
        logging.info("Returning results.")
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
