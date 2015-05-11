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
CONFIG_FILE = "./v2ag.cfg"
LOGLEVEL = logging.DEBUG
LOG = None
FLASK_DEBUG = True
HOST = '0.0.0.0'
PORT = 8080

########### NOT USER EDITABLE BELOW THIS POINT #################


## IMPORTS
from py2neo import neo4j, cypher  # CHANGEME
import networkx as nx  # CHANGEME
import argparse
import ConfigParser
from flask import Flask, jsonify, render_template, request
from flask.ext.restful import reqparse, Resource, Api, abort

## SETUP
__author__ = "Gabriel Bassett"

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


## GLOBAL EXECUTION
pass


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

    def get(self):
        self.api_parser = api_parser
        api_args = self.api_parser.parse_args(strict=False)
        # TODO: Subset the data based on 'worries'
        analysis = {"controls": "Nuke it from orbit.",
                    "removed_paths": 50,
                    "dist_increase ": 50
                   }  # TODO: Replace this default data

        # TODO: Pick a node to mitigate
        # TODO: calculate the impact
        # TODO: format the data for output

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