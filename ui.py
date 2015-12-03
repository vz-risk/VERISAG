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
import copy
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


def build_graph(api_args):
    global data, cache, analysis

    # the '-' causes problems in file names so '_' used instead.  Change it back here to query valid VERIS data.
    if api_args['worry'] == "pattern.Cyber_Espionage":
        api_args['worry'] = "pattern.Cyber-Espionage"

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

    return ATK


def parse_args(args):
    api_args = dict()
    api_args['worry'] = args['worry']
    api_args['attributes'] = args.getlist('attributes')
    """
    self.api_parser = api_parser
    api_args = self.api_parser.parse_args()
    """  # F the parser.  didn't work at all
    logging.info("Parsed arguments: {0}".format(api_args))

    return api_args


def parse_attributes(api_args):
    error = ""  # if anything put in this string, it will be printed instead of the output.

    if "Everything" in api_args['attributes'] or "" in api_args['attributes']:
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

        # Ensure there is some overlap between src & actions and dst and attributes.  Otherwise shortest path will error.  If no overlap, handle it.
        # Handle if the none of the requested actions or attributes aren't even in the graph
        if attributes is not None:
            attributes = set(attributes).intersection(set(ATK.g.nodes()))
            if not len(attributes) > 0:
                error = "The attribute to protect was not in the graph to be analyzed."

    return attributes, error


# Initialize the API class
# Analyze all actors
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

        api_args = parse_args(request.args)

        #analysis = V2AG.attack_graph_analysis.analyze()  # should already be assigned
        # Subset the data based on 'worries'
        # check cache
        if api_args['worry'] in cache:
            logging.info("Cache hit. Retrieving attack graph.")
            ATK = cache[api_args['worry']]
        #cache miss
        elif data is not None:
            logging.info("Cache miss.  Building attack graph.")
            ATK = build_graph(api_args)

        else:
            raise LookupError("Graph not cached and no data exists to build graph from.")

        # correct the attributes list (remove aggregations)
        attributes, error = parse_attributes(api_args)

        # Do the analysis
        if not error:
            logging.info("Doing all actors analysis.")
            
            node_to_mitigate, removed_paths, paths, after_paths, before_score, after_score = analysis.one_graph_multiple_paths(ATK.g, dst=attributes, output="return")

            logging.debug("Removed paths: {0}".format(len(removed_paths)))
            logging.debug("Paths: {0}".format(len(paths)))
            logging.debug("Difference: {0}".format(len(set(paths.keys()).difference(set(removed_paths)))))

            # Format the data for output
            logging.info("Formatting the output.")
            analyzed = dict()
            analyzed['error'] = list(error)
            analyzed['controls'] = node_to_mitigate
            # below if/then handles if all paths were removed by mitigating node_to_mitigate
            if len(removed_paths) - len(paths.keys()) != 0:
                analyzed['removed_paths'] = round(len(removed_paths)/float(len(paths)) * 100, 1)
                analyzed['dist_increase'] = round((after_score - before_score)/before_score * 100, 1)
            else:
                analyzed['removed_paths'] = 100
                analyzed['dist_increase'] = 0

            # Calculate mitigated path distances and add to return dictionary
            logging.info("Beginning path analysis.")
            mitigated_paths = after_paths

            path_lengths = dict()
            for key, path in mitigated_paths.iteritems():
    #            logging.debug("src/dst: {0}\npath: {1}".format(key, path))
                if path:
                    path_lengths["{0}->{1}".format(key[0], key[1])] = analysis.helper.path_length(ATK.g, path)[1]
                else:
                    path_lengths["{0}->{1}".format(key[0], key[1])] = 0
                    logging.info("Attack path {0} with path {1} had a length of 0.  This could be an issue.".format(key, path))

            for key in set(analysis.helper.shortest_attack_paths(ATK.g).keys()).difference(set(mitigated_paths.keys())):
                path_lengths["{0}->{1}".format(key[0], key[1])] = 0

            analyzed['path_lengths'] = path_lengths

        else:
            logging.error("Error detected: {0}".format(error))
            analyzed = {'error': error}

        logging.info("Returning results.")
        return analyzed


# Analyze Likely Actor
class analyze2(Resource):
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

        api_args = parse_args(request.args)

        #analysis = V2AG.attack_graph_analysis.analyze()  # should already be assigned
        # Subset the data based on 'worries'
        # check cache
        if api_args['worry'] in cache:
            logging.info("Cache hit. Retrieving attack graph.")
            DBIRAG = cache[api_args['worry']]
        #cache miss
        elif data is not None:
            logging.info("Cache miss.  Building attack graph.")
            DBIRAG = build_graph(api_args)

        else:
            raise LookupError("Graph not cached and no data exists to build graph from.")

        # correct the attributes list (remove aggregations)
        attributes, error = parse_attributes(api_args)

        if not error:
            analyzed = {"likely_actor":{}}

            # Ensure edge weights are populated
            DBIRAG.g = DBIRAG.normalize_weights(DBIRAG.g)

            # Best Nodes to Mitigate and Relative Change (from  blog)
            # Initialize Variables
            shortest_path_lengths = list()
            shortest_paths = list()
            mitigations = ["No Mitigation"]
            action="start"
            attribute = "end"
            cutoff = 6
            done = False
            g_copy = copy.deepcopy(DBIRAG.g)
            l = 1

            logging.info("Starting best mitigations analysis for likely actor analysis.")
            # Run LookupError
            try:
                path = nx.dijkstra_path(g_copy,action,attribute,'weight')
                p = path[0]
                for node in path[1:]:
                    p = p + " -> " + node
                shortest_paths.append(p)
            except nx.NetworkXNoPath:
                done = True
                shortest_paths.append("No paths left.")
                shortest_path_lengths.append(0)

            while not done:
                # since as you remove paths, the paths will get longer, the cutoff needs to be continuously increased
                if len(path) != l:
                    l = len(path)
                    #print(l)

                if len(path) > 4:
                    cutoff = len(path) + 2

                # get shortest path and add to distrubion
                _, length = analysis.helper.path_length(g_copy, path)
                shortest_path_lengths.append(length)

                #Mitigate a node
                direct, nodes = analysis.one_graph_one_path(g_copy, action, attribute, cutoff=cutoff, output="return")
                if direct:
                    g_copy.remove_edge(action, attribute)
                    mitigations.append("{0}->{1}".format(action, attribute))
                else:
                    node_to_mitigate = nodes.pop()
                    g_copy.remove_node(node_to_mitigate)
                    mitigations.append(node_to_mitigate)

                # retest
                try:
                    path = nx.dijkstra_path(g_copy,action,attribute,'weight')

                    # Add the path to the output list 'shorest_paths' as a string
                    p = path[0]
                    for node in path[1:]:
                        p = p + " -> " + node
                    shortest_paths.append(p)

                except nx.NetworkXNoPath:
                    done = True
                    shortest_paths.append("No paths left.")
                    shortest_path_lengths.append(0)

            logging.info("Analysis finished.  Formatting output.")

            shortest_path_lengths = [x - 2 for x in shortest_path_lengths]  # subtract off the start and end lengths

            l_no_mitigation = shortest_path_lengths[0]
            normalized_shortest_path_lengths = [x/float(l_no_mitigation) - 1 for x in shortest_path_lengths]  # divide by shortest lengths and subtract 1 to see percent improvement

#            for i in range(len(shortest_path_lengths)):
#                try:
#                    analyzed["likely_actor"]["mitigations"].append((mitigations[i], shortest_paths[i], shortest_path_lengths[i]))
#                except:
#                    logging.error(mitigations)
#                    logging.error(shortest_path_lengths)
#                    logging.error(shortest_paths)
#                    raise
            logging.debug("mark 1")
            # format the output for nvd3
            analyzed["likely_actor"]["chart"] = {u'enabled': True, u'key': u'Mitigations', u'values': list()}
            analyzed["likely_actor"]["shortest_paths"] = dict()
            logging.debug("mark 2")

            for i in range(len(shortest_path_lengths)-1):
                analyzed["likely_actor"]["chart"][u'values'].append({u'name': mitigations[i], u'x': i, u'y': normalized_shortest_path_lengths[i]})
                analyzed["likely_actor"]["shortest_paths"][shortest_paths[i]] = shortest_path_lengths[i]

            logging.debug("mark 3")
            # include the last mitigations
            analyzed["likely_actor"]["last_mitigation"] = mitigations[-1]

            logging.info("likely actor analysis complete.")

        else:
            logging.error("Error detected: {0}".format(error))
            analyzed = {'error': error}

        logging.info("Returning results.")
        return analyzed


# Analyze Comparison
class analyze3(Resource):
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

        api_args = parse_args(request.args)

        #analysis = V2AG.attack_graph_analysis.analyze()  # should already be assigned
        # Subset the data based on 'worries'
        # check cache
        if api_args['worry'] in cache:
            logging.info("Cache hit. Retrieving attack graph.")
            DBIRAG = cache[api_args['worry']]
        #cache miss
        elif data is not None:
            logging.info("Cache miss.  Building attack graph.")
            DBIRAG = build_graph(api_args)

        else:
            raise LookupError("Graph not cached and no data exists to build graph from.")

        # Remove any dividers if selected
        mitigations1 = list(set(api_args["mitigations1"]).difference(set(["-"])))
        mitigations2 = list(set(api_args["mitigations2"]).difference(set(["-"])))

        # Calculate paths for unmitigated graph
        pass #TODO: all actors paths
        pass #TODO: likely actor path

        # Calculate paths for mitigations1 graph
        pass #TODO: Remove mitigated nodes from graph
        pass #TODO: all actors paths
        pass #TODO: likely actor path

        # Calculate paths for mitigations2 graph
        pass #TODO: Remove mitigated nodes from graph
        pass #TODO: all actors paths
        pass #TODO: likely actor path

        # Compare the mitigations
        pass #TODO

        # Return the comparison


class paths(Resource):
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

        error = ""  # if anything put in this string, it will be printed instead of the output.

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
            # the '-' causes problems in file names so '_' used instead.  Change it back here to query valid VERIS data.
            if api_args['worry'] == "pattern.Cyber_Espionage":
                api_args['worry'] = "pattern.Cyber-Espionage"

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

        logging.info("Beginning path analysis.")
        paths = analysis.helper.shortest_attack_paths(ATK.g)
        path_lengths = dict()
        for key, path in paths.iteritems():
#            logging.debug("src/dst: {0}\npath: {1}".format(key, path))
            if path:
                path_lengths["{0}->{1}".format(key[0], key[1])] = analysis.helper.path_length(ATK.g, path)[1]
            else:
                path_lengths["{0}->{1}".format(key[0], key[1])] = 0

        return path_lengths


# Set up the API
api = Api(app)
api.add_resource(analyze, '/analyze/')
api.add_resource(analyze2, '/analyze_likely_actor/')
api.add_resource(analyze3, '/analyze_comparison/')
api.add_resource(paths, '/paths/')

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
