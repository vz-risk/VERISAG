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
#VERIS_DIRS = ["/Volumes/verizon/Customer and Partner Data/DBIR/data/1.3","/Users/v685573/Documents/Development/VCDB/data/json"]
#VERIS_DIRS = ["/Volumes/verizon/Customer and Partner Data/DBIR/data/1.3"]
#VERIS_DIRS = ["/Users/v685573/Documents/Development/VCDB/data/json"]
#VERIS_DIRS = "/Users/v685573/Documents/customer data/DBIR/data/dbir20150224-full.csv"
VERIS_DIRS = ['/Users/v685573/Documents/customer data/DBIR/data/1.3']
GENERAL_GRAPH = "/Users/v685573/Documents/Data/veris_attack_graph/dbir_Rev2_v2.graphml"
CONFIG_FILE = "/Users/v685573/Documents/Development/veris_attack_graph/veris_atk_graph.cfg"
#FILTER_WEIGHT = 0.2
LOGLEVEL = logging.DEBUG
LOG = None
FILTER = "/Users/v685573/Documents/Development/veris_attack_graph/filter.txt"

########### NOT USER EDITABLE BELOW THIS POINT #################


## IMPORTS
import networkx as nx 
import argparse
import ConfigParser
import os  # used for geting file lists for reading in
from itertools import combinations, product  # used for combining actions and attributes
import json  # used for reading VERIS
import re  # used for filters
import pandas as pd  # for reading data frames

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
# <add arguments here>
parser.add_argument('--conf', help='Config File', default=CONFIG_FILE)
parser.add_argument('--records', help='Comma separated list of directories containing json breach records.', default=None)
parser.add_argument('--general', help='File to save the general graph to.', default=GENERAL_GRAPH)
parser.add_argument('--filter', help='file with regexes, 1 per line, to filter out of action/attribute enumerations.', default=None)
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
    if config.has_section('GENERAL'):
        if 'veris_dirs' in config.options('GENERAL'):
            VERIS_DIRS = config.get('GENERAL', 'veris_dirs')
            VERIS_DIRS = map(lambda x: x.strip(), VERIS_DIRS.split(","))
        if 'general_graph' in config.options('GENERAL'):
            GENERAL_GRAPH = config.get('GENERAL', 'general_graph')
        if 'filter' in config.options('GENERAL'):
            FILTER = config.get('GENERAL', 'filter')
# <add additional config options here>

## Set up Logging
if args.log is not None:
    logging.basicConfig(filename=args.log, level=args.loglevel)
else:
    logging.basicConfig(level=args.loglevel)
# <add other setup here>
if args.records is not None:
    VERIS_DIRS = args.records
    VERIS_DIRS = map(lambda x: x.strip(), VERIS_DIRS.split(","))
GENERAL_GRAPH = args.general
if args.filter is not None:
    FILTER = args.filter



## GLOBAL EXECUTION
# Parse the FILTERs file into regexes
filters = list()
with open(FILTER, 'r') as f:
    for line in f:
        if line[0] is "#":
            continue
        line = line.strip()
        try:
            filters.append(re.compile(line))
        except:
            logging.warning("Regex {0} did not compile and was not added to the filters.".format(line))
            pass



## FUNCTION DEFINITION
def parse_json_record(record):
    actions = []
    attributes = []
    # Parse hacking actions
    try:
        for enum in record['action']['hacking']['variety']:
            actions.append('action.hacking.variety.{0}'.format(enum))
    except KeyError:
        pass
    # Parse malware actions
    try:
        for enum in record['action']['malware']['variety']:
            actions.append('action.malware.variety.{0}'.format(enum))
    except KeyError:
        pass
    try: 
        for enum in record['action']['malware']['vector']:
            actions.append('action.malware.vector.{0}'.format(enum))
    except KeyError:
        pass
    # Parse error actions
    '''
    try:
      for enum in record['action']['error']['variety']:
        actions.append('action.error.variety.{0}'.format(enum))
    except KeyError:
      pass
    '''
    # Parse evironmental actions
    try:
        for enum in record['action']['environmental']['variety']:
            actions.append('action.environmental.variety.{0}'.format(enum))
    except KeyError:
        pass
    # Parse misuse actions
    try:
        for enum in record['action']['misuse']['variety']:
            actions.append('action.misuse.variety.{0}'.format(enum))
    except KeyError:
        pass

    try:
        for enum in record['action']['physical']['variety']:
            actions.append('action.physical.variety.{0}'.format(enum))
    except KeyError:
        pass
    try:
        for enum in record['action']['social']['variety']:
            actions.append('action.social.variety.{0}'.format(enum))
    except KeyError:
        pass
    try:
        for enum in record['attribute']['availability']['variety']:
            attributes.append('attribute.availability.variety.{0}'.format(enum))
    except KeyError:
        pass
    try:
        for i in range(len(record['attribute']['confidentiality']['data'])):
    #            for enum in record['attribute']['confidentiality']['data'][i]['variety']:
            enum = record['attribute']['confidentiality']['data'][i]['variety']
            attributes.append('attribute.confidentiality.data.variety.{0}'.format(enum))
    except KeyError:
        pass
    try:
        for enum in record['attribute']['integrity']['variety']:
            attributes.append('attribute.integrity.variety.{0}'.format(enum))
    except KeyError:
        pass

    return actions, attributes


def filter_record(list_in):
    list_out = []
    for item in list_in:
        include = True
        for line in filters:
            if line.match(item) is not None:
                include = False
        if include:
            list_out.append(item)
        else:
            logging.debug("Filtered out {0}.".format(item))
    return list_out


def get_or_create_nodes_and_edge(g, src, dst, edge_count=1):
    # if the source node doesn't exist, create it.  Otherwise, incriment it's counter.
    src_split = src.split(".", 2)
    if not g.has_node(src):
        properties = {
            'type': src_split[0],
            'sub_type': ".".join(src_split[0:2]),
            'count': 1,
            'Label': src
        }
        g.add_node(src, attr_dict=properties)
    else:
        g.node[src]['count'] += 1
    # if the destination node doesn't exist, create it.  Otherwise, incriment it's counter.
    dst_split = dst.split(".", 2)
    if not g.has_node(dst):
        properties = {
            'type': dst_split[0],
            'sub_type': ".".join(dst_split[0:2]),
            'count': 1,
            'Label': dst
        }
        g.add_node(dst, attr_dict=properties)
 #   else:
 #       g.node[dst]['count'] += 1
    # If the edge doesn't exist, create it.  Otherwise, incriment it's counter.
    if not g.has_edge(src, dst):
        # calculate the direction. forward unless from attribute to action
        if src_split[0] == 'attribute' and dst_split[0] == 'action':
            direction = 'backward'
        else:
            direction = 'forward'
        properties = {
            'direction': direction,
            'count': edge_count,
            'Label': "{0}->{1}".format(src, dst)
        }
        g.add_edge(src, dst, attr_dict=properties)
    else:
        g.edge[src][dst]['count'] += edge_count



def add_record_to_graph(g, actions, attributes, base_mappings):
    '''
    In the second pass:
    1. If collect action-attribute relationships
    2. If an action-attribute relationship exists in the base_mappings, add it to the attack graph and remove it from the relationships list
    3. If an action-attribute relationship is not in the base_mapping, delete it
    4. If actions are left with no mapping to an attribute, map them directly to all actions which did have a mapping to attributes
    5. if two actions and two attributes exist in the graph, create backwards mappings from the attributes to the actions they were not mapped to.  # TODO: Improve this

    Other Accounting:
    - Create node type
    - Create node sub-type
    - Create relationship direction (forward/backward)
    - Create node label (to make gephi happy)
    - Iterate edge count
    - Iterate node count
    '''

    # filter unwanted stuff
    actions = filter_record(actions)
    attributes = filter_record(attributes)

    # create sets
    paired_actions = set()  # for step 4
    act_att_pairs = set()  # for step 5
    # 1
    for action, attribute in product(actions, attributes):
        # 2
        if base_mappings.has_edge(action, attribute):
            get_or_create_nodes_and_edge(g, action, attribute)
            act_att_pairs.add((action, attribute))
            paired_actions.add(action)
        # 3
        elif action.split(".", 1)[0] == "action" and attribute.split(".", 1)[0] == "attribute":
            pass  # Ignore it
    # 4
    unpaired_actions = set(actions).difference(paired_actions)
    for src, dst in product(unpaired_actions, paired_actions):
        get_or_create_nodes_and_edge(g, src, dst)
    # 5
    for a, b in combinations(act_att_pairs, 2):
        get_or_create_nodes_and_edge(g, a[1], b[0])  # 1 = attribute, 0 = action
        get_or_create_nodes_and_edge(g, b[1], a[0])
    # incriment node counters
    for enum in actions + attributes:
        enum_split = enum.split(".", 2)
        if not g.has_node(enum):
            properties = {
                'type': enum_split[0],
                'sub_type': ".".join(enum_split[0:2]),
                'count': 1,
                'Label': enum
            }
            g.add_node(enum, attr_dict=properties)
        else:
            g.node[enum]['count'] += 1



## MAIN LOOP EXECUTION
def main():
    global VERIS_DIRS

    logging.info('Beginning main loop.')
    logging.info("Initialize the graphs")
    g = nx.DiGraph()

    logging.info('Read in VERIS data')
    # assume this is a CSV file and parse it in as a dataframe
    if type(VERIS_DIRS) == str and VERIS_DIRS.split(".")[-1] == "csv":
        data = pd.read_csv(VERIS_DIRS)
        data_type = "dataframe"
    # if it's not a CSV, assume it's supposed to be a directory or list of directories full of JSON
    else:
        if type(VERIS_DIRS) == str:
            VERIS_DIRS = [VERIS_DIRS]
        # Read in JSON files
        json_files = []
        for path in VERIS_DIRS:
            json_files += [os.path.join(dirpath, f) for dirpath, dirnames, files in os.walk(path) for f in files if f.endswith('.json')]
        # set data type so we use the correct parsing engine
        data_type = "json"

    if data_type == "json":
        # First pass.  single action-attribute linkage
        '''
        In the first pass, we only want records where a single action-attribute mpaping exists.  We will use these as the filter for the next pass
        '''
        logging.info('Beginning first pass.')
        base_mappings = nx.DiGraph()
        for F in json_files:
            with open(F, 'r') as f:
                actions, attributes = parse_json_record(json.load(f))
                # filter unwanted stuff
                actions = filter_record(actions)
                attributes = filter_record(attributes)
                if len(actions) == 1:
                    # create  mapping
                    for attribute in attributes:
                        base_mappings.add_edge(actions[0], attribute)


        logging.info('Beginning second pass.')
        # Second Pass
        for F in json_files:
            with open(F, 'r') as f:
                actions, attributes = parse_json_record(json.load(f))
                add_record_to_graph(g, actions, attributes, base_mappings)

    elif data_type == "dataframe":
        # get rows to filter from records
        act_regex = re.compile("^action\.(malware\.vector|((hacking|error|environmental|misuse|physical|social|malware)\.variety))")
        act_cols = [l for l in data.columns for m in [act_regex.search(l)] if m]  # returns action columns
        att_regex = re.compile("^attribute\.(confidentiality\.data|integrity|availability)\.variety")
        att_cols = [l for l in data.columns for m in [att_regex.search(l)] if m]  # returns action columns
        # First pass
        logging.info('Beginning first pass.')
        for index, record in data.iterrows():
            raise ValueError("Dataframe parsing not yet implemented.")
            actions = list(record.where(record[act_cols] == True).dropna().index)
            attributes = list(record.where(record[att_cols] == True).dropna().index)
            # filter unwanted stuff
            actions = filter_record(actions)
            attributes = filter_record(attributes)
            if len(actions) == 1:
                # create  mapping
                for attribute in attributes:
                    base_mappings.add_edge(actions[0], attribute)

        logging.info('Beginning second pass.')
        for index, row in data.iterrows():
            actions = list(record.where(record[act_cols] == True).dropna().index)
            attributes = list(record.where(record[att_cols] == True).dropna().index)
            add_record_to_graph(g, actions, attributes, base_mappings)

    else:
        raise ValueError("Data type not supported.")


    logging.info('Adding normalized weights')
    # normalize the node and edge weights
    # Normalize g edge weights to 0<x<=1
    # First pass sets max weight to 1 and adjusts all weights to maintain their distance from the max weight.
    weights = list()
    for edge in g.edges():
        weights.append(g.edge[edge[0]][edge[1]]['count'])
#    weights = [edge[2] for edge in g.edges_iter(data='weight', default=0)]
    max_weight = max(weights)
    for edge in g.edges():
        g.edge[edge[0]][edge[1]]['weight'] = 1 + (max_weight - g.edge[edge[0]][edge[1]]['count'])
#        g.edge[edge[0]][edge[1]]['weight'] = g.edge[edge[0]][edge[1]]['count'] / float(max_weight)
    # we now have the maximum value set to 1 and all other values the same distance from the max weight in the positive direction.  Now to normalize to 0<x<=1
    weights = list()
    for edge in g.edges():
        weights.append(g.edge[edge[0]][edge[1]]['weight'])
    max_weight = max(weights)
    for edge in g.edges():
        g.edge[edge[0]][edge[1]]['weight'] = g.edge[edge[0]][edge[1]]['weight'] / float(max_weight)

    # add node weights (follow same procedure used for edge weights)
    weights = list()
    for node in g.nodes():
        weights.append(g.node[node]['count'])
    max_weight = max(weights)
    for node in g.nodes():
        if node in g.nodes():
            g.node[node]['weight'] = 1 + (max_weight - g.node[node]['count'])
    weights = list()
    for node in g.nodes():
        weights.append(g.node[node]['weight'])
    max_weight = max(weights)
    for node in g.nodes():
        if node in g.nodes():
            g.node[node]['weight'] = g.node[node]['weight'] / float(max_weight)    

    logging.info('Adding start & end nodes')
    # create mapping from 'start' to actions and attributes to 'end'  # TODO: THIS IS NOT OPTIMAL. would be nice to get 'count' better as well as things we 'know' started a breach
    # create start and end nodes
    properties = {
        'type': 'start',
        'sub_type': 'start',
        'count': 0,
        'Label': 'start'
    }
    g.add_node('start', attr_dict=properties)
    properties = {
        'type': 'end',
        'sub_type': 'end',
        'count': 0,
        'Label': 'end'
    }
    g.add_node('end', attr_dict=properties)
    # Connect start and end to attribute and action nodes
    for node in g.nodes():
        if g.node[node]['type'] == 'action':
            get_or_create_nodes_and_edge(g, 'start', node)
        elif g.node[node]['type'] == 'attribute':
            get_or_create_nodes_and_edge(g, node, 'end')

    logging.info('Saving the graph.')
    nx.write_graphml(g, GENERAL_GRAPH)

    logging.info('Ending main loop.')

if __name__ == "__main__":
    main()
