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
VERIS_DIRS = "/Users/v685573/Documents/customer data/DBIR/data/dbir20150224-full.csv"
#VERIS_DIRS = ['/Users/v685573/Documents/customer data/DBIR/data/1.3']
GENERAL_GRAPH = "/Users/v685573/Documents/Data/veris_attack_graph/dbir_Rev2_v5.graphml"
CONFIG_FILE = "/Users/v685573/Documents/Development/veris_attack_graph/veris_atk_graph.cfg"
#FILTER_WEIGHT = 0.2
LOGLEVEL = logging.INFO
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
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='This script creates an attack graph from VERIS data.')
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
pass



## CLASS/FUNCTION DEFINITION
class attack_graph():
    g = None
    filter_file = None
    data_source = None
    filters = None
    data_type = None
    data = None # note, data will be the dataframe if source is Dataframe and will be the list of files if source is JSON
    base_mappings = None

    def __init__(self, data_source, filter_file=None, build=True):
        # create the filters
        self.filter_file = filter_file
        self.filters = self.create_filters()
        # Store the data source reference
        if data_source is None:
            build = False
            self.data_source = None
            self.data_type = None
        if type(data_source) == str and data_source.split(".")[-1] == "csv":
            self.data_type = 'dataframe'
            self.data_source = data_source
            self.data = pd.read_csv(VERIS_DIRS)
        elif type(data_source) == str:
            self.data_source = [data_source]
            self.data = []
            for path in self.data_source:
                self.data += [os.path.join(dirpath, f) for dirpath, dirnames, files in os.walk(path) for f in files if f.endswith('.json')]
            self.data_type = 'json'
        else:
            self.data_source = data_source
            self.data = []
            for path in self.data_source:
                self.data += [os.path.join(dirpath, f) for dirpath, dirnames, files in os.walk(path) for f in files if f.endswith('.json')]
            self.data_type = 'json'
        # build the graph if expected
        if build == True:
            self.build()


    def add_record_to_graph(self, actions, attributes):
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
        actions = self.filter_record(actions)
        attributes = self.filter_record(attributes)

        if len(actions) > 0 and len(attributes) > 0:
            # create sets
            paired_actions = set()  # for step 4
            act_att_pairs = set()  # for step 5
            # 1
            for action, attribute in product(actions, attributes):
                # 2
                if self.base_mappings.has_edge(action, attribute):
                    self.get_or_create_nodes_and_edge(action, attribute)
                    act_att_pairs.add((action, attribute))
                    paired_actions.add(action)
                # 3
                elif action.split(".", 1)[0] == "action" and attribute.split(".", 1)[0] == "attribute":
                    pass  # Ignore it
            # 4
            unpaired_actions = set(actions).difference(paired_actions)
            for src, dst in product(unpaired_actions, paired_actions):
                self.get_or_create_nodes_and_edge(src, dst)
            # 5
            for a, b in combinations(act_att_pairs, 2):
                self.get_or_create_nodes_and_edge(a[1], b[0])  # 1 = attribute, 0 = action
                self.get_or_create_nodes_and_edge(b[1], a[0])
            # incriment node counters
            for enum in set(actions).union(set(attributes)):
                enum_split = enum.split(".", 2)
                if not self.g.has_node(enum):
                    properties = {
                        'type': enum_split[0],
                        'sub_type': ".".join(enum_split[0:2]),
                        'count': 1,
                        'Label': enum
                    }
                    self.g.add_node(enum, attr_dict=properties)
                else:
                    self.g.node[enum]['count'] += 1


    def build(self):
        # Get the data
        if self.data_type == "json":
            logging.info('Creating list of JSON records.')
        elif self.data_type == "dataframe":
            logging.info('Reading in record data frame from csv.')
        self.read_data()

        # First pass.  single action-attribute linkage
        '''
        In the first pass, we only want records where a single action-attribute mpaping exists.  We will use these as the filter for the next pass
        '''
        logging.info('Beginning first pass.')
        if self.base_mappings is None:
            self.base_mappings = self.get_mappings()

        logging.info('Beginning second pass.')
        '''
        See the add_record_to_graph() function for the logic used in the second pass to build the attack graph.
        '''
        self.populate_graph()

        logging.info('Adding start & end nodes')
        # create mapping from 'start' to actions and attributes to 'end'  # TODO: THIS IS NOT OPTIMAL. would be nice to get 'count' better as well as things we 'know' started a breach
        # create start and end nodes
        properties = {
            'type': 'start',
            'sub_type': 'start',
            'count': 0,
            'Label': 'start'
        }
        self.g.add_node('start', attr_dict=properties)
        properties = {
            'type': 'end',
            'sub_type': 'end',
            'count': 0,
            'Label': 'end'
        }
        self.g.add_node('end', attr_dict=properties)
        # Connect start and end to attribute and action nodes
        for node in self.g.nodes():
            if self.g.node[node]['type'] == 'action':
                self.get_or_create_nodes_and_edge('start', node)
            elif self.g.node[node]['type'] == 'attribute':
                self.get_or_create_nodes_and_edge(node, 'end')

        logging.info('Adding normalized weights')
        self.g = self.normalize_weights(self.g)


        # correct start and end edges to 0 to prevent effects on path distances
        for node in self.g.successors('start'):
            self.g.edge['start'][node]
        for node in self.g.predecessors('end'):
            self.g.edge[node]['end']


    def create_filters(self):
        filters = list()
        if self.filter_file is not None:
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
        return filters


    def filter_record(self, list_in):
        list_out = []
        for item in list_in:
            include = True
            for line in self.filters:
                if line.match(item) is not None:
                    include = False
            if include:
                list_out.append(item)
            else:
                logging.debug("Filtered out {0}.".format(item))
        return list_out


    def get_mappings(self):
        base_mappings = nx.DiGraph()
        if self.data_type == 'json':
            for F in self.data:
                with open(F, 'r') as f:
                    actions, attributes = self.parse_json_record(json.load(f))
                    # filter unwanted stuff
                    actions = self.filter_record(actions)
                    attributes = self.filter_record(attributes)
                    if len(actions) == 1:
                        # create  mapping
                        for attribute in attributes:
                            base_mappings.add_edge(actions[0], attribute)
        elif self.data_type == 'dataframe':
            act_regex = re.compile("^action\.(malware\.vector|((hacking|error|environmental|misuse|physical|social|malware)\.variety))")
            act_cols = [l for l in self.data.columns for m in [act_regex.search(l)] if m]  # returns action columns
            att_regex = re.compile("^attribute\.(confidentiality\.data|integrity|availability)\.variety")
            att_cols = [l for l in self.data.columns for m in [att_regex.search(l)] if m]  # returns action columns

            for index, record in self.data.iterrows():
                actions = list(record.where(record[act_cols] == True).dropna().index)
                attributes = list(record.where(record[att_cols] == True).dropna().index)
                # filter unwanted stuff
                actions = self.filter_record(actions)
                attributes = self.filter_record(attributes)
                if len(actions) == 1:
                    # create  mapping
                    for attribute in attributes:
                        base_mappings.add_edge(actions[0], attribute)
        else:
            raise ValueError("Data type not supported.")

        return base_mappings


    def get_or_create_nodes_and_edge(self, src, dst, edge_count=1, attr_dict={}):
        # if the source node doesn't exist, create it.  Otherwise, incriment it's counter.
        src_split = src.split(".", 2)
        if not self.g.has_node(src):
            properties = {
                'type': src_split[0],
                'sub_type': ".".join(src_split[0:2]),
                'count': 1,
                'Label': src
            }
            self.g.add_node(src, attr_dict=properties)
        # if the destination node doesn't exist, create it.  Otherwise, incriment it's counter.
        dst_split = dst.split(".", 2)
        if not self.g.has_node(dst):
            properties = {
                'type': dst_split[0],
                'sub_type': ".".join(dst_split[0:2]),
                'count': 1,
                'Label': dst
            }
            self.g.add_node(dst, attr_dict=properties)
        #   else:
        #       g.node[dst]['count'] += 1
        # If the edge doesn't exist, create it.  Otherwise, incriment it's counter.
        if not self.g.has_edge(src, dst):
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
            # import properties manually
            for k, v in attr_dict.iteritems():
                properties[k] = v
            self.g.add_edge(src, dst, attr_dict=properties)
        else:
            self.g.edge[src][dst]['count'] += edge_count


    def normalize_weights(self, g, prop='count'):
        """ Takes a graph and uses the count attribute to add a 'weight' attribute that is the inverse of count normalized to 1.

            The reason for this appoach is that the new weight may be used in shortest path calculations.  Also, it should never be '0'.

        :param g: a networkx graph to reweight.  A 'weight' attribute is not necessary
        :param prop: the property to use to generate weights.  default is 'count'
        :return: a networkx graph with the weights added
        """
        # normalize the node and edge weights
        # Normalize g edge weights to 0<x<=1
        # First pass sets max weight to 1 and adjusts all weights to maintain their distance from the max weight.
        weights = list()
        for edge in g.edges():
            weights.append(g.edge[edge[0]][edge[1]][prop])
        #    weights = [edge[2] for edge in g.edges_iter(data='weight', default=0)]
        max_weight = max(weights)
        for edge in g.edges():
            g.edge[edge[0]][edge[1]]['weight'] = float(1 + (max_weight - g.edge[edge[0]][edge[1]][prop]))
        #        g.edge[edge[0]][edge[1]]['weight'] = g.edge[edge[0]][edge[1]]['count'] / float(max_weight)
        # we now have the maximum value set to 1 and all other values the same distance from the max weight in the positive direction.  Now to normalize to 0<x<=1
        weights = list()
        for edge in g.edges():
            weights.append(g.edge[edge[0]][edge[1]]['weight'])
        max_weight = max(weights)
        for edge in g.edges():
            g.edge[edge[0]][edge[1]]['weight'] = float(g.edge[edge[0]][edge[1]]['weight'] / float(max_weight))

        # add node weights (follow same procedure used for edge weights)
        weights = list()
        for node in g.nodes():
            weights.append(g.node[node][prop])
        max_weight = max(weights)
        for node in g.nodes():
            if node in g.nodes():
                g.node[node]['weight'] = float(1 + (max_weight - g.node[node][prop]))
        weights = list()
        for node in g.nodes():
            weights.append(g.node[node]['weight'])
        max_weight = max(weights)
        for node in g.nodes():
            if node in g.nodes():
                g.node[node]['weight'] = float(g.node[node]['weight'] / float(max_weight))
        return g

    def parse_json_record(self, record):
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


    def populate_graph(self):
        self.g = nx.DiGraph()
        if self.data_type == 'json':
            for F in self.data:
                with open(F, 'r') as f:
                    actions, attributes = self.parse_json_record(json.load(f))
                    self.add_record_to_graph(actions, attributes)
        elif self.data_type == 'dataframe':
            # get rows to filter from records
            act_regex = re.compile("^action\.(malware\.vector|((hacking|error|environmental|misuse|physical|social|malware)\.variety))")
            act_cols = [l for l in self.data.columns for m in [act_regex.search(l)] if m]  # returns action columns
            att_regex = re.compile("^attribute\.(confidentiality\.data|integrity|availability)\.variety")
            att_cols = [l for l in self.data.columns for m in [att_regex.search(l)] if m]  # returns action columns

            for index, record in self.data.iterrows():
                actions = list(record.where(record[act_cols] == True).dropna().index)
                attributes = list(record.where(record[att_cols] == True).dropna().index)
                self.add_record_to_graph(actions, attributes)
        else:
            raise ValueError("Data type not supported.") 


    def read_data(self):
        if self.data_type == 'dataframe':
            self.data = pd.read_csv(self.data_source)
        elif self.data_type == 'json':
            self.data = []
            for path in self.data_source:
                self.data += [os.path.join(dirpath, f) for dirpath, dirnames, files in os.walk(path) for f in files if f.endswith('.json')]
        else:
            raise ValueError("Data type not supported.")


    def save(self, filename):
        logging.info('Saving the graph.')
        nx.write_graphml(self.g, filename)


## MAIN LOOP EXECUTION
def main():
    atk = attack_graph(VERIS_DIRS, filter_file="/Users/v685573/Documents/Development/veris_attack_graph/filter.txt", build=True)
    atk.save(GENERAL_GRAPH)

if __name__ == "__main__":
    main()
