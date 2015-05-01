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
LOGLEVEL = logging.DEBUG
LOG = None

########### NOT USER EDITABLE BELOW THIS POINT #################


## IMPORTS
import networkx as nx  # CHANGEME
import argparse
import ConfigParser
from itertools import product  # used for combining actions and attributes
from operator import itemgetter
from collections import defaultdict
import copy
from tabulate import tabulate

## SETUP
__author__ = "Gabriel Bassett"


## GLOBAL EXECUTION
pass



## FUNCTION DEFINITION
class helper():
    def __init__(self):
        pass  #  TODO

    def path_length(self, g, path, weight='weight'):
        """ A function to calculate the length of a path

        :param g: the graph to find the length through
        :param path: a list of nodes representing the path
        :param weight: the edge parameter to use for the edge length
        :return tuple of (path, length)
        """
        length = float(0)
        for i in range(len(path)-1):
            length += g.edge[path[i]][path[i+1]][weight]
        return (path, length)

    def shortest_attack_paths(self, g, src=None, dst=None):
        """ helper function to find all shortest paths between any combination of action->attribute.

        :param g: the attack graph to analyze
        :param src: optional list of source nodes (for subsetting down to specific actions)
        :param dst: optional list of destination nodes (for subsetting down to specific attributes)
        :param weight: the parameter on edges representing their length.
        :return: a dictionary of paths, keyed by (src, dst) tuple and value of a list representing the shortest path from src to dst
        """
        # get the actions/attributes set
        actions = set()
        attributes = set()
        for node in g.nodes():
            if g.node[node]['type'] == 'action':
                actions.add(node)
            elif g.node[node]['type'] == 'attribute':
                attributes.add(node)

        # Allow subsetting actions or attributes to use
        if src is not None:
            actions = actions.intersect(set(src))
        if dst is not None:
            attributes = attributes.intersect(set(src))

        if len(actions) == 0 or len(attributes) == 0:
            raise ValueError("The source must contain at least one valid action and the destination must contain at least one valid attribute.")

        # get the paths
        paths = dict()
        for action, attribute in product(actions, attributes):
            try:
                paths[(action, attribute)] = nx.dijkstra_path(g,action,attribute,'weight')
            except nx.NetworkXNoPath:
                paths[(action, attribute)] = list()
        return paths

    def all_simple_paths(self, g, src, dst, cutoff=7):
        """ returns a list of all simple paths up to a given cutoff in no order

        :param g: graph to calculate paths for
        :param src: node to start paths at
        :param dst: node to end paths at
        :param cutoff: integer representing the maximum length of paths.  STRONGLY recommended to be 7 or less
        :return: a list of paths (which are themselves lists of nodes from src to dst) in no specific order
        """
        paths = []
        for path in nx.all_simple_paths(g, src, dst, cutoff):
            paths.append(path)
        return paths

    def compare_graphs(self, g1, g2):
        """ compare two graphs returning a graph with the count of the 1st graph as a percentage of the second and the count as the inverste of the weight (for shortest path calculation)

        :param g1: a networkx directed attack graph. the graph to assess.
        :param g2: a networkx directed attack graph. the baseline graph to assess against.
        :returns: a networkx graph of the comparison
        """
        g_out = nx.DiGraph()
        # copy nodes, updating their weight
        for node, d1 in g1.nodes(data=True):
            data1 = copy.deepcopy(d1)  # added because the script was somehow updating the originating graph
            unpaired_nodes = list()
            if g2.has_node(node):
                try:
                    data1['count'] = float(data1['weight'] / g2.node[node]['weight'])
                    data1['paired'] = True
                    _ = data1.pop('weight')
                    g_out.add_node(node, attr_dict=data1)
                except KeyError:  # Start and End nodes /may/ not have weights.
                    if data1['type'] in ['start', 'end']:
                        data1['count'] = float(1)
                        data1['paired'] = True
                        g_out.add_node(node, attr_dict=data1)
                    else:
                        print data1
                        print g2.node[node]
                        raise
            else:
                unpaired_nodes.append((node, data1))
        # get max weight
        max_weight = 0
        for node, data in g_out.nodes(data=True):
            if data['count'] > max_weight:
                max_weight = data['count']
        # add unpaired nodes with the max weight
        for node, d in unpaired_nodes:
            data = copy.deepcopy(d)  # added because the script was somehow updating the originating graph
            data['count'] = max_weight
            _ = data.pop('weight')
            data['paired'] = False
            g_out.add_node(node, attr_dict=data)
        # copy edges, upadting their weight
        for src, dst, d1 in g1.edges(data=True):
            data1 = copy.deepcopy(d1)  # added because the script was somehow updating the originating graph
            unpaired_edges = list()
            if g2.has_edge(src, dst):
                try:
                    data1['count'] = float(data1['weight'] / g2.edge[src][dst]['weight'])
                    data1['paired'] = True
                    _ = data1.pop('weight')
                    g_out.add_edge(src, dst, data1)
                except KeyError:
                    if src == 'start' or dst == 'end':
                        data1['count'] = float(1)
                        data1['paired'] = True
                        g_out.add_edge(src, dst, attr_dict=data1)
                    else:
                        print src, dst
                        print data1
                        print g2.edge[src][dst]
                        raise
            else:
                unpaired_edges.append((src, dst, data1))
        # get max weight
        max_weight = 0
        for src, dst, data in g_out.edges(data=True):
            if data['count'] > max_weight:
                max_weight = data['count']
        # add unpaired edges with the max weight
        for src, dst, d in unpaired_edges:
            data = copy.deepcopy(d)  # added because the script was somehow updating the originating graph
            data['count'] = max_weight
            _ = data.pop('weight')
            data['paired'] = False
            g_out.add_edge(src, dst, attr_dict=data)

        # Percentage is now stored as a count.  Now we must re-add the weights to be most common shortest to allow path calculation
        g_out = attack_graph.attack_graph(None).normalize_weights(g_out)

        return g_out


class score():
    def __init__(self):
        """ Provides functions for picking attack graph nodes or edges to mitigate

        * shortest_path_occurence: A modified form of shortest-path centrality which only considers action-attribute pairs
        * initialized_pagerank: Pagerank (eigenvector) centrality initialized to jump to action nodes only.
        """
        pass  # TODO

    def shortest_path_occurence(self, g, paths, mid=False):
        """ scores nodes based on their occurence in shortest paths

        :param g: a networkx attack digraph
        :param paths: a dictionary of the shortest paths to be scored.  Key is a tuple of (src, dst).  Value is the a tuple of the path.
        :param mid: If true, only nodes in the middle of a path will be used (i)
        """
        scores = defaultdict(int)
        for path in paths.values():
            if not mid:
                for node in path:
                    scores[node] += 1
            else:
                for node in path[1:-1]:
                    scores[node] += 1
        scores = [(k, v) for k, v in scores.iteritems()]  # convert from dictionary so it can be sorted
        scores.sort(key=itemgetter(1), reverse=True)  # Sort the scores
        return scores

    def initialized_pagerank(self, g):
        """ Returns nodes scored by pagerank.

        :param g: a directed networkx graph
        :returns list of tuples of (node, score)
        Note: Pagerank is modified to always jump to an action node.  All action nodes are jumped to equally.
        """
        # Get actions
        actions = set()
        for node in g.nodes():
            if g.node[node]['type'] == 'action':
                actions.add(node)
        # create actions as 'jump points' with even probability
        #actions = {a: 1/float(len(actions)) for a in actions}  
        dangling = dict()
        for node in g.nodes():
            dangling[node] = 0
        for action in actions:
            dangling[action] = 1/float(len(actions))
        # do the actual scoring 
        scores = nx.pagerank_numpy(g, weight='weight', dangling = dangling)
        scores = [(k, v) for k, v in scores.iteritems()]  # convert from dictionary so it can be sorted
        scores.sort(key=itemgetter(1), reverse=True)  # Sort the scores
        return scores    


class analyze():
    helper = None
    score = None

    def __init__(self):
        """ Analyze provides functions which analyze VERIS attack graphs in various ways, printing the output


        * one_graph_multiple_paths: analyze the effect of mitigating a single node in the attack graph on all shortest paths
        * one_graph_one_path: analyze the mitigation of a single node to all potential paths between two nodes
        * two_graphs: analyze the relative differences between node and edge weights in two attack graphs
        * two_graphs_multiple_paths: analyze the difference in all shortest paths in two graphs
        """
        self.helper = helper()
        self.score = score()


    def one_graph_multiple_paths(self, g, mitigate="any", node_to_mitigate=None, src=None, dst=None):
        """ Takes a networkx attack graph, analyzes it, and prints a recommendation for a mitigation with associated expected value

            :param g: networkx digraph attack graph to analyze
            :param mitigate: String of either 'any', action', or 'attribute' used to limit what type of enumerations may be recommended for mitigation
            :param node_to_mitigate: If included, it will be used as the mitigated node.  Otherwise, the script will pick one.
            :param src: a list subset of actions to use as sources for paths.  If not included, all actions are used.
            :param dst: a list subset of attributes to use as distinations for paths.  If not included, all attributes are used.
            :return: None.  Recommendation is printed
        """

        # Graph is already built

        # calculate base score
        paths = self.helper.shortest_attack_paths(g, src=None, dst=None)
        paths = {k: v for k, v in paths.iteritems() if v}

        if not node_to_mitigate:
            # Score the graph
            node_scores = self.score.shortest_path_occurence(g, paths)  # score based on occurence in shortest paths
        #     node_scores = self.score.shortest_path_occurence(g, paths, mid=True)  # score based on occurence in shortest paths, but only ends
        #    node_scores = self.score.initialized_pagerank(g)  # score based on pagerank initialized to start at actions

            # Pick a node to mitigate
            if mitigate is "any":
                node_to_mitigate = node_scores[0][0]
            elif mitigate is "actions":
                for k,v in node_scores:
                    if k.split(".", 1)[0] == "action":
                        node_to_mitigate = k
                        break

        # Pick a node to mitigate
        after_g = g.copy()
        after_g.remove_node(node_to_mitigate)  # Should this look for the first 'action' rather than either action or attribute?

        # Recreate paths (using only the key pairs that still exist in after_g)
        after_paths = self.helper.shortest_attack_paths(after_g, src=None, dst=None)
        after_paths = {k: v for k, v in after_paths.iteritems() if v}  # This is necessary to remove empty paths
        before_paths = {k: v for k, v in paths.iteritems() if k in after_paths.keys()}

        # Calculate the graph's initial score
        before_score = 0
        for path in before_paths.values():
            _, length = self.helper.path_length(g, path)
            before_score += length

        # Rescore
        after_score = 0
        for path in after_paths.values():
            _, length = self.helper.path_length(after_g, path)
            if length == 0:
                logging.warning("Path length was 0 implying an empty path.  This will cause improvement to be understimated.")
            after_score += length

        # find paths removed
        removed_paths = set(paths.keys()).difference(set(after_paths.keys()))

        # find attributes removed
        before_attributes = set()
        after_attributes = set()
        for src, dst in paths.keys():
            if dst.split(".", 1)[0] == 'attribute':
                before_attributes.add(dst)
        for src, dst in after_paths.keys():
            if dst.split(".", 1)[0] == 'attribute':
                after_attributes.add(dst)
        removed_attributes = before_attributes.difference(after_attributes)

        print "Removing {0} decreased available paths by {1}%.".format(node_to_mitigate, round(len(removed_paths)/float(len(paths)) * 100, 2))
        print "{0} attributes are no longer compromisable.".format(len(removed_attributes))
        print "The remaining attack paths increased in cost by {0}%.".format(round((after_score - before_score)/before_score * 100, 2))


    def one_graph_one_path(self, g, src, dst, cutoff=7):
        """ Analyze the top N potential paths between the source and destination in the graph

        :param g: a networkx directed graph
        :param src: the source node within the graph
        :param dst: the destionation node within the graph
        :param n: the maximum length of path to consider.  It is STRONGLY recommended to use 7 or less.
        """
        lengths = list()
        paths = self.helper.all_simple_paths(g, src, dst, cutoff)

        for path in paths:
            lengths.append(self.helper.path_length(g, path, 'weight'))
        lengths.sort(key=itemgetter(1))
        nodes = set(lengths[0][0][1:-1])
        i = 1
        if len(nodes) <= 2:
            nodes = set(lengths[1][0][1:-1])
            i = 2
            direct = True
        while 1:
            if len(lengths[i][0]) <= 2:  # If the path is only 2, it is the direct path.
                nodes2 = nodes
            else:
                nodes2 = nodes.intersection(set(lengths[i][0][1:-1]))
            if len(nodes2) > 1:
                nodes = nodes2
                i += 1
                if i == len(lengths):
                    break
            elif len(nodes2) <= 0:
                break
            else:
                nodes = nodes2
                break

        if direct:
            print ("The most likely path is directly from {0} to {1}.  Mitigating that first will provide an improvement of {2}%.  "
                   "Once that has been dealt with, you can gain a {3}% improvement by mitigating {4}.").format(
                       src,
                       dst,
                       round((lengths[1][1]/float(lengths[0][1]) - 1) * 100, 2),
                       round((lengths[i][1]/float(lengths[1][1]) - 1) * 100, 2),
                       list(nodes)
                       )
        else:
            print "Remove {0} for a {1}% improvement. This ignores the toy solution of mitigating {2} or {3}.".format(
                nodes,
                round((lengths[i][1]/float(lengths[0][1]) - 1) * 100, 2),
                src,
                dst
                )


    def two_graphs(self, g1, g2):
        """ Compare two graphs and print the major differences

        :param g1: networkx graph to analyze
        :param g2: baseline networkx graph to compare the g1 graph to
        """
        n = 10  # a variable for the number of results to print

        # get the differential graph
        g_diff = self.helper.compare_graphs(g1, g2)

        # Find major differences
        scores = list()
        for src, dst, data in g_diff.edges(data=True):
            scores.append(['edge', data['Label'], round(data['count'] * 100, 2)])
        for node, data in g_diff.nodes(data=True):
            scores.append(['node', data['Label'], round(data['count'] * 100, 2)])
        scores.sort(key=itemgetter(2), reverse=True)  # sort the scores

        # Find missing nodes
        missing = list()
        for node, data in g_diff.nodes(data=True):
            if not data['paired']:
                missing.append(['node', data['Label']])
        for src, dst, data in g_diff.edges(data=True):
            if not data['paired']:
                missing.append(['edge', data['Label']])

        # Display (could just as easily dump out as json or something)
        print "Top {0} nodes and edges by relative strength vs the reference graph.".format(n)
        print tabulate(scores[:n], headers=["Type", "Name", "Score (%)"])
        print ""
        print "Top {0} nodes and edges by relative weakness vs the reference graph.".format(n)
        print tabulate(scores[-(n):], headers=["Type", "Name", "Score (%)"])
        print ""
        if len(missing) > 0:
            print "All nodes and edges missing from the baseline graph."
            print tabulate(missing, headers=['Type', 'Name'])
        else:
            print "No nodes or edges are missing from the baseline graph."


    def two_graphs_multiple_paths(self, g1, g2):
        """ take two graphs and compare the shortest paths between them

        :param g1: networkx graph to analyze
        :param g2: baseline networkx graph to compare the g1 graph to
        """

        n = 10  # variable used for number of output to display

        # get the baseline paths
        baseline_paths = self.helper.shortest_attack_paths(g2, src=None, dst=None)
        baseline_paths = {k: v for k, v in baseline_paths.iteritems() if v}  # Remove empty paths
        analyze_paths = self.helper.shortest_attack_paths(g1, src=None, dst=None)
        analyze_paths = {k: v for k, v in analyze_paths.iteritems() if v}
        # get the pairs in both path sets
        mutual_pairs = set(analyze_paths.keys()).intersection(set(baseline_paths.keys()))

        analyzed_paths = []
        for pair in mutual_pairs:
            base_length = self.helper.path_length(g2, baseline_paths[pair])
            analyze_length = self.helper.path_length(g1, analyze_paths[pair])
            analyzed_paths.append([pair[0], pair[1], float(analyze_length[1]/float(base_length[1]))])
        analyzed_paths.sort(key=itemgetter(2), reverse=True)

        # Display (could just as easily dump out as json or something)
        print "Top {0} paths by relative strength vs the reference graph.".format(n)
        print tabulate(analyzed_paths[:n], headers=["Source", "Destination", "Score (%)"])
        print ""
        print "Top {0} paths by relative weakness vs the reference graph.".format(n)
        print tabulate(analyzed_paths[-(n):], headers=["Source", "Destination", "Score (%)"])
        print ""
        if len(mutual_pairs) == len(set(analyze_paths.keys())):
            print "All paths in the analyzed graph are in the reference graph."
        else:
            print "The following paths are in the analyzed graph but not the reference graph."
            tabulate(set(analyze_paths.keys()).difference(mutual_pairs), headers=["Source", "Destination"])
        print ""
        if len(mutual_pairs) == len(set(baseline_paths.keys())):
            print "All paths in the reference graph are in the analyzed graph."
        else:
            print "The following paths are in the reference graph but not the analyzed graph."
            tabulate(set(baseline_paths.keys()).difference(mutual_pairs), headers=["Source", "Destination"])