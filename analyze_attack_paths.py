

DETAILED_GRAPH = "/Users/v685573/Documents/Data/veris_attack_graph/dbir_detailed_filtered_2.graphml"
detailed_graph = nx.read_graphml(DETAILED_GRAPH)

# remove 'error' node
nodes_to_remove = set()
for node in detailed_graph.nodes():
    if detailed_graph.node[node]['sub-type'] == 'action.error':
        nodes_to_remove.add(node)
detailed_graph.remove_nodes_from(nodes_to_remove)


# remove 'unknown' node
nodes_to_remove = set()
for node in detailed_graph.nodes():
    if node.split(".")[-1] == 'Unknown':
        nodes_to_remove.add(node)
detailed_graph.remove_nodes_from(nodes_to_remove)

# set all attributes -> action values to '0'
for src,dst in detailed_graph.edges():
    if detailed_graph.node[src]['type'] == 'attribute' and detailed_graph.node[dst]['type'] == 'action' and detailed_graph.edge[src][dst]['weight'] == 1:
        detailed_graph.edge[src][dst]['weight'] = 0
# set all attributes -> End values to '0'
for src,dst in detailed_graph.edges():
    if detailed_graph.node[src]['type'] == 'attribute' and detailed_graph.node[dst]['type'] == 'End' and detailed_graph.edge[src][dst]['weight'] == 1:
        detailed_graph.edge[src][dst]['weight'] = 0
# set all Start -> action values to '0'
for src,dst in detailed_graph.edges():
    if detailed_graph.node[src]['type'] == 'Start' and detailed_graph.node[dst]['type'] == 'action' and detailed_graph.edge[src][dst]['weight'] == 1:
        detailed_graph.edge[src][dst]['weight'] = 0

# re-normalize edge values
# turns out not necessary

# Take the inverse weight edges
for src,dst in detailed_graph.edges():
    if detailed_graph.edge[src][dst]['weight'] != 0:
        detailed_graph.edge[src][dst]['weight'] = 1 - detailed_graph.edge[src][dst]['weight']


# Find most often action (w/o error)
'''
> e <- vz %>% getenum('action.social.variety')
> e2 <- vz %>% getenum('action.malware.variety')
> e <- rbind(e, e2)
> e2 <- vz %>% getenum('action.hacking.variety')
> e <- rbind(e, e2)
> e2 <- vz %>% getenum('action.physical.variety')
> e <- rbind(e, e2)
> e2 <- vz %>% getenum('action.misuse.variety')
> e <- rbind(e, e2)
> e <- e %>% arrange(-x)
> e[1:10]
'''
# action.social.variety.Phishing is highest after 3 'unknown's
src = 'action.social.variety.Phishing'

# Find most often attribute (w/o error)
'''
> a <- vz %>% getenum('attribute.confidentiality.data.variety')
> a2 <- vz %>% getenum('attribute.integrity.variety')
> a <- rbind(a, a2)
> a2 <- vz %>% getenum('attribute.availability.variety')
> a <- rbind(a, a2)
> a <- a %>% arrange(-x)
> a[1:10]
'''
# attribute.confidentiality.data.variety.Personal followed by 'Repurpose'
dst = 'attribute.confidentiality.data.variety.Personal'


# trace paths between them
print([p for p in nx.all_shortest_paths(detailed_graph, source=src, target=dst, weight="weight")])

# Example path
path = ["Incident Begins",
        "action.hacking.variety.SQLi",
        "attribute.confidentiality.data.variety.Personal",  # attribute.integrity.variety.Alter behavior
        "action.social.variety.Phishing",
        "action.malware.vector.Email attachment",
        "attribute.integrity.variety.Software installation",
        "action.malware.variety.Ram scraper",
        "attribute.confidentiality.data.variety.Payment",
        "Incident Ends"
]

# Path Length
path_length = 0
for i in range(len(path)-1):
    path_length += detailed_graph.edge[path[i]][path[i+1]]['weight']
print path_length