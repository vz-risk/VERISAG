# VERISAG

VERIS Attack Graph (or VERISAG for short) is a module for parsing a directory of VERIS JSON or a VERIS CSV dataframe into an attack graph.  It also provides functions for analyzing the attack graph.

## Installation

Clone the Repository
```
git clone  https://github.com/gdbassett/veris_attack_graph.git
```

## Usage

Run the following within your python code or at a python console.  Ensure to set the Initialization Variables
```
# Begin Initialization Variables
LOCATION = "~/Documents/Development/VERISAG/"
FILTERS = "~/Documents/Development/VERISAG/filter.txt"
VCDB_LOCATION = "~/Documents/Data/VCDB/data/json"
# End Initialization Variables
# Import the library
import imp
fp, pathname, description = imp.find_module("V2AG", [LOCATION])
V2AG = imp.load_module("V2AG", fp, pathname, description)
# Load the attack graph
VCDB = V2AG.attack_graph(VCDB_LOCATION, FILTERS)
VCDB.build()
# Conduct some analysis, Find a good node to mitigate in the VCDB
analysis = V2AG.attack_graph_analysis.analyze()
analysis.one_graph_multiple_paths(VCDB.g)
```

## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## History

TODO: Write history

## Credits

TODO: Write credits

## License

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