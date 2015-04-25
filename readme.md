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
LOCATION = "~/Documents/Development/veris_attack_graph/"
FILTERS = "~/Documents/Development/veris_attack_graph/filter.txt"
VCDB_LOCATION = "~/Documents/Development/VCDB/data/json"
# End Initialization Variables
# Import the library
import imp
fp, pathname, description = imp.find_module("veris_to_atk_graph_Rev2", [LOCATION])
V2AG = imp.load_module("veris_to_atk_graph_Rev2", fp, pathname, description)
# Load the attack graph
DBIR = V2AG.attack_graph(LOCATION, FILTERS)
DBIR.build()
# TODO: add some example analysis code
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

TODO: Will be apache