```markdown
# ACI SPAN Discovery

This project provides a set of tools to interact with Cisco ACI (Application Centric Infrastructure) APIC (Application Policy Infrastructure Controller) to gather and analyze SPAN (Switched Port Analyzer) information. The script performs multiple API calls to the APICs to gather information about EPGs, BDs, VLANs, Subnets, VRFs, and SPAN configurations.

## Features

- Authenticate with the APIC
- Retrieve and map EPG to BD, VLAN, Subnet, and VRF
- Retrieve and analyze active ports, VPC members, and SPAN sources
- Evaluate SPAN configuration and generate a detailed report

## Requirements

- Python 3.x
- `requests` library
- `pandas` library
- `argparse` library

## Installation

1. Clone the repository:
    ```sh
    git clone https://github.com/samlama1/aci-span-discovery.git
    cd aci-span-discovery
    ```

2. Install the required Python libraries:
    ```sh
    pip install requests pandas argparse
    ```

3. Create a `config.json` file with the following structure:
    ```json
    {
        "apic_url": "https://your-apic-url",
        "username": "your-username",
        "password": "your-password"
    }
    ```

## Usage

### Fabric Discovery

To run the fabric discovery script and export the results to a CSV file:
```sh
python aci_span_discovery.py --fabric fabric_results.csv
```

### SPAN Discovery

To run the SPAN discovery script and export the results to a CSV file:
```sh
python aci_span_discovery.py --span span_results.csv
```

### Combined Usage

To run both fabric and SPAN discovery scripts and export the results to CSV files:
```sh
python aci_span_discovery.py --fabric fabric_results.csv --span span_results.csv
```

## Script Overview

### APICClient Class

- **`__init__(self, apic_url, username, password)`**: Initialize the APICClient with the given APIC URL, username, and password.
- **`authenticate(self)`**: Authenticate with the APIC using the provided credentials.
- **`class_lookup(self, name, filter=None)`**: Perform a class lookup on the APIC and return the data.
- **`epg_bd(self)`**: Retrieve EPG to BD mappings and return as a dictionary.
- **`epg_vlans(self)`**: Retrieve EPG to VLAN mappings and return as a dictionary.
- **`bd_subnets(self)`**: Retrieve BD to Subnet mappings and return as a dictionary.
- **`bd_vrf(self)`**: Retrieve BD to VRF mappings and return as a dictionary.
- **`nodes(self)`**: Retrieve the Leaf nodes that are alive in the fabric.
- **`span_destinations(self)`**: Retrieve the span destinations or ports to exclude in the analysis.
- **`span_sources(self)`**: Retrieve the span sources.
- **`vpc_members(self)`**: Retrieve the VPC member interfaces.
- **`active_ports(self)`**: Retrieve the active ports that are not fabric or span destinations.
- **`discover(self)`**: Discover and merge EPG, BD, VLAN, Subnet, and VRF information into a Pandas DataFrame.
- **`evaluate_span(self)`**: Evaluate the span configuration of the fabric.
- **`save_to_csv(self, data, moquery_class, file_name)`**: Save the given data to a CSV file.

### Helper Functions

- **`load_config(file_path)`**: Load configuration from a JSON file.
- **`main()`**: Main function to load configuration, initialize APIC client, and perform discovery.

## Output

The output of the script will be saved as CSV files specified in the command line arguments. The CSV files will contain detailed information about the fabric and SPAN configurations.

## License

N/A

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## Contact

For any questions or support, please contact me.
```