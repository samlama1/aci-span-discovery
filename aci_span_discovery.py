"""
ACI SPAN Discovery Script

This script interacts with Cisco ACI to gather and analyze SPAN information. 
It performs multiple API calls to the APICs to gather information about EPGs, BDs, VLANs, Subnets, VRFs, and SPAN configurations.

Author: Samil Lama
Date: 2024-08-27
Version: 1.0
"""
import requests
import pandas as pd
import json
import argparse
import sys
import re
import pprint
import getpass

# Disable warnings for insecure requests
requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)

class APICClient:
    def __init__(self, apic_url, username, password):
        """
        Initialize the APICClient with the given APIC URL, username, and password.
        """
        self.apic_url = apic_url
        self.username = username
        self.password = password
        self.session = requests.Session()
        self.authenticated = False

    def authenticate(self):
        """
        Authenticate with the APIC using the provided credentials.
        """
        try:
            login_url = f'{self.apic_url}/api/aaaLogin.json'
            auth_payload = {
                'aaaUser': {
                    'attributes': {
                        'name': self.username,
                        'pwd': self.password
                    }
                }
            }
            response = self.session.post(login_url, json=auth_payload, verify=False)
            response.raise_for_status()
            self.authenticated = True
        except requests.exceptions.RequestException as e:
            raise Exception(f'Failed to authenticate with the APIC: {e}')

    def class_lookup(self, name, filter=None):
        """
        Perform a class lookup on the APIC and return the data.
        """
        try:
            if not self.authenticated:
                self.authenticate()
            if filter is None:
                query_url = f'{self.apic_url}/api/node/class/{name}.json?&order-by={name}.modTs|desc'
            else:
                query_url = f'{self.apic_url}/api/node/class/{name}.json?{filter}'
            print(f"+++ Querying {query_url}")
            response = self.session.get(query_url, verify=False)
            response.raise_for_status()
            return response.json()['imdata']
        except requests.exceptions.RequestException as e:
            raise Exception(f'Failed to run moquery for {name}: {e}')

    def epg_bd(self):
        """
        Retrieve EPG to BD mappings and return as a dictionary.
        """
        try:
            data = self.class_lookup('fvRsBd')
            results = {}
            for item in data:
                attributes = item['fvRsBd']['attributes']
                dn = attributes['dn']
                bd = attributes['tDn']
                tenant = re.search(r'(uni/tn-[^/]+)', dn).group(1)
                ap = re.search(r'(uni/tn-[^/]+/ap-[^/]+)', dn).group(1)
                epg = re.search(r'(uni/tn-[^/]+/ap-[^/]+/epg-[^/]+)', dn).group(1)
                
                # Add the combination to the dictionary
                results[(tenant, ap, epg)] = bd

            # Print results
            for (tenant, ap, epg), bd in results.items():
                print(f"+++ tenant: {tenant}, ap: {ap}, epg: {epg}, bd: {bd}")

            return results
        except Exception as e:
            raise Exception(f'Failed to retrieve EPG to BD mappings: {e}')

    def epg_vlans(self):
        """
        Retrieve EPG to VLAN mappings and return as a dictionary.
        """
        try:
            data = self.class_lookup('infraRsFuncToEpg', f'query-target-filter=and(wcard(infraRsFuncToEpg.dn,"uni/infra/"))&order-by=infraRsFuncToEpg.modTs|desc')
            results = {}
            
            for item in data:
                attributes = item['infraRsFuncToEpg']['attributes']
                epg = attributes['tDn']
                encap = attributes['encap']
                
                # Add the combination to the dictionary
                results[epg] = encap

            # Print results
            for epg, encap in results.items():
                print(f"+++ epg: {epg}, encap: {encap}")

            return results
        except Exception as e:
            raise Exception(f'Failed to retrieve EPG to VLAN mappings: {e}')

    def bd_subnets(self):
        """
        Retrieve BD to Subnet mappings and return as a dictionary.
        """
        try:
            data = self.class_lookup('fvSubnet')
            results = {}
            for item in data:
                attributes = item['fvSubnet']['attributes']
                subnet = attributes['dn']
                ip = attributes['ip']
                match = re.search(r'(uni/tn-[^/]+/BD-[^/]+)', subnet)
                if match:
                    bd = match.group(1)
                else:
                    bd = ''

                # Add the combination to the dictionary
                results[bd] = (subnet, ip)
                #exit()

            # Print results
            for bd, (subnet, ip) in results.items():
                print(f"+++ bd: {bd}, subnet: {subnet}, ip: {ip}")

            return results
        except Exception as e:
            raise Exception(f'Failed to retrieve BD to Subnet mappings: {e}')

    def bd_vrf(self):
        """
        Retrieve BD to VRF mappings and return as a dictionary.
        """
        try:
            data = self.class_lookup('fvBD', f'rsp-subtree=full&order-by=fvBD.dn|asc')
            results = {}
            for item in data:
                bd = item['fvBD']['attributes']['dn']
                vrf = ''
                for child in item['fvBD']['children']:
                    if 'fvRsCtx' in child:
                        vrf = child['fvRsCtx']['attributes']['tDn']
                
                # Add the combination to the dictionary
                results[bd] = vrf

            # Print results
            for bd, vrf in results.items():
                print(f"+++ bd: {bd}, vrf: {vrf}")

            return results
        except Exception as e:
            raise Exception(f'Failed to retrieve BD to VRF mappings: {e}')

    def nodes(self):
        """
        Retrieve the Leaf nodes that are alive in the fabric.
        """
        try:
            data = self.class_lookup('topSystem', f'query-target-filter=and(eq(topSystem.role,"leaf"),eq(topSystem.state,"in-service"))')
            results = {}
            for item in data:
                if item['topSystem']['attributes']['state'] == 'in-service': 
                    site_id = item['topSystem']['attributes']['siteId']
                    pod_id = item['topSystem']['attributes']['podId']
                    node_id = item['topSystem']['attributes']['id']
                    leaf_name = item['topSystem']['attributes']['name']
                    leaf_oob = item['topSystem']['attributes']['oobMgmtAddr']
                    # Add the combination to the dictionary
                    results[(site_id, pod_id, node_id, leaf_name, leaf_oob)] = None

            # Print results
            for (site_id, pod_id, node_id, leaf_name, leaf_oob), _ in results.items():
                print(f"+++ site_id: {site_id}, pod_id: {pod_id}, node: {node_id}, leaf_name: {leaf_name}, leaf_oob: {leaf_oob}")

            return results
        except Exception as e:
            raise Exception(f'Failed to retrieve the Leaf nodes: {e}')

    def span_destinations(self):
        """
        Retrieve the span destinations or ports to exclude in the analysis.
        """
        try:
            class_or_object = 'l1PhysIf'
            data = self.class_lookup(class_or_object, f'query-target-filter=or(eq(l1PhysIf.spanMode,"span-dest"),eq(l1PhysIf.descr,"t04h1-ndba"))&order-by=l1PhysIf.dn|desc')
            results = {}
            for item in data:
                pod_id = re.search(r'(topology/pod-([^/]+)/)', item[class_or_object]['attributes']['dn']).group(2)
                node_id = re.search(r'(topology/pod-[^/]+/node-([^/]+)/)', item[class_or_object]['attributes']['dn']).group(2)
                port = item[class_or_object]['attributes']['id']
                desc = item[class_or_object]['attributes']['descr']
                # Add the combination to the dictionary
                results[(pod_id, node_id, port, desc)] = None

            # Print results
            for (pod_id, node_id, port, desc), _ in results.items():
                print(f"+++ pod: {pod_id}, node: {node_id}, port: {port}, description: {desc}")
            return results
        except Exception as e:
            raise Exception(f'Failed to retrieve the span destinations: {e}')

    def span_sources(self):
        """
        Retrieve the span sources
        """
        try:
            class_or_object = 'spanRsSrcToPathEp'
            results = {}
            data = self.class_lookup(class_or_object)
            for item in data:
                pod_id = re.search(r'(topology/pod-([^/]+)/)', item[class_or_object]['attributes']['tDn']).group(2)
                node_id = re.search(r'(topology/pod-[^/]+/paths-([^/]+)/)', item[class_or_object]['attributes']['tDn']).group(2)
                port_or_vpcname = re.search(r'(topology/pod-[^/]+/paths-[^/]+(/extpaths-[^/]+)?/pathep-\[([^\]]+)\])', item[class_or_object]['attributes']['tDn']).group(2)
                # Add the combination to the dictionary
                results[(pod_id, node_id, port_or_vpcname)] = None

            # Print results
            for (pod_id, node_id, port_or_vpcname), _ in results.items():
                print(f"+++ pod: {pod_id}, node: {node_id}, port_or_vpcname: {port_or_vpcname}")

            return results
        except Exception as e:
            raise Exception(f'Failed to retrieve the span source configuration: {e}')

    def vpc_members(self):
        """
        Retrieve the VPC member interfaces.
        """
        try:
            results = {}
            vpc_data = self.class_lookup('pcAggrIf')
            vpc_member = self.class_lookup('pcRsMbrIfs')

            for item in vpc_data:
                vpc_dn1 = item['pcAggrIf']['attributes']['dn']
                vpc_name = item['pcAggrIf']['attributes']['name']
                vpc_id = item['pcAggrIf']['attributes']['id']

                for member in vpc_member:
                    vpc_dn2 = re.search(r'(topology/pod-[^/]+/node-[^/]+/sys/aggr-\[[^\]]+\])', member['pcRsMbrIfs']['attributes']['dn']).group(0)
                    if (vpc_dn1 == vpc_dn2):
                        port = member['pcRsMbrIfs']['attributes']['tSKey']
                        pod_id = re.search(r'(topology/pod-([^/]+)/)', vpc_dn2).group(2)
                        node_id = re.search(r'(topology/pod-[^/]+/node-([^/]+)/)', vpc_dn2).group(2)
                        results[(pod_id, node_id, port, vpc_id, vpc_name)] = None

            # Print results
            for (pod_id, node_id, port, vpc_id, vpc_name), _ in results.items():
                print(f"+++ pod: {pod_id}, node: {node_id}, port: {port}, vpc_id: {vpc_id}, vpc_name: {vpc_name}")

            return results
        except Exception as e:
            raise Exception(f'Failed to retrieve the VPC configuration: {e}')

    def active_ports(self):
        """
        Retrieve the active ports that are not fabric or span destinations.
        """
        try:
            # Get the list of active ports
            class_or_object = 'ethpmPhysIf'
            data = self.class_lookup(class_or_object, f'query-target-filter=and(eq(ethpmPhysIf.bundleIndex,"unspecified"),'
                                                    f'eq(ethpmPhysIf.operSt,"up"),'
                                                    f'ne(ethpmPhysIf.usage,"fabric"),'
                                                    f'ne(ethpmPhysIf.usage,"discovery"),'
                                                    f'ne(ethpmPhysIf.usage,"span"))&order-by=ethpmPhysIf.dn|desc')
            port_status = {}
            for item in data:
                pod_id = re.search(r'(topology/pod-([^/]+)/)', item[class_or_object]['attributes']['dn']).group(2)
                node_id = re.search(r'(topology/pod-[^/]+/node-([^/]+)/)', item[class_or_object]['attributes']['dn']).group(2)
                port = re.search(r'(topology/pod-[^/]+/node-[^/]+/sys/phys-\[([^/]+/[^/]+(?:/[^/]+)?)\])', item[class_or_object]['attributes']['dn']).group(2)
                usage = item[class_or_object]['attributes']['usage']
                mode = item[class_or_object]['attributes']['operMode']
                vlan = item[class_or_object]['attributes']['allowedVlans']
                # Add the combination to the dictionary with a placeholder for description
                port_status[(pod_id, node_id, port)] = {'usage': usage, 'mode': mode, 'vlan': vlan, 'descr': None}

            # Get the descriptions
            class_or_object = 'l1PhysIf'
            data = self.class_lookup(class_or_object, f'query-target-filter=and(eq(l1PhysIf.adminSt,"up"),'
                                                    f'ne(l1PhysIf.descr,""))&order-by=l1PhysIf.dn|desc')
            port_desc = {}
            for item in data:
                pod_id = re.search(r'(topology/pod-([^/]+)/)', item[class_or_object]['attributes']['dn']).group(2)
                node_id = re.search(r'(topology/pod-[^/]+/node-([^/]+)/)', item[class_or_object]['attributes']['dn']).group(2)
                port = re.search(r'(topology/pod-[^/]+/node-[^/]+/sys/phys-\[([^/]+/[^/]+(?:/[^/]+)?)\])', item[class_or_object]['attributes']['dn']).group(2)
                descr = item[class_or_object]['attributes']['descr']
                # Add the combination to the dictionary
                port_desc[(pod_id, node_id, port)] = descr

            # Create a new dictionary to combine port_status and port_desc
            combined_port_info = {}
            for (pod_id, node_id, port), details in port_status.items():
                descr = port_desc.get((pod_id, node_id, port), "")
                combined_port_info[(pod_id, node_id, port, details['usage'], details['mode'], details['vlan'], descr)] = None

            # Print combined results
            for (pod_id, node_id, port, usage, mode, vlan, descr), _ in combined_port_info.items():
                print(f"+++ pod: {pod_id}, node: {node_id}, port: {port}, usage: {usage}, mode: {mode}, vlan: {vlan}, descr: {descr}")

            return combined_port_info
        except Exception as e:
            raise Exception(f'Failed to retrieve the active port configurations: {e}')

    def discover(self):
        """
        Discover and merge EPG, BD, VLAN, Subnet, and VRF information into a Pandas DataFrame.
        """
        try:
            epg_bd = self.epg_bd()
            epg_vlans = self.epg_vlans()
            bd_subnets = self.bd_subnets()
            bd_vrf = self.bd_vrf()

            # Initialize a list to hold the merged information
            merged_list = []

            # Iterate through the tenant_ap_epg_bd_set and merge with other dictionaries
            for (tenant, ap, epg), bd in epg_bd.items():
                vrf = bd_vrf.get(bd, None)
                vlan = epg_vlans.get(epg, None)
                subnet_info = bd_subnets.get(bd, (None, None))
                subnet, ip = subnet_info
                
                # Add the combined information to the merged list
                merged_list.append({
                    'Tenant': re.search(r'(uni/tn-([^/]+))', tenant).group(2),
                    'AP': re.search(r'(uni/tn-[^/]+/ap-([^/]+))', ap).group(2),
                    'EPG': re.search(r'(uni/tn-[^/]+/ap-[^/]+/epg-([^/]+))', epg).group(2),
                    'BD': re.search(r'(uni/tn-[^/]+/BD-([^/]+))', bd).group(2),
                    'Subnet': ip,
                    'VRF': re.search(r'(uni/tn-[^/]+/ctx-([^/]+))', vrf).group(2) if vrf and re.search(r'(uni/tn-[^/]+/ctx-([^/]+))', vrf) else None,
                    'VLAN': vlan
                })

            # Convert the merged list to a Pandas DataFrame
            df = pd.DataFrame(merged_list)

            # Sort the DataFrame
            df = df.sort_values(by=['Tenant', 'AP', 'VRF', 'EPG'])

            # Print the DataFrame
            print(df)

            return df
        except Exception as e:
            raise Exception(f'Failed to discover and merge information: {e}')

    def evaluate_span(self):
        """
        Evaluate the span configuration of the fabric.
        """
        try:
            nodes = self.nodes()
            interfaces = self.active_ports()
            vpc_members = self.vpc_members()
            span_sources = self.span_sources()

            # List to hold merged results
            merged_list = []

            # Create a dictionary to quickly lookup vpc_members by (pod_id, node_id, port)
            vpc_lookup = {(pod_id, node_id, port): {'vpc_id': vpc_id, 'vpc_name': vpc_name}
                        for (pod_id, node_id, port, vpc_id, vpc_name) in vpc_members}

            # Create a set for quick lookup of span_sources
            span_set = {(pod_id, node_id, port_or_vpcname) for (pod_id, node_id, port_or_vpcname) in span_sources}

            # Create a dictionary for quick lookup of site_id, leaf_name, and leaf_oob by (pod_id, node_id)
            nodes_lookup = {(pod_id, node_id): {'site_id': site_id, 'leaf_name': leaf_name, 'leaf_oob': leaf_oob}
                            for (site_id, pod_id, node_id, leaf_name, leaf_oob) in nodes}

            # Create a dictionary to count span items for each (pod_id, node_id)
            span_count_lookup = {}
            for (pod_id, node_id, port_or_vpcname) in span_sources:
                if (pod_id, node_id) in span_count_lookup:
                    span_count_lookup[(pod_id, node_id)] += 1
                else:
                    span_count_lookup[(pod_id, node_id)] = 1

            # Merge interfaces and vpc_members, and check span_sources
            for key in interfaces:
                pod_id, node_id, port, usage, mode, vlan, descr = key
                if (pod_id, node_id) in nodes_lookup:
                    node_info = nodes_lookup[(pod_id, node_id)]
                    merged_entry = {
                        'site_id': node_info['site_id'],
                        'pod_id': pod_id,
                        'node_id': node_id,
                        'leaf_name': node_info['leaf_name'],
                        'leaf_oob': node_info['leaf_oob'],
                        'port': port,
                        'usage': usage,
                        'mode': mode,
                        'vlan': vlan,
                        'descr': descr
                    }
                    # Add VPC information if available
                    if (pod_id, node_id, port) in vpc_lookup:
                        merged_entry.update(vpc_lookup[(pod_id, node_id, port)])
                    
                    # Determine the span status
                    port_captured = (pod_id, node_id, port) in span_set
                    vpc_name_captured = (pod_id, node_id, merged_entry.get('vpc_name')) in span_set
                    
                    if port_captured and vpc_name_captured:
                        merged_entry['span'] = 'both'
                    elif port_captured:
                        merged_entry['span'] = 'port'
                    elif vpc_name_captured:
                        merged_entry['span'] = 'vpc'
                    else:
                        merged_entry['span'] = 'no'
                    
                    # Add span_count
                    merged_entry['span_count'] = span_count_lookup.get((pod_id, node_id), 0)
                    
                    # Determine the span_status
                    if merged_entry['span'] == 'port' and 'vpc_id' in merged_entry and not merged_entry['vpc_id']:
                        merged_entry['span_status'] = 'misconfig'
                    elif merged_entry['span_count'] >= 63:
                        merged_entry['span_status'] = 'limited' if merged_entry.get('span_status') != 'misconfig' else 'misconfig'
                    elif 59 < merged_entry['span_count'] < 63:
                        merged_entry['span_status'] = 'warning' if merged_entry.get('span_status') != 'misconfig' else 'misconfig'
                    elif merged_entry['span'] != 'no':
                        merged_entry['span_status'] = 'valid'
                    else:
                        merged_entry['span_status'] = 'no'
                    
                    merged_list.append(merged_entry)

            # Convert the list to a Pandas DataFrame
            df = pd.DataFrame(merged_list)

            # Sort the DataFrame by site_id, node_id, leaf_name, and port
            df = df.sort_values(by=['site_id', 'node_id', 'leaf_name', 'port'])

            # Print the DataFrame
            print(df)

            return df
        except Exception as e:
            raise Exception(f'Failed to discover and merge information: {e}')

def load_config(file_path):
    """
    Load configuration from a JSON file.
    """
    try:
        with open(file_path, 'r') as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}
    except Exception as e:
        raise Exception(f'Failed to load configuration from {file_path}: {e}')

def main():
    """
    Main function to load configuration, initialize APIC client, and perform discovery.
    """
    try:
        # Load Variables from CLI
        parser = argparse.ArgumentParser(prog="ACI SPAN Discovery", description="Run multiple API calls to the APICs to gather SPAN information.")
        parser.add_argument('-f', '--fabric', help='Run the Fabric Discovery script and export to a file')
        parser.add_argument('-s', '--span', help='Run the SPAN Discovery script and export to a file')

        args = parser.parse_args()

        if not args.fabric and not args.span:
            print("Error: At least one of --fabric or --span must be specified.", file=sys.stderr)
            sys.exit(1)

        # Load Variables from File
        config = load_config('config.json')

        apic_ip = config.get('apic_ip') or input('Enter APIC IP/Hostname: ')
        apic_url = f'https://{apic_ip}'
        username = config.get('username') or input('Enter APIC username: ')
        password = config.get('password') or getpass.getpass(prompt='Enter APIC password: ')

        # Initialize APIC client
        client = APICClient(apic_url, username, password)
    
        if args.fabric:
            fabric = client.discover()
            pprint.pprint(fabric, sort_dicts=False)
            fabric.to_csv(args.fabric, index=False)
            print(f'Fabric discovery results saved to {args.fabric}')

        if args.span:
            span = client.evaluate_span()
            pprint.pprint(span, sort_dicts=False)
            span.to_csv(args.span, index=False)
            print(f'SPAN discovery results saved to {args.span}')

    except Exception as e:
        print(f'Error: {e}', file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
