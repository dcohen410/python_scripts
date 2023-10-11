#!/usr/bin/python

"""Export information on all IPv4 addresses in a network or container.

Given a network or network container, export information on all IPv4
addresses associated with the network or (if a network container) all
networks below that container.

Here's an example of running the script to export information for the
network container 192.168.16.0/20:

  python export-addresses.py -n 192.168.16.0/20 -o ipam.csv

If you do not specify the network or container then the script will
prompt for it. If you do not specify an output file then the CSV
output will be send to stdout.

This script was tested on NIOS 8.2.1 (WAPI version 2.7) but should
work for at least some earlier versions as well.

If you do not want to type in the name of the grid master (or a cloud
platform member) and a userid and password every time you run the
script, create an INI file to store credentials and other information
for WAPI calls. For example:

  [api]
  endpoint: gm.example.com
  userid: alice
  password: jabberwocky
  version: 2.7
  valid_cert: False

On Linux/Unix/MacOS by default the script will look for the file
~/.infoblox. On Microsoft Windows by default it will look for the file
infoblox.ini in the user's home directory. You can also specify the
file using the --config option.
"""


# Import the required Python modules.
import requests
import json
import getpass
import sys
import argparse
import ConfigParser
import os
import urllib3
import csv
import string
import contextlib


# Define helper functions.
@contextlib.contextmanager
def smart_open(filename=None):
    """Open either named file or standard output, for use in `with` block.

    This function can be used at the head of a `with` block as a
    substitute for the `open` function, in order to allow output
    generated within the `with` block to be sent either to a named
    file or to standard output.

    For original code and relevant discussions see:
    https://stackoverflow.com/questions/17602878/how-to-handle-both-with-open-and-sys-stdout-nicely

    Args:
      filename (string): A valid filename/pathname, or '-' for stdout.
    """
    
    if filename and filename != '-':
        fh = open(filename, 'wb')
    else:
        fh = sys.stdout

    try:
        yield fh
    finally:
        if fh is not sys.stdout:
            fh.close()
                                                    

def get_args():
    """Get arguments from command line or user input and return them."""

    # Prepare to parse the command line options (if present).
    parser = argparse.ArgumentParser(
        description='Export IP address information for network or container',
    )

    # Add an option to print the version of the script.
    parser.add_argument(
        '-v',
        '--version',
        action='version',
        version='%(prog)s 0.9',
    )

    # Add an option for specifying the location of the configuration file.
    parser.add_argument(
        '-c',
        '--config',
        action='store',
        dest='config',
        help='file with API credentials, related information',
    )

    # Add an option for specifying the network or network container.
    parser.add_argument(
        '-n',
        '--network',
        action='store',
        dest='network',
        help='network or network container to export addresses for',
    )

    # Add an option for specifying the CSV file.
    parser.add_argument(
        '-o',
        '--output',
        action='store',
        dest='output',
        help='file to contain exported CSV data',
    )

    # Parse the command line according to the definitions above.
    args = parser.parse_args()

    # If none specified, look for a default configuration file.
    if args.config:
        config_file = args.config
    elif sys.platform.startswith('win32'):
        config_file = os.path.expanduser('~\infoblox.ini')
    else:
        config_file = os.path.expanduser('~/.infoblox')

    # Get the network/container based on options or user input.
    if args.network:
        network_addr = args.network
    else:
        network_addr = raw_input('Network/container (CIDR format): ').strip()

    # Make sure the network/container has a valid CIDR format.
    if not is_valid_network(network_addr):
        print '"{}" is not a valid CIDR-format network address'.format(network_addr)
        parser.print_usage()
        sys.exit(1)

    # If no output file was supplied then default to stdout.
    if args.output:
        csv_output = args.output
    else:
        csv_output = '-'
    
    return (network_addr, csv_output, config_file)


def network_key(network):
    """Return a character string for sorting IPv4 networks by address.

    Args:
      network (string): A string containing an IPv4 network address in
        CIDR format.

    Returns:
      str: A 14-character string, with the first 12 characters
        containing the zero-filled integer value for the 32-bit
        network address, and the last 2 characters containing the
        zero-filled integer value for the CIDR prefix.
    """

    # Split CIDR string into network address string and prefix string.
    addr_str, prefix_str = network.split('/')

    # Split dotted decimal address into octets, convert to binary.
    addr_octets = [int(octet) for octet in addr_str.split('.')]
    addr_value = (
        256*256*256 * addr_octets[0] +
        256*256 * addr_octets[1] +
        256 * addr_octets[2] +
        addr_octets[3]
        )
    
    # Concatenate address value and prefix value to form sort key.
    prefix_value = int(prefix_str)
    key_str = '{:0>12d}/{:0>2d}'.format(addr_value, prefix_value)
    return key_str


def get_grid_credentials(config_file):
    """Get credentials, other info, for Infoblox grid and return them.

    Args:
      config_file (string): A string containing the pathname of an INI
        file containing configuration information needed to access an
        Infoblox grid. If the string is empty then the user is
        prompted for the necessary information.

    Returns:
      dict: A dictionary with fields containing the configuration
        information for grid access.
    """

    # Default API credentials and other information.
    ep = ''
    id = ''
    pw = ''
    ver = '2.7'  # corresponds to NIOS 8.2.1
    vc = False

    # Look for Infoblox configuration file and options therein.
    config = ConfigParser.ConfigParser()
    if config.read(config_file) and 'api' in config.sections():
        if 'endpoint' in config.options('api'):
            ep = config.get('api', 'endpoint')
        if 'userid' in config.options('api'):
            id = config.get('api', 'userid')
        if 'password' in config.options('api'):
            pw = config.get('api', 'password')
        if 'version' in config.options('api'):
            ver = config.get('api', 'version')
        if 'valid_cert' in config.options('api'):
            vc = config.getboolean('api', 'valid_cert')

    # Prompt for any values not in config file and not defaulted above.
    if not ep:
        ep = raw_input('FQDN for GM (or CP member): ').strip()
    if not id:
        id = raw_input('Userid for API calls: ').strip()
    if not pw:
        pw = getpass.getpass('Password for user {}: '.format(id))

    # Create grid credentials object.
    grid = {}
    grid['url'] = 'https://{}/wapi/v{}/'.format(ep, ver)
    grid['id'] = id
    grid['pw'] = pw
    grid['valid_cert'] = vc

    return grid


def is_valid_network(network):
    """Return True if network is in valid CIDR format, False otherwise."""

    cidr = network.split('/')
    if len(cidr) != 2:
        return False
    if not cidr[1].isdigit():
        return False
    prefix_value = int(cidr[1])
    if prefix_value < 1 or prefix_value > 32:
        return False
    if not is_valid_ip(cidr[0]):
        return False
    # TODO: Verify that address + prefix form a valid combination.
    return True


def is_valid_ip(addr):
    """Return True if addr is a valid IPv4 address, False otherwise."""

    octets = addr.split('.')
    if len(octets) != 4:
        return False
    for octet in octets:
        if not octet.isdigit():
            return False
        octet_value = int(octet)
        if octet_value < 0 or octet_value > 255:
            return False
    return True


def ib_initialize(grid):
    """Verify we can access grid. If so, save auth cookie for later use.

    Args:
      grid (string): Contains credentials and other information to
        access the grid.

    Returns:
      boolean: True if the initialization succeeds. In this case a
      new field 'ibapauth' is added to the grid object to store the
      authentication cookie value.
    """

    # Avoid warnings due to a self-signed certificate on the GM or CP member.
    if not grid['valid_cert']:
        urllib3.disable_warnings()

    # Try to get grid object reference. (This should work in WAPI 1.1+.)
    r = requests.get(
        grid['url'] + 'grid',
        auth=(grid['id'], grid['pw']),
        verify=grid['valid_cert'],
    )

    if r.status_code != requests.codes.ok:
        print r.text
        exit_msg = 'Error {} accessing grid: {}'
        sys.exit(exit_msg.format(r.status_code, r.reason))

    results = r.json()[0]

    grid['ref'] = results['_ref']
    grid['auth_cookie'] = r.cookies['ibapauth']

    return True


def is_network(grid, network_addr):
    """Given network address, return True if it is a known network.

    Args:
      grid (dict): A dictionary containing grid authentication and
        other information from previous call to ib_initialize()

      network_addr (string): A string containing an IPv4 network address in
        CIDR format.

    Returns:
      boolean: True if `network_addr` is a known network object in the
        grid database, False otherwise.
    """

    # Authentication info for the grid.
    req_cookies = {'ibapauth': grid['auth_cookie']}

    # Try to get object reference for network_addr as a network.
    req_params = {
        'network': network_addr,
        'network_view': 'default',
    }

    r = requests.get(
        grid['url'] + 'network',
        params=req_params,
        cookies=req_cookies,
        verify=grid['valid_cert'],
    )

    if r.status_code != requests.codes.ok:
        print r.text
        exit_msg = 'Error {} looking for network container: {}'
        sys.exit(exit_msg.format(r.status_code, r.reason))

    # We found a network with this address.
    if len(r.json()) >= 1:
        return True
    else:
        return False


def is_container(grid, network_addr):
    """Given network address, return True if it is a known container.

    Args:
      grid (dict): A dictionary containing grid authentication and
        other information from previous call to ib_initialize()

      network_addr (string): A string containing an IPv4 network address in
        CIDR format.

    Returns:
      boolean: True if `network_addr` is a known network container
        object in the grid database, False otherwise.
    """

    # Authentication info for the grid.
    req_cookies = {'ibapauth': grid['auth_cookie']}

    # Try to get object reference for network_addr as a network container.
    req_params = {
        'network': network_addr,
        'network_view': 'default',
    }

    r = requests.get(
        grid['url'] + 'networkcontainer',
        params=req_params,
        cookies=req_cookies,
        verify=grid['valid_cert'],
    )

    if r.status_code != requests.codes.ok:
        print r.text
        exit_msg = 'Error {} looking for network container: {}'
        sys.exit(exit_msg.format(r.status_code, r.reason))

    # We found a network container with this address.
    if len(r.json()) >= 1:
        return True
    else:
        return False


def get_child_networks(grid, container):
    """Given network container, return list of child networks.

    Args:
      grid (dict): A dictionary containing grid authentication and
        other information from previous call to ib_initialize()

      container (string): A string containing an IPv4 network address
        in CIDR format, representing an Infoblox network container.

    Returns:
      list: A list of strings containing the network addresses (in
        CIDR format) of Infoblox networks that are immediate children
        of the given container.
    """

    # Authentication info for the grid.
    req_cookies = {'ibapauth': grid['auth_cookie']}

    # Get list of all networks with this container as parent.
    req_params = {
        'network_container': container,
        'network_view': 'default',
    }

    r = requests.get(
        grid['url'] + 'network',
        params=req_params,
        cookies=req_cookies,
        verify=grid['valid_cert'],
    )

    if r.status_code != requests.codes.ok:
        print r.text
        exit_msg = 'Error {} getting networks in container: {}'
        sys.exit(exit_msg.format(r.status_code, r.reason))

    # Create list of child networks and return sorted version of it.
    results = r.json()
    networks = []
    if len(results) >= 1:
        for result in results:
            networks.append(result['network'])
    return networks


def get_child_containers(grid, container):
    """Given network container, return list of child containers.

    Args:
      grid (dict): A dictionary containing grid authentication and
        other information from previous call to ib_initialize()

      container (string): A string containing an IPv4 network address
        in CIDR format, representing an Infoblox network container.

    Returns:
      list: A list of strings containing the network addresses (in
        CIDR format) of Infoblox network containers that are immediate
        children of the given container.
    """

    # Authentication info for the grid.
    req_cookies = {'ibapauth': grid['auth_cookie']}

    # Get list of all network containers with this container as parent.
    req_params = {
        'network_container': container,
        'network_view': 'default',
    }

    r = requests.get(
        grid['url'] + 'networkcontainer',
        params=req_params,
        cookies=req_cookies,
        verify=grid['valid_cert'],
    )

    if r.status_code != requests.codes.ok:
        print r.text
        exit_msg = 'Error {} getting network containers in container: {}'
        sys.exit(exit_msg.format(r.status_code, r.reason))

    # Create list of child containers and return sorted version of it.
    results = r.json()
    containers = []
    if len(results) >= 1:
        for result in results:
            containers.append(result['network'])
    return containers


def get_all_networks(grid, container):
    """Given network container, return list of all networks in hierarchy."""

    # First get networks directly under this container.
    networks = get_child_networks(grid, container)

    # Then add networks under any containers in this container.
    for child in get_child_containers(grid, container):
        networks.extend(get_all_networks(grid, child))

    return networks


def get_address_results(grid, network):
    """Given network, return results for addresses in network.

    Args:
      grid (dict): A dictionary containing grid authentication and
        other information from previous call to ib_initialize()

      network (string): A string containing an IPv4 network address
        in CIDR format, representing an Infoblox network.

    Returns:
      list: A list of IPv4 address objects in the network.
    """

    # Authentication info for the grid.
    req_cookies = {'ibapauth': grid['auth_cookie']}

    # Get list of all IPv4 address objects with this network as parent.
    req_params = {
        'network': network,
        'network_view': 'default',
        '_max_results': str(20000),
    }

    r = requests.get(
        grid['url'] + 'ipv4address',
        params=req_params,
        cookies=req_cookies,
        verify=grid['valid_cert'],
    )

    if r.status_code != requests.codes.ok:
        print r.text
        exit_msg = 'Error {} getting networks in container: {}'
        sys.exit(exit_msg.format(r.status_code, r.reason))

    # Create list of IPv4 address objects and return it.
    results = r.json()
    address_results = []
    if len(results) >= 1:
        for result in results:
            address_results.append(result)
    return address_results


def export_address_results(grid, networks, csv_output):
    """Given networks, export results from addresses in networks.

    Args:
      grid (dict): A dictionary containing grid authentication and
        other information from previous call to ib_initialize()

      networks (list): A list of strings containing IPv4 network
        addresses in CIDR format, representing a list of Infoblox
        networks.

      csv_output (str): A string containing the filename/pathname of
        the file to which CSV output should be written, or '-' to send
        to standard output.

    Returns:
      N/A
    """

    # Fields to export. (These correspond to columns in the IPAM view.)
    # TODO: Expand the list of fields that can be exported, and allow
    # some user control over which fields to export.
    fields = [
        'ip_address',
        'names',
        'mac_address',
        'usage',
        'types',
    ]
    
    # Export the results in CSV format to the specified file (or stdout).
    with smart_open(csv_output) as out_file:

        # Write a CSV file, quoting multi-valued fields if needed.
        out_csv = csv.writer(out_file,
                             delimiter=',',
                             quotechar='"',
                             quoting=csv.QUOTE_MINIMAL)

        # Write a header row containing the field names.
        out_csv.writerow(fields)

        # For each network, get information on addresses in the network.
        for network in networks:
            address_results = get_address_results(grid, network)

            # For each address, output a CSV row with field values for
            # that address.
            for address_result in address_results:
                field_values = format_address_result(address_result, fields)
                out_csv.writerow(field_values)


def format_address_result(address_result, fields):
    """Format specified fields of an address result into CSV output row.

    Args:
      address_result (dict): Dictionary of fields for a given IPv4
        address, indexed by field names. Individual field values are
        strings, lists of strings, or other types.

      fields (list): Names of fields to be exported.

    Returns:
      list: Field values formatted for CSV export.
    """

    field_values = []
    for field in fields:
        field_value = address_result[field]
        if isinstance(field_value, unicode) or isinstance(field_value, str):
            # A normal string gets added as is.
            field_values.append(field_value)
        elif isinstance(field_value, list):
            # A list of strings is converted into a string of
            # comma-separated values.
            # TODO: Validate that list elements are all strings.
            field_values.append(string.join(field_value, ','))
        else:
            # This should not occur, but just in case.
            field_values.append('UNKNOWN VALUE TYPE')
    return field_values


def main():
    # Network/container to export comes from command line or user input.
    # CSV output file comes from command line, with default to stdout.
    (network_addr, csv_output, config_file) = get_args()
    
    # Grid credentials come from configuration file or user input.
    grid = get_grid_credentials(config_file)

    # Look for the specified network in the grid and determine if it
    # is a network container or a (leaf) network. Create a list
    # containing the (leaf) network or all (leaf) networks in the
    # hierarchy below the network container.
    ib_initialize(grid)
    if is_network(grid, network_addr):
        networks = [network_addr]
    elif is_container(grid, network_addr):
        networks = get_all_networks(grid, network_addr)
        networks.sort(key=network_key)
    else:
        exit_msg = '{} is not a known network or network container.'
        sys.exit(exit_msg.format(network_addr))

    # Find address info for the network(s) and export it to CSV.
    export_address_results(grid, networks, csv_output)


# Execute the following when this is run as a script.
if __name__ == '__main__':
    main()


# This is an example of the standard fields returned by default when
# retrieving an ipv4_address object via the WAPI. The _return_fields+
# parameter can be used to retrieve additional fields beyond those
# listed here.

# {
#   u'status': u'USED',
#   u'network': u'192.168.0.0/23',
#   u'network_view': u'default',
#   u'usage': [u'DNS'],
#   u'objects': [
#     u'record:host/ZG5zLmhvc3QkLl9kZWZhdWx0LmNvbS5maGVja2VyLndzMjAwOA:ws2008.fhecker.com/internal'
#   ],
#   u'names': [u'ws2008.fhecker.com'],
#   u'mac_address': u'00:0c:29:a2:ab:3c',
#   u'types': [u'HOST'],
#   u'_ref': u'ipv4address/Li5pcHY0X2FkZHJlc3MkMTkyLjE2OC4wLjMzLzA:192.168.0.33',
#   u'ip_address': u'192.168.0.33',
#   u'is_conflict': False
# }
