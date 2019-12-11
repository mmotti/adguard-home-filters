from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
from datetime import datetime
from validators import domain as validatedomain
import re
import os
import locale
import yaml

# Set the locale to UTF-8
locale.setlocale(locale.LC_ALL, 'en_GB.UTF-8')


def read_yaml_settings(file_yaml):
    # If the yaml file exists
    if os.path.isfile(file_yaml):
        with open(file_yaml, 'r') as fOpen:
            return yaml.safe_load(fOpen)


def fetch_url(url):

    if not url:
        return

    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:71.0) Gecko/20100101 Firefox/71.0'}

    print('[i] Fetching:', url)

    try:
        response = urlopen(Request(url, headers=headers))
    except HTTPError as e:
        print('[E] HTTP Error:', e.code, 'whilst fetching', url)
        return
    except URLError as e:
        print('[E] URL Error:', e.reason, 'whilst fetching', url)
        return

    # Read and decode
    response = response.read().decode('UTF-8').replace('\r\n', '\n')

    # If there is data
    if response:
        # Strip leading and trailing whitespace
        response = '\n'.join(x.strip() for x in response.splitlines())

    # Return the hosts
    return response


def run_str_substitutions(string, dict_subs, precompiled=False):

    # Return None if the supplied string was empty
    if not string or not dict_subs:
        return

    # If the patterns aren't already compiled
    # (it may be necessary to pre-compile if calling for a for loop)
    if not precompiled:
        # Add compiled regexps to dict
        dict_subs = {re.compile(rf'{k}', re.M): v for k, v in dict_subs.items()}

    # For each sub pattern
    for pattern, sub in dict_subs.items():
        # Remove matches
        string = pattern.sub(sub, string)

    return string


def clean_hosts(str_hosts):

    # Conditional exit if argument not supplied
    if not str_hosts:
        return

    # Construct substitution array
    dict_subs = \
        {
            # Remove local dead-zone
            r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}\s+': '',
            # Remove IP addresses
            r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$': '',
            # Remove any line that doesn't start a-z 0-9
            r'^[^a-z0-9].*': '',
            # Remove in-line comments
            r'[^\S\n]+#.*$': '',
            # Remove entries without a '.' (non-domains) or that start with
            # localhost. and don't have any subsequent dots
            r'^(?:(?![^.\n]+\.).*|localhost\.[^.\n]+)$': '',
            # Remove empty lines
            r'^[\t\s]*(?:\r?\n|\r)+': ''
        }

    str_hosts = run_str_substitutions(str_hosts, dict_subs).lower()

    return str_hosts


def clean_regexps(str_regexps):

    # Conditional exit if argument not supplied
    if not str_regexps:
        return

    # Construct substitution array
    dict_subs = \
        {
            # Remove comments
            r'^(?:!|#).*$': '',
            # Remove empty lines
            r'^[\t\s]*(?:\r?\n|\r)+': ''
        }

    str_regexps = run_str_substitutions(str_regexps, dict_subs)

    return str_regexps


def clean_filters(str_filters):

    # Conditional exit if argument not supplied
    if not str_filters:
        return

    # Construct substitution array
    dict_subs = \
        {
            # Remove non-valid (for AdGuard Home)
            # restrictive / whitelist filters
            r'^(?!(?:@@)?\|\|.+\^(?:\||(?:\$(?:document)))?$).*$': '',
            # Remove type options
            r'(?:\||\$.+)$': '',
            # Remove IP addresses
            r'^\|\|(?:[0-9]{1,3}\.){3}[0-9]{1,3}\^$': '',
            # Remove empty lines
            r'^[\t\s]*(?:\r?\n|\r)+': ''
        }

    str_filters = run_str_substitutions(str_filters, dict_subs).lower()

    return str_filters


def fetch_hosts(urls_hostfiles):

    if not urls_hostfiles:
        return

    set_hosts = set()

    # For each host file
    for url in urls_hostfiles:

        # Fetch the hosts
        str_hosts = fetch_url(url)
        str_hosts = clean_hosts(str_hosts)

        # If no hosts were returned (or an error occurred fetching them)
        # Jump to the next host file
        if not str_hosts:
            continue

        # Update the hosts set
        set_hosts.update(str_hosts.splitlines())

    return set_hosts


def convert_hosts_to_restrictive_filters(set_hosts):

    if not set_hosts:
        return

    # Create string from set_hosts
    str_hosts = '\n'.join(set_hosts)
    # Remove www prefixes
    # providing there is at least one further dot (e.g. exclude www.be, www.fr)
    str_hosts = run_str_substitutions(str_hosts, {r'^www\.(?=(?:[^.\n]+\.){1,}[^.\n]+$)': ''})
    # Remove sub-domains
    # and add back to filter format
    set_hosts = {f'||{x}^' for x in str_hosts.splitlines()}

    return set_hosts


def fetch_regexps(urls_regex):

    if not urls_regex:
        return

    set_regexps = set()

    for url in urls_regex:

        # Read the regexps
        str_regexps = fetch_url(url)
        str_regexps = clean_regexps(str_regexps)

        # Conditional skip
        if not str_regexps:
            continue

        # Update regexps set in the correct format
        set_regexps.update(f'/{r}/' for r in str_regexps.splitlines())

    return set_regexps


def fetch_filters(urls_filters):

    if not urls_filters:
        return

    set_filters = set()

    # For each host file
    for url in urls_filters:

        # Fetch the hosts
        str_filters = fetch_url(url)
        str_filters = clean_filters(str_filters)

        # If no hosts were returned (or an error occurred fetching them)
        # Jump to the next host file
        if not str_filters:
            continue

        # Add to array (append)
        set_filters.update(str_filters.splitlines())

    return set_filters


def parse_hosts_and_filters(set_hosts_and_filters, path_includes, file_filter_whitelist):

    if not set_hosts_and_filters:
        return

    set_restrictive_filters = set()
    set_whitelist = set()

    # Filter pattern to match ||test.com^
    valid_filter_pattern = re.compile(r'^\|\|([a-z0-9_.-]+)\^$', flags=re.M)
    # Whitelist pattern to match @@||test.com^ or @@||test.com^|
    valid_whitelist_pattern = re.compile(r'^@@\|\|([a-z0-9_.-]+)\^$', flags=re.M)

    # If a filter whitelist has been provided
    if file_filter_whitelist:
        # Join the file path / name
        file_filter_whitelist = os.path.join(path_includes, file_filter_whitelist)
        # If the path exists and it is a file
        if os.path.isfile(file_filter_whitelist):
            # Add each line that's not a comment to the whitelist set
            with open(file_filter_whitelist, 'r', encoding='UTF-8') as fOpen:
                set_whitelist.update(line for line in (line.strip() for line in fOpen)
                                     if line and not line.startswith(('!', '#')) and validatedomain(line))

    # Convert filters to string format
    str_hosts_and_filters = '\n'.join(set_hosts_and_filters)

    # Extract valid restrictive filters
    list_valid_filters = valid_filter_pattern.findall(str_hosts_and_filters)
    # Extract valid whitelist filters
    list_valid_whitelist = valid_whitelist_pattern.findall(str_hosts_and_filters)

    # If there are valid restrictive filters
    if list_valid_filters:
        # Add the valid domains to the restrictive filter set
        for domain in list_valid_filters:
            if validatedomain(domain):
                set_restrictive_filters.add(domain)

    # If there are valid whitelist filters
    if list_valid_whitelist:
        # Add the valid domains to the whitelist set
        for domain in list_valid_whitelist:
            if validatedomain(domain):
                set_whitelist.add(domain)

    # Remove exact matches between whitelist and restrictive filters
    set_restrictive_filters.difference_update(set_whitelist)

    # Add @@|| prefix and ^ suffix to verified whitelist matches
    set_whitelist = {f'@@||{x}^' for x in set_whitelist}

    # Remove sub-domains
    # Add || prefix and ^ suffix to set filters
    set_restrictive_filters = {f'||{x}^' for x in remove_subdomains(set_restrictive_filters)}

    return set.union(set_restrictive_filters, set_whitelist)


def output_required(set_content, path_output, file):

    # Initialise local_content
    set_local_content = set()
    # Store full file path
    file_path = os.path.join(path_output, file)

    # If the file already exists in the output directory
    if os.path.isfile(file_path):
        # Fetch the local file
        # without the added header comments
        with open(file_path, 'r', encoding='UTF-8') as fOpen:
            set_local_content.update(line for line in (line.strip() for line in fOpen)
                                     if line and not line.startswith(('!', '#')))

        # If the local copy was empty
        # output the file
        if not set_local_content:
            return True

        # If the local copy is identical to
        # the generated output
        if set_content == set_local_content:
            print('[i] No updates required for', file)
            return False
        else:
            return True

    # File does not exist
    else:
        return True


"""
def identify_wildcards(hosts, limit=50):

    # Conditionally exit if hosts not provided
    if not hosts:
        return

    # Create set to store wildcards
    wildcards = {}
    # Set prev tracker to None
    prev = None
    # Set iterator to 0
    i = 0
    # Reverse each host
    rev_hosts = [host[::-1] for host in hosts]
    # Sort reversed hosts
    rev_hosts.sort()

    # For each host
    for host in rev_hosts:
        # If the domain is not a subdomain of the previous
        # iteration
        if not host.startswith(f'{prev}.'):
            # If our previous host had more subdomains
            # than the limit
            if i >= limit:
                # Add to wildcards set
                wildcards[prev[::-1]] = i
            # Set previous domain to the current iteration
            prev = host
            # Reset the iterator
            i = 0
        else:
            # Current iteration is a subdomain of the last
            # so increment the counter
            i += 1

    # Sort dict on sub-domain count (desc)
    wildcards = {k: v for k, v in sorted(wildcards.items(), key=lambda x: x[1], reverse=True)}

    return wildcards
"""


def remove_subdomains(hosts):

    # Conditionally exit if hosts not provided
    if not hosts:
        return

    # Create set to store wildcards
    cleaned_hosts = set()
    # Set prev tracker to None
    prev = None
    # Reverse each host
    rev_hosts = [host[::-1] for host in hosts]
    # Sort reversed hosts
    rev_hosts.sort()

    # For each host
    for host in rev_hosts:
        # If the domain is not a subdomain of the previous
        # iteration
        if not host.startswith(f'{prev}.'):
            # Conditionally set rev_host depending on prev
            rev_host = prev[::-1] if prev else host[::-1]
            # Add to host set
            cleaned_hosts.add(rev_host)
            # Set previous domain to the current iteration
            prev = host

    return cleaned_hosts


class Output:

    def __init__(self, path_base: str, path_output: str, path_includes: str,
                 arr_sources: list, file_header: str, list_output: list,
                 file_name: str, description: str):

        self.path_base = path_base
        self.path_output = path_output
        self.path_includes = path_includes
        self.arr_sources = arr_sources
        self.file_header = file_header
        self.list_output = list_output
        self.file_name = file_name
        self.description = description

    def build_header(self):

        # Store header file path
        file_header = os.path.join(self.path_includes, self.file_header)

        # If header file exists
        if os.path.isfile(file_header):
            # Open it
            with open(file_header, 'r', encoding='UTF-8') as fOpen:
                # Add each line to list if not blank
                list_header = [line for line in (line.strip() for line in fOpen) if line]

            # If the header file is not empty
            if list_header:
                # Fetch the header
                # Join header and store in a string
                str_header = '\n'.join(list_header)
                # Set the comment character
                c = '!'
                # Get the current timestamp with timezone
                time_timestamp = datetime.now().astimezone().strftime('%d-%m-%Y %H:%M %Z')
                # Set default for description if none is set
                description = self.description or 'None'
                # Fetch the sources and put into string
                str_sources = '\n'.join([f'{c} {source}' for source in self.arr_sources]) or f'{c} None'

                # Set the replacement criteria
                dict_subs = \
                    {
                        '{c}': c,
                        '{title}': f'MMotti AdguardHome - {self.file_name}',
                        '{description}': description,
                        '{time_timestamp}': time_timestamp,
                        '{count}': f'{len(self.list_output):n}',
                        f'{c} {{arr_sources}}': str_sources
                    }

                # Run the replacements
                for k, v in dict_subs.items():
                    str_header = str_header.replace(k, v)

                return str_header

    def output_file(self):

        # Store the output path
        path_output = self.path_output
        # Output file path
        out_file = os.path.join(path_output, self.file_name)

        # Double check output folder exists
        if not os.path.exists(path_output):
            os.makedirs(path_output)

        # Set header to None by default
        str_header = self.build_header()

        # Output the file
        print(f'[i] Outputting {self.file_name} to:', path_output)
        with open(out_file, 'w', newline='\n', encoding='UTF-8') as f:
            if str_header:
                # Output header
                f.write(f'{str_header}\n')
            # Output hosts
            f.writelines(f'{host}\n' for host in self.list_output)
