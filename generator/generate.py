import resources
import os

# Initialise variables
set_hosts = set()
set_regexps = set()
set_filters = set()
set_hosts_and_filters = set()
set_man_whitelist = set()

# Store the base path
path_base = os.path.dirname(os.path.realpath(__file__))
# Read yaml settings
file_yaml = os.path.join(path_base, 'generate.yaml')
yaml_settings = resources.read_yaml_settings(file_yaml)

if yaml_settings:
    # Output directory
    path_output = yaml_settings['local_paths']['output'] or os.path.join(path_base, 'output')
    # Includes directory
    path_includes = yaml_settings['local_paths']['includes'] or os.path.join(path_base, 'includes')
    # Input files
    file_header = yaml_settings['file_include']['header'] or None
    # Domain whitelist
    file_filter_whitelist = yaml_settings['file_include']['filter_whitelist'] or None
    # Output files
    file_regex = yaml_settings['file_output']['regex']['name'] or 'regex.txt'
    desc_regex = yaml_settings['file_output']['regex']['desc'] or 'None'
    file_filters = yaml_settings['file_output']['filters']['name'] or 'filters.txt'
    desc_filters = yaml_settings['file_output']['filters']['desc'] or 'None'
    # Hosts
    h_urls = yaml_settings['remote_files']['hosts']
    # Regexps
    r_urls = yaml_settings['remote_files']['regex']
    # Filters
    f_urls = yaml_settings['remote_files']['filters']
else:
    raise Exception(f'[E] An error occurred whilst processing {file_yaml}')

# Check that the output and includes paths exist
# and create if not
if not os.path.isdir(path_output):
    os.makedirs(path_output)
if not os.path.isdir(path_includes):
    os.makedirs(path_includes)

if h_urls:
    # Gather hosts
    print('[i] Processing host files')
    set_hosts = resources.fetch_hosts(h_urls)
    # If hosts were returned
    if set_hosts:
        # Convert to filter format and add to 'hosts and filters' set
        print('[i] Converting hosts to filter format')
        set_hosts_and_filters.update(resources.convert_hosts_to_restrictive_filters(set_hosts))

# If there are filter files specified
if f_urls:
    # Fetch the filters
    print('[i] Processing filter files')
    set_filters = resources.fetch_filters(f_urls)
    # If filters were returned
    if set_filters:
        set_hosts_and_filters.update(set_filters)

# Extract valid restrictive filters and necessary
# whitelist filters
if set_hosts_and_filters:
    print('[i] Parsing filters')
    set_hosts_and_filters = resources.parse_filters(set_hosts_and_filters, path_includes, file_filter_whitelist)

# If there are regexp urls specified
if r_urls:
    # Fetch the regexps
    print('[i] Processing regex files')
    set_regexps.update(resources.fetch_regexps(r_urls))

print('[i} Checking output requirements')

# Conditionally output filters
if set_hosts_and_filters and resources.output_required(set_hosts_and_filters, path_output, file_filters):
    # Output to file
    resources.Output(path_base, path_output, path_includes, sorted(h_urls + f_urls),
                     file_header, sorted(set_hosts_and_filters), file_filters, 2, desc_filters).output_file()

# Conditionally output regex
if set_regexps and resources.output_required(set_regexps, path_output, file_regex):
    # Output regexps to file
    resources.Output(path_base, path_output, path_includes, sorted(r_urls),
                     file_header, sorted(set_regexps), file_regex, 1, desc_regex).output_file()
