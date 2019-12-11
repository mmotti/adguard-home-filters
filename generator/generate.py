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
settings_yaml = resources.read_yaml_settings(file_yaml)

if settings_yaml:
    # Output directory
    path_output = settings_yaml['local_paths']['output'] or os.path.join(path_base, 'output')
    # Includes directory
    path_includes = settings_yaml['local_paths']['includes'] or os.path.join(path_base, 'includes')
    # Input files
    file_header = settings_yaml['file_include']['header'] or None
    # Domain whitelist
    file_filter_whitelist = settings_yaml['file_include']['filter_whitelist'] or None
    # Output files
    file_regex = settings_yaml['file_output']['regex']['name'] or 'regex.txt'
    desc_regex = settings_yaml['file_output']['regex']['desc'] or 'None'
    file_filters = settings_yaml['file_output']['filters']['name'] or 'filters.txt'
    desc_filters = settings_yaml['file_output']['filters']['desc'] or 'None'
    # Hosts
    urls_hostfiles = settings_yaml['remote_files']['hosts']
    # Regexps
    urls_regex = settings_yaml['remote_files']['regex']
    # Filters
    urls_filters = settings_yaml['remote_files']['filters']
else:
    raise Exception(f'[E] An error occurred whilst processing {file_yaml}')

# Check that the output and includes paths exist
# and create if not
if not os.path.isdir(path_output):
    os.makedirs(path_output)
if not os.path.isdir(path_includes):
    os.makedirs(path_includes)

if urls_hostfiles:
    # Gather hosts
    print('[i] Processing host files')
    set_hosts = resources.fetch_hosts(urls_hostfiles)
    # If hosts were returned
    if set_hosts:
        # Convert to filter format and add to 'hosts and filters' set
        print('[i] Converting hosts to filter format')
        set_hosts_and_filters.update(resources.convert_hosts_to_restrictive_filters(set_hosts))

# If there are filter files specified
if urls_filters:
    # Fetch the filters
    print('[i] Processing filter files')
    set_filters = resources.fetch_filters(urls_filters)
    # If filters were returned
    if set_filters:
        set_hosts_and_filters.update(set_filters)

# Extract valid restrictive filters and necessary
# whitelist filters
if set_hosts_and_filters:
    print('[i] Parsing filters')
    set_hosts_and_filters = resources.parse_hosts_and_filters(set_hosts_and_filters, path_includes, file_filter_whitelist)

# If there are regexp urls specified
if urls_regex:
    # Fetch the regexps
    print('[i] Processing regex files')
    set_regexps.update(resources.fetch_regexps(urls_regex))

print('[i} Checking output requirements')

# Conditionally output filters
if set_hosts_and_filters and resources.output_required(set_hosts_and_filters, path_output, file_filters):
    # Output to file
    resources.Output(path_base, path_output, path_includes, sorted(urls_hostfiles + urls_filters),
                     file_header, sorted(set_hosts_and_filters), file_filters, desc_filters).output_file()

# Conditionally output regex
if set_regexps and resources.output_required(set_regexps, path_output, file_regex):
    # Output regexps to file
    resources.Output(path_base, path_output, path_includes, sorted(urls_regex),
                     file_header, sorted(set_regexps), file_regex, desc_regex).output_file()