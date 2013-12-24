#!/usr/bin/python
# encoding: utf-8

import socket, os, sys, time, re, signal, math, tempfile

try:
    set()
except NameError:
    from sets import Set as set

if sys.stdout.isatty():
    tty_red       = '\033[31m'
    tty_green     = '\033[32m'
    tty_yellow    = '\033[33m'
    tty_blue      = '\033[34m'
    tty_magenta   = '\033[35m'
    tty_cyan      = '\033[36m'
    tty_white     = '\033[37m'
    tty_bgblue    = '\033[44m'
    tty_bgmagenta = '\033[45m'
    tty_bgwhite   = '\033[47m'
    tty_bold      = '\033[1m'
    tty_underline = '\033[4m'
    tty_normal    = '\033[0m'
    tty_ok        = tty_green + tty_bold + 'OK' + tty_normal
    def tty(fg=-1, bg=-1, attr=-1):
        if attr >= 0:
            return "\033[3%d;4%d;%dm" % (fg, bg, attr)
        elif bg >= 0:
            return "\033[3%d;4%dm" % (fg, bg)
        elif fg >= 0:
            return "\033[3%dm" % fg
        else:
            return tty_normal
else:
    tty_red       = ''
    tty_green     = ''
    tty_yellow    = ''
    tty_blue      = ''
    tty_magenta   = ''
    tty_cyan      = ''
    tty_white     = ''
    tty_bgblue    = ''
    tty_bgmagenta = ''
    tty_bold      = ''
    tty_underline = ''
    tty_normal    = ''
    tty_ok        = 'OK'
    def tty(fg=-1, bg=-1, attr=-1):
        return ''

g_dns_cache                  = {}
g_infocache                  = {} # In-memory cache of host info.
g_agent_already_contacted    = {} # do we have agent data from this host?
g_counters                   = {} # storing counters of one host
g_hostname                   = "unknown" # Host currently being checked
g_aggregated_service_results = {}   # store results for later submission
compiled_regexes             = {}   # avoid recompiling regexes
nagios_command_pipe          = None # Filedescriptor to open nagios command pipe.
checkresult_file_fd          = None
checkresult_file_path        = None
g_single_oid_hostname        = None
g_single_oid_cache           = {}
g_broken_snmp_hosts          = set([])
g_broken_agent_hosts         = set([])


opt_dont_submit              = False
opt_showplain                = False
opt_showperfdata             = False
opt_use_cachefile            = False
opt_no_tcp                   = False
opt_no_cache                 = False
opt_no_snmp_hosts            = False
opt_use_snmp_walk            = False
opt_cleanup_autochecks       = False
fake_dns                     = False

def interrupt_handler(signum, frame):
    sys.stderr.write('<Interrupted>\n')
    sys.exit(1)
signal.signal(signal.SIGINT, interrupt_handler)

class MKGeneralException(Exception):
    def __init__(self, reason):
        self.reason = reason
    def __str__(self):
        return self.reason

class MKCounterWrapped(Exception):
    def __init__(self, countername, reason):
        self.name = countername
        self.reason = reason
    def __str__(self):
        return '%s: %s' % (self.name, self.reason)

class MKAgentError(Exception):
    def __init__(self, reason):
        self.reason = reason
    def __str__(self):
        return self.reason

class MKSNMPError(Exception):
    def __init__(self, reason):
        self.reason = reason
    def __str__(self):
        return self.reason


def summary_hostname(hostname):
    return aggr_summary_hostname % hostname

def store_aggregated_service_result(hostname, detaildesc, aggrdesc, newstatus, newoutput):
    global g_aggregated_service_results
    count, status, outputlist = g_aggregated_service_results.get(aggrdesc, (0, 0, []))
    if status_worse(newstatus, status):
        status = newstatus
    if newstatus > 0 or aggregation_output_format == "multiline":
        outputlist.append( (newstatus, detaildesc, newoutput) )
    g_aggregated_service_results[aggrdesc] = (count + 1, status, outputlist)

def status_worse(newstatus, status):
    if status == 2:
        return False # nothing worse then critical
    elif newstatus == 2:
        return True  # nothing worse then critical
    else:
        return newstatus > status # 0 < 1 < 3 are in correct order

def submit_aggregated_results(hostname):
    if not host_is_aggregated(hostname):
        return

    if opt_verbose:
        print "\n%s%sAggregates Services:%s" % (tty_bold, tty_blue, tty_normal)
    global g_aggregated_service_results
    items = g_aggregated_service_results.items()
    items.sort()
    aggr_hostname = summary_hostname(hostname)
    for servicedesc, (count, status, outputlist) in items:
        if aggregation_output_format == "multiline":
            longoutput = ""
            statuscounts = [ 0, 0, 0, 0 ]
            for itemstatus, item, output in outputlist:
                longoutput += '\\n%s: %s' % (item, output)
                statuscounts[itemstatus] = statuscounts[itemstatus] + 1
            summarytexts = [ "%d service%s %s" % (x[0], x[0] != 1 and "s" or "", x[1])
                           for x in zip(statuscounts, ["OK", "WARN", "CRIT", "UNKNOWN" ]) if x[0] > 0 ]
            text = ", ".join(summarytexts) + longoutput
        else:
            if status == 0:
                text = "OK - %d services OK" % count
            else:
                text = " *** ".join([ item + " " + output for itemstatus, item, output in outputlist ])

        if not opt_dont_submit:
            submit_to_nagios(aggr_hostname, servicedesc, status, text)

        if opt_verbose:
            color = { 0: tty_green, 1: tty_yellow, 2: tty_red, 3: tty_magenta }[status]
            lines = text.split('\\n')
            print "%-20s %s%s%-70s%s" % (servicedesc, tty_bold, color, lines[0], tty_normal)
            if len(lines) > 1:
                for line in lines[1:]:
                    print "  %s" % line
                print "-------------------------------------------------------------------------------"



def submit_check_mk_aggregation(hostname, status, output):
    if not host_is_aggregated(hostname):
        return

    if not opt_dont_submit:
        submit_to_nagios(summary_hostname(hostname), "Check_MK", status, output)

    if opt_verbose:
        color = { 0: tty_green, 1: tty_yellow, 2: tty_red, 3: tty_magenta }[status]
        print "%-20s %s%s%-70s%s" % ("Check_MK", tty_bold, color, output, tty_normal)









def get_host_info(hostname, ipaddress, checkname):

    add_nodeinfo = check_info.get(checkname, {}).get("node_info", False)

    nodes = nodes_of(hostname)
    if nodes != None:
        info = []
        at_least_one_without_exception = False
        exception_texts = []
        global opt_use_cachefile
        opt_use_cachefile = True
	is_snmp_error = False
        for node in nodes:
            try:
                ipaddress = lookup_ipaddress(node)
                new_info = get_realhost_info(node, ipaddress, checkname, cluster_max_cachefile_age)
                if add_nodeinfo:
                    new_info = [ [node] + line for line in new_info ]
                info += new_info
                at_least_one_without_exception = True
            except MKAgentError, e:
		if str(e) != "": # only first error contains text
                    exception_texts.append(str(e))
		g_broken_agent_hosts.add(node)
            except MKSNMPError, e:
		if str(e) != "": # only first error contains text
		    exception_texts.append(str(e))
		g_broken_snmp_hosts.add(node)
		is_snmp_error = True
        if not at_least_one_without_exception:
	    if is_snmp_error:
                raise MKSNMPError(", ".join(exception_texts))
            else:
                raise MKAgentError(", ".join(exception_texts))
        return info
    else:
        info = get_realhost_info(hostname, ipaddress, checkname, check_max_cachefile_age)
        if add_nodeinfo:
            return [ [ None ] + line for line in info ]
        else:
            return info

def get_realhost_info(hostname, ipaddress, check_type, max_cache_age):
    info = get_cached_hostinfo(hostname)
    if info and info.has_key(check_type):
        return info[check_type]

    cache_relpath = hostname + "." + check_type

    oid_info = snmp_info.get(check_type.split(".")[0])
    if oid_info:
        content = read_cache_file(cache_relpath, max_cache_age)
        if content:
            return eval(content)

	if hostname in g_broken_snmp_hosts:
	    raise MKSNMPError("")

        try:
            if type(oid_info) == list:
                table = [ get_snmp_table(hostname, ipaddress, entry) for entry in oid_info ]
                if None in table:
                    table = None
            else:
                table = get_snmp_table(hostname, ipaddress, oid_info)
        except:
            if opt_debug:
                raise
            else:
                raise MKGeneralException("Incomplete or invalid response from SNMP agent")

        store_cached_checkinfo(hostname, check_type, table)
        write_cache_file(cache_relpath, repr(table) + "\n")
        return table

    if g_agent_already_contacted.has_key(hostname):
	raise MKAgentError("")

    g_agent_already_contacted[hostname] = True
    store_cached_hostinfo(hostname, []) # leave emtpy info in case of error

    output = get_agent_info(hostname, ipaddress, max_cache_age)
    if len(output) == 0:
        raise MKAgentError("Empty output from agent")
    elif len(output) < 16:
        raise MKAgentError("Too short output from agent: '%s'" % output)

    lines = [ l.strip() for l in output.split('\n') ]
    info = parse_info(lines)
    store_cached_hostinfo(hostname, info)
    return info.get(check_type, []) # return only data for specified check


def read_cache_file(relpath, max_cache_age):
    cachefile = tcp_cache_dir + "/" + relpath
    if os.path.exists(cachefile) and (
        (opt_use_cachefile and ( not opt_no_cache ) )
        or (simulation_mode and not opt_no_cache) ):
        if cachefile_age(cachefile) <= max_cache_age or simulation_mode:
            f = open(cachefile, "r")
            result = f.read(10000000)
            f.close()
            if len(result) > 0:
                if opt_debug:
                    sys.stderr.write("Using data from cachefile %s.\n" % cachefile)
                return result
        elif opt_debug:
            sys.stderr.write("Skipping cache file %s: Too old\n" % cachefile)

    if simulation_mode and not opt_no_cache:
        raise MKGeneralException("Simulation mode and no cachefile present.")

    if opt_no_tcp:
        raise MKGeneralException("Host is unreachable")


def write_cache_file(relpath, output):
    cachefile = tcp_cache_dir + "/" + relpath
    if not os.path.exists(tcp_cache_dir):
        try:
            os.makedirs(tcp_cache_dir)
        except Exception, e:
            raise MKGeneralException("Cannot create directory %s: %s" % (tcp_cache_dir, e))
    try:
        if not i_am_root():
            f = open(cachefile, "w+")
            f.write(output)
            f.close()
    except Exception, e:
        raise MKGeneralException("Cannot write cache file %s: %s" % (cachefile, e))


def get_agent_info(hostname, ipaddress, max_cache_age):
    output = read_cache_file(hostname, max_cache_age)
    if not output:
        if hostname in g_broken_agent_hosts:
            raise MKAgentError("")

        commandline = get_datasource_program(hostname, ipaddress)
        if commandline:
            output = get_agent_info_program(commandline)
        else:
            output = get_agent_info_tcp(hostname, ipaddress)

        write_cache_file(hostname, output)

    if agent_simulator:
        output = agent_simulator_process(output)

    return output

def get_agent_info_program(commandline):
    if opt_verbose:
        sys.stderr.write("Calling external programm %s\n" % commandline)
    try:
        sout = os.popen(commandline + " 2>/dev/null")
        output = sout.read()
        exitstatus = sout.close()
    except Exception, e:
        raise MKAgentError("Could not execute '%s': %s" % (commandline, e))

    if exitstatus:
        if exitstatus >> 8 == 127:
            raise MKAgentError("Programm '%s' not found (exit code 127)" % (commandline,))
        else:
            raise MKAgentError("Programm '%s' exited with code %d" % (commandline, exitstatus >> 8))
    return output

def get_agent_info_tcp(hostname, ipaddress):
    if not ipaddress:
        raise MKGeneralException("Cannot contact agent: host '%s' has no IP address." % hostname)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(tcp_connect_timeout)
        except:
            pass # some old Python versions lack settimeout(). Better ignore than fail
        s.connect((ipaddress, agent_port_of(hostname)))
        try:
            s.setblocking(1)
        except:
            pass
        output = ""
        while True:
            out = s.recv(4096, socket.MSG_WAITALL)
            if out and len(out) > 0:
                output += out
            else:
                break
        s.close()
        if len(output) == 0: # may be caused by xinetd not allowing our address
            raise MKAgentError("Empty output from agent at TCP port %d" %
                  agent_port_of(hostname))
        return output
    except MKAgentError, e:
        raise
    except Exception, e:
        raise MKAgentError("Cannot get data from TCP port %s:%d: %s" %
                           (ipaddress, agent_port_of(hostname), e))


def get_cached_hostinfo(hostname):
    global g_infocache
    return g_infocache.get(hostname, None)

def store_cached_hostinfo(hostname, info):
    global g_infocache
    oldinfo = get_cached_hostinfo(hostname)
    if oldinfo:
        oldinfo.update(info)
        g_infocache[hostname] = oldinfo
    else:
        g_infocache[hostname] = info

def store_cached_checkinfo(hostname, checkname, table):
    global g_infocache
    info = get_cached_hostinfo(hostname)
    if info:
        info[checkname] = table
    else:
        g_infocache[hostname] = { checkname: table }

def parse_info(lines):
    info = {}
    chunk = []
    chunkoptions = {}
    separator = None
    for line in lines:
        if line[:3] == '<<<' and line[-3:] == '>>>':
            chunkheader = line[3:-3]
            headerparts = chunkheader.split(":")
            chunkname = headerparts[0]
            chunkoptions = {}
            for o in headerparts[1:]:
                opt_parts = o.split("(")
                opt_name = opt_parts[0]
                if len(opt_parts) > 1:
                    opt_args = opt_parts[1][:-1]
                else:
                    opt_args = None
                chunkoptions[opt_name] = opt_args

            chunk = info.get(chunkname, None)
            if chunk == None: # chunk appears in output for the first time
                chunk = []
                info[chunkname] = chunk
            try:
                separator = chr(int(chunkoptions["sep"]))
            except:
                separator = None
        elif line != '':
            chunk.append(line.split(separator))
    return info


def cachefile_age(filename):
    try:
        return time.time() - os.stat(filename)[8]
    except Exception, e:
        raise MKGeneralException("Cannot determine age of cache file %s: %s" \
                                 % (filename, e))
        return -1



def load_counters(hostname):
    global g_counters
    filename = counters_directory + "/" + hostname
    try:
        g_counters = eval(file(filename).read())
    except:
        try:
            lines = file(filename).readlines()
            for line in lines:
                line = line.split()
                g_counters[' '.join(line[0:-2])] = ( int(line[-2]), int(line[-1]) )
        except:
            g_counters = {}

def get_counter(countername, this_time, this_val, allow_negative=False):
    global g_counters

    if not countername in g_counters:
        g_counters[countername] = (this_time, this_val)
        if opt_dont_submit:
            return 1.0, 0.0
        raise MKCounterWrapped(countername, 'Counter initialization')

    last_time, last_val = g_counters.get(countername)
    timedif = this_time - last_time
    if timedif <= 0: # do not update counter
        g_counters[countername] = (this_time, this_val)
        if opt_dont_submit:
            return 1.0, 0.0
        raise MKCounterWrapped(countername, 'No time difference')

    g_counters[countername] = (this_time, this_val)

    valuedif = this_val - last_val
    if valuedif < 0 and not allow_negative:
        if opt_dont_submit:
            return 1.0, 0.0
        raise MKCounterWrapped(countername, 'Value overflow')

    per_sec = float(valuedif) / timedif
    return timedif, per_sec


def get_average(itemname, this_time, this_val, backlog, initialize_zero = True):

    if not itemname in g_counters:
        if initialize_zero:
            this_val = 0
        g_counters[itemname] = (this_time, this_val)
        return 1.0, this_val # avoid time diff of 0.0 -> avoid division by zero

    last_time, last_val = g_counters.get(itemname)
    timedif = this_time - last_time

    if timedif < 0:
        timedif = 0

    percentile = 0.50

    weight_per_minute = (1 - percentile) ** (1.0 / backlog)

    weight = weight_per_minute ** (timedif / 60.0)

    new_val = last_val * weight + this_val * (1 - weight)


    g_counters[itemname] = (this_time, new_val)
    return timedif, new_val


def save_counters(hostname):
    if not opt_dont_submit and not i_am_root(): # never writer counters as root
        global g_counters
        filename = counters_directory + "/" + hostname
        try:
            if not os.path.exists(counters_directory):
                os.makedirs(counters_directory)
            file(filename, "w").write("%r\n" % g_counters)
        except Exception, e:
            raise MKGeneralException("User %s cannot write to %s: %s" % (username(), filename, e))




def do_check(hostname, ipaddress, only_check_types = None):

    if opt_verbose:
        sys.stderr.write("Check_mk version %s\n" % check_mk_version)

    start_time = time.time()

    try:
        load_counters(hostname)
        agent_version, num_success, error_sections, problems = do_all_checks_on_host(hostname, ipaddress, only_check_types)
        num_errors = len(error_sections)
        save_counters(hostname)
        if problems:
	    output = "CRIT - %s, " % problems
            status = 2
        elif num_errors > 0 and num_success > 0:
            output = "WARN - Missing agent sections: %s - " % ", ".join(error_sections)
            status = 1
        elif num_errors > 0:
            output = "CRIT - Got no information from host, "
            status = 2
        elif agent_min_version and agent_version < agent_min_version:
            output = "WARN - old plugin version %s (should be at least %s), " % (agent_version, agent_min_version)
            status = 1
        else:
            output = "OK - "
            if agent_version != None:
                output += "Agent version %s, " % agent_version
            status = 0

    except MKGeneralException, e:
        if opt_debug:
            raise
        output = "UNKNOWN - %s, " % e
        status = 3

    if aggregate_check_mk:
        try:
            submit_check_mk_aggregation(hostname, status, output)
        except:
            if opt_debug:
                raise

    if checkresult_file_fd != None:
        close_checkresult_file()

    run_time = time.time() - start_time
    if check_mk_perfdata_with_times:
        times = os.times()
        output += "execution time %.1f sec|execution_time=%.3f user_time=%.3f "\
                  "system_time=%.3f children_user_time=%.3f children_system_time=%.3f\n" %\
                (run_time, run_time, times[0], times[1], times[2], times[3])
    else:
        output += "execution time %.1f sec|execution_time=%.3f\n" % (run_time, run_time)

    sys.stdout.write(output)
    sys.exit(status)

def check_unimplemented(checkname, params, info):
    return (3, 'UNKNOWN - Check not implemented')

def convert_check_info():
    for check_type, info in check_info.items():
        basename = check_type.split(".")[0]

        if type(info) != dict:
            check_function, service_description, has_perfdata, inventory_function = info
            if inventory_function == no_inventory_possible:
                inventory_function = None

            check_info[check_type] = {
                "check_function"          : check_function,
                "service_description"     : service_description,
                "has_perfdata"            : not not has_perfdata,
                "inventory_function"      : inventory_function,
                "group"                   : checkgroup_of.get(check_type, check_type),
                "snmp_info"               : snmp_info.get(check_type),
                "snmp_scan_function"      :
                    snmp_scan_functions.get(check_type,
                        snmp_scan_functions.get(basename)),
                "default_levels_variable" : check_default_levels.get(check_type),
                "node_info"               : False,
            }
        else:
            info.setdefault("inventory_function", None)
            info.setdefault("group", None)
            info.setdefault("snmp_info", None)
            info.setdefault("snmp_scan_function", None)
            info.setdefault("default_levels_variable", None)
            info.setdefault("node_info", False)

            check_includes.setdefault(basename, [])
            check_includes[basename] += info.get("includes", [])

    for check_type, info in check_info.iteritems():
        if "." in check_type:
            base_check = check_type.split(".")[0]
            if base_check not in check_info:
                if info["node_info"]:
                    raise MKGeneralException("Invalid check implementation: node_info for %s is True, but base check %s not defined" %
                        (check_type, base_check))
            elif check_info[base_check]["node_info"] != info["node_info"]:
               raise MKGeneralException("Invalid check implementation: node_info for %s and %s are different." % (
                   (base_check, check_type)))

    for check_type, info in check_info.iteritems():
        basename = check_type.split(".")[0]
        if info["snmp_info"] and basename not in snmp_info:
            snmp_info[basename] = info["snmp_info"]
        if info["snmp_scan_function"] and basename not in snmp_scan_functions:
            snmp_scan_functions[basename] = info["snmp_scan_function"]

def do_all_checks_on_host(hostname, ipaddress, only_check_types = None):
    global g_aggregated_service_results
    g_aggregated_service_results = {}
    global g_hostname
    g_hostname = hostname
    num_success = 0
    error_sections = set([])
    check_table = get_sorted_check_table(hostname)
    problems = []

    for checkname, item, params, description, info in check_table:
        if only_check_types != None and checkname not in only_check_types:
            continue

        period = check_period_of(hostname, description)
        if period and not check_timeperiod(period):
            if opt_debug:
                sys.stderr.write("Skipping service %s: currently not in timeperiod %s.\n" %
                        (description, period))
            continue
        elif period and opt_debug:
            sys.stderr.write("Service %s: timeperiod %s is currently active.\n" %
                    (description, period))

        if type(info) == str:
            aggrname = info
        else:
            aggrname = aggregated_service_name(hostname, description)

        infotype = checkname.split('.')[0]
        try:
	    info = get_host_info(hostname, ipaddress, infotype)
        except MKSNMPError, e:
	    if str(e):
	        problems.append(str(e))
            error_sections.add(infotype)
	    g_broken_snmp_hosts.add(hostname)
	    continue

        except MKAgentError, e:
	    if str(e):
                problems.append(str(e))
            error_sections.add(infotype)
	    g_broken_agent_hosts.add(hostname)
	    continue

        if info or info == []:
            num_success += 1
            try:
                check_function = check_info[checkname]["check_function"]
            except:
                check_function = check_unimplemented

            try:
                dont_submit = False
                result = check_function(item, params, info)
            except MKCounterWrapped, e:
                if opt_verbose:
                    print "Counter wrapped, not handled by check, ignoring this check result: %s" % e
                dont_submit = True
            except Exception, e:
                result = (3, "invalid output from agent, invalid check parameters or error in implementation of check %s. Please set <tt>debug_log</tt> to a filename in <tt>main.mk</tt> for enabling exception logging." % checkname)
                if debug_log:
                    try:
                        import traceback, pprint
                        l = file(debug_log, "a")
                        l.write(("Invalid output from plugin or error in check:\n"
                                "  Check_MK Version: %s\n"
                                "  Date:             %s\n"
                                "  Host:             %s\n"
                                "  Service:          %s\n"
                                "  Check type:       %s\n"
                                "  Item:             %r\n"
                                "  Parameters:       %s\n"
                                "  %s\n"
                                "  Agent info:       %s\n\n") % (
                                check_mk_version,
                                time.strftime("%Y-%d-%m %H:%M:%S"),
                                hostname, description, checkname, item, pprint.pformat(params),
                                traceback.format_exc().replace('\n', '\n      '),
                                pprint.pformat(info)))
                    except:
                        pass

                if opt_debug:
                    raise
            if not dont_submit:
                submit_check_result(hostname, description, result, aggrname)
        else:
            error_sections.add(infotype)

    submit_aggregated_results(hostname)

    try:
        if is_tcp_host(hostname):
            version_info = get_host_info(hostname, ipaddress, 'check_mk')
            agent_version = version_info[0][1]
        else:
            agent_version = None
    except MKAgentError, e:
	g_broken_agent_hosts.add(hostname)
        agent_version = "(unknown)"
    except:
        agent_version = "(unknown)"
    error_sections = list(error_sections)
    error_sections.sort()
    return agent_version, num_success, error_sections, ", ".join(problems)



def open_checkresult_file():
    global checkresult_file_fd
    global checkresult_file_path
    if checkresult_file_fd == None:
        try:
            checkresult_file_fd, checkresult_file_path = \
                tempfile.mkstemp('', 'c', check_result_path)
        except Exception, e:
            raise MKGeneralException("Cannot create check result file in %s: %s" %
                    (check_result_path, e))


def close_checkresult_file():
    global checkresult_file_fd
    if checkresult_file_fd != None:
        os.close(checkresult_file_fd)
        file(checkresult_file_path + ".ok", "w")
        checkresult_file_fd = None


def nagios_pipe_open_timeout(signum, stackframe):
    raise IOError("Timeout while opening pipe")


def open_command_pipe():
    global nagios_command_pipe
    if nagios_command_pipe == None:
        if not os.path.exists(nagios_command_pipe_path):
            nagios_command_pipe = False # False means: tried but failed to open
            raise MKGeneralException("Missing Nagios command pipe '%s'" % nagios_command_pipe_path)
        else:
            try:
                signal.signal(signal.SIGALRM, nagios_pipe_open_timeout)
                signal.alarm(3) # three seconds to open pipe
                nagios_command_pipe =  file(nagios_command_pipe_path, 'w')
                signal.alarm(0) # cancel alarm
            except Exception, e:
                nagios_command_pipe = False
                raise MKGeneralException("Error writing to command pipe: %s" % e)



def convert_perf_value(x):
    if x == None:
        return ""
    elif type(x) in [ str, unicode ]:
        return x
    elif type(x) == float:
        return ("%.6f" % x).rstrip("0").rstrip(".")
    else:
        return str(x)

def convert_perf_data(p):
    p = (map(convert_perf_value, p) + ['','','',''])[0:6]
    return "%s=%s;%s;%s;%s;%s" %  tuple(p)


def submit_check_result(host, servicedesc, result, sa):
    if len(result) >= 3:
        state, infotext, perfdata = result[:3]
    else:
        state, infotext = result
        perfdata = None

    if not (
        infotext.startswith("OK -") or
        infotext.startswith("WARN -") or
        infotext.startswith("CRIT -") or
        infotext.startswith("UNKNOWN -")):
        infotext = nagios_state_names[state] + " - " + infotext

    global nagios_command_pipe

    if sa != "":
        store_aggregated_service_result(host, servicedesc, sa, state, infotext)

    perftexts = [];
    perftext = ""

    if perfdata:
        if len(perfdata) > 0 and type(perfdata[-1]) == str:
            check_command = perfdata[-1]
            del perfdata[-1]
        else:
            check_command = None

        for p in perfdata:
            perftexts.append(convert_perf_data(p))

        if perftexts != []:
            if check_command and perfdata_format == "pnp":
                perftexts.append("[%s]" % check_command)
            perftext = "|" + (" ".join(perftexts))

    if not opt_dont_submit:
        submit_to_nagios(host, servicedesc, state, infotext + perftext)

    if opt_verbose:
        if opt_showperfdata:
            p = ' (%s)' % (" ".join(perftexts))
        else:
            p = ''
        color = { 0: tty_green, 1: tty_yellow, 2: tty_red, 3: tty_magenta }[state]
        print "%-20s %s%s%-56s%s%s" % (servicedesc, tty_bold, color, infotext, tty_normal, p)


def submit_to_nagios(host, service, state, output):
    if check_submission == "pipe":
        open_command_pipe()
        if nagios_command_pipe:
            nagios_command_pipe.write("[%d] PROCESS_SERVICE_CHECK_RESULT;%s;%s;%d;%s\n" %
                                   (int(time.time()), host, service, state, output)  )
            nagios_command_pipe.flush()
    elif check_submission == "file":
        open_checkresult_file()
        if checkresult_file_fd:
            now = time.time()
            os.write(checkresult_file_fd,
                """host_name=%s
service_description=%s
check_type=1
check_options=0
reschedule_check
latency=0.0
start_time=%.1f
finish_time=%.1f
return_code=%d
output=%s

""" % (host, service, now, now, state, output))
    else:
        raise MKGeneralException("Invalid setting %r for check_submission. Must be 'pipe' or 'file'" % check_submission)



def username():
    import pwd
    return pwd.getpwuid(os.getuid())[0]

def i_am_root():
    return os.getuid() == 0

def nodes_of(hostname):
    for tagged_hostname, nodes in clusters.items():
        if hostname == tagged_hostname.split("|")[0]:
            return nodes
    return None




def within_range(value, minv, maxv):
    if value >= 0: return value >= minv and value <= maxv
    else: return value <= minv and value >= maxv

def get_regex(pattern):
    reg = compiled_regexes.get(pattern)
    if not reg:
        reg = re.compile(pattern)
        compiled_regexes[pattern] = reg
    return reg

nagios_state_names = ["OK", "WARN", "CRIT", "UNKNOWN"]

def saveint(i):
    try:
        return int(i)
    except:
        return 0

def savefloat(f):
    try:
        return float(f)
    except:
        return 0.0

def get_bytes_human_readable(b, base=1024.0, bytefrac=True, unit="B"):
    base = float(base)
    prefix = ''
    if b < 0:
        prefix = '-'
        b *= -1

    if b >= base * base * base * base:
        return '%s%.2fT%s' % (prefix, b / base / base / base / base, unit)
    elif b >= base * base * base:
        return '%s%.2fG%s' % (prefix, b / base / base / base, unit)
    elif b >= base * base:
        return '%s%.2fM%s' % (prefix, b / base / base, unit)
    elif b >= base:
        return '%s%.2fk%s' % (prefix, b / base, unit)
    elif bytefrac:
        return '%s%.2f%s' % (prefix, b, unit)
    else: # Omit byte fractions
        return '%s%.0f%s' % (prefix, b, unit)

def get_filesize_human_readable(size):
    if size < 4 * 1024 * 1024:
        return str(size)
    elif size < 4 * 1024 * 1024 * 1024:
        return "%.2fMB" % (float(size) / (1024 * 1024))
    else:
        return "%.2fGB" % (float(size) / (1024 * 1024 * 1024))


def get_nic_speed_human_readable(speed):
    try:
        speedi = int(speed)
        if speedi == 10000000:
            speed = "10MBit/s"
        elif speedi == 100000000:
            speed = "100MBit/s"
        elif speedi == 1000000000:
            speed = "1GBit/s"
        elif speed < 1500:
            speed = "%dBit/s" % speedi
        elif speed < 1000000:
            speed = "%.1fKBit/s" % (speedi / 1000.0)
        elif speed < 1000000000:
            speed = "%.2fMBit/s" % (speedi / 1000000.0)
        else:
            speed = "%.2fGBit/s" % (speedi / 1000000000.0)
    except:
        pass
    return speed

def to_celsius(f):
    return round(float(f) - 32.0) * 5.0 / 9.0

def get_age_human_readable(secs):
    if secs < 240:
        return "%d sec" % secs
    mins = secs / 60
    if mins < 120:
        return "%d min" % mins
    hours, mins = divmod(mins, 60)
    if hours < 12:
        return "%d hours, %d min" % (hours, mins)
    if hours < 48:
        return "%d hours" % hours
    days, hours = divmod(hours, 24)
    if days < 7:
        return "%d days, %d hours" % (days, hours)
    return "%d days" % days

def quote_shell_string(s):
    return "'" + s.replace("'", "'\"'\"'") + "'"


g_inactive_timerperiods = None
def check_timeperiod(timeperiod):
    global g_inactive_timerperiods
    if g_inactive_timerperiods == None:
        import socket
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(livestatus_unix_socket)
        s.send("GET timeperiods\nColumns:name\nFilter: in = 0\n")
        s.shutdown(socket.SHUT_WR)
        g_inactive_timerperiods = s.recv(10000000).splitlines()
    return timeperiod not in g_inactive_timerperiods


# very simple commandline parsing: only -v and -d are supported
opt_verbose = '-v' in sys.argv
opt_debug   = '-d' in sys.argv

# make sure these names are defined (even if never needed)
no_inventory_possible = None

# Global variables
check_mk_version = '1.2.2p3'
tcp_connect_timeout = 5.0
agent_min_version = 0
perfdata_format = 'pnp'
aggregation_output_format = 'multiline'
aggr_summary_hostname = '%s-s'
nagios_command_pipe_path = '/var/lib/nagios3/rw/nagios.cmd'
check_result_path = '/var/lib/nagios3/spool/checkresults'
check_submission = 'file'
var_dir = '/home/nagios/check_mk/var'
counters_directory = '/home/nagios/check_mk/var/counters'
tcp_cache_dir = '/home/nagios/check_mk/var/cache'
snmpwalks_dir = '/home/nagios/check_mk/var/snmpwalks'
check_mk_basedir = '/home/nagios/check_mk'
nagios_user = 'nagios'
www_group = 1001
cluster_max_cachefile_age = 90
check_max_cachefile_age = 0
simulation_mode = False
agent_simulator = False
aggregate_check_mk = False
debug_log = None
check_mk_perfdata_with_times = False
livestatus_unix_socket = '/var/lib/nagios3/rw/live'

# Checks for host1

def get_sorted_check_table(hostname):
    return [('cpu.loads', None, (5, 10), 'CPU load', ''), ('kernel.util', None, None, 'CPU utilization', ''), ('diskstat', 'SUMMARY', {}, 'Disk IO SUMMARY', ''), ('lnx_if', '2', {'state': ['1'], 'errors': (0.01, 0.1)}, 'Interface 2', ''), ('lnx_if', '4', {'state': ['1'], 'errors': (0.01, 0.1)}, 'Interface 4', ''), ('lnx_if', '8', {'state': ['1'], 'errors': (0.01, 0.1)}, 'Interface 8', ''), ('kernel', 'Context Switches', None, 'Kernel Context Switches', ''), ('kernel', 'Major Page Faults', None, 'Kernel Major Page Faults', ''), ('kernel', 'Process Creations', None, 'Kernel Process Creations', ''), ('mem.used', None, (150.0, 200.0), 'Memory used', ''), ('mounts', '/', ['data=ordered', 'errors=remount-ro', 'relatime', 'rw'], 'Mount options of /', ''), ('mounts', '/boot', ['errors=continue', 'relatime', 'rw'], 'Mount options of /boot', ''), ('cpu.threads', None, (2000, 4000), 'Number of threads', ''), ('tcp_conn_stats', None, {}, 'TCP Connections', ''), ('uptime', None, None, 'Uptime', ''), ('df', '/', {'levels_low': (50, 60), 'magic_normsize': 20, 'levels': (80, 90), 'trend_range': 24, 'trend_perfdata': True}, 'fs_/', ''), ('df', '/boot', {'levels_low': (50, 60), 'magic_normsize': 20, 'levels': (80, 90), 'trend_range': 24, 'trend_perfdata': True}, 'fs_/boot', '')]

precompiled_service_timeperiods = {}
def check_period_of(hostname, service):
    return precompiled_service_timeperiods.get(service)

check_info = {}
check_includes = {}
precompile_params = {}
factory_settings = {}
checkgroup_of = {}
check_config_variables = []
check_default_levels = {}
snmp_info = {}
snmp_scan_functions = {}
# /home/nagios/check_mk/checks/kernel

inventory_kernel_counters = [ "pgmajfault", "ctxt", "processes" ]
kernel_default_levels = None

kernel_counter_names = {
  "ctxt"       : "Context Switches",
  "processes"  : "Process Creations",
  "pgmajfault" : "Major Page Faults",
}

def inventory_kernel(info):
    inventory = []
    for counter in inventory_kernel_counters:
        hits = [ line[0] for line in info[1:] if line[0] == counter ]
        if len(hits) == 1:
            countername = kernel_counter_names.get(counter, counter)
            inventory.append( (countername, "kernel_default_levels") )
    return inventory


def check_kernel(item, params, info):
    this_time = int(info[0][0])

    hits = [ (line[0], line[1])
             for line in info[1:]
             if line[0] == item or kernel_counter_names.get(line[0], line[0]) == item ]
    if len(hits) == 0:
        return (3, "UNKNOWN - item '%s' not found in agent output" % item)
    elif len(hits) > 1:
        return (3, "UNKNOWN - item '%s' not unique (found %d times)" % (item, len(hits)))

    counter = hits[0][0]
    this_val = int(hits[0][1])
    timedif, per_sec = get_counter("kernel." + item, this_time, this_val)
    infotext = " - %.0f/s in last %d secs" % (per_sec, timedif)

    if params == None:
        return (0, "OK" + infotext, [ (counter, per_sec) ])

    warn, crit = params
    perfdata = [ (counter, per_sec, warn, crit) ]
    if warn == None and crit != None:
        infotext += " (critical at %.0f/s)" % crit
    elif warn != None and crit == None:
        infotext += " (warning at %.0f/s)" % warn
    elif warn != None:
        infotext += " (warn/crit at %.0f/%.0f per sec)" % (warn, crit)

    if crit != None and per_sec >= crit:
        return (2, "CRIT" + infotext, perfdata)
    elif warn != None and per_sec >= warn:
        return (1, "WARN" + infotext, perfdata)
    else:
        return (0, "OK" + infotext, perfdata)

kernel_util_default_levels = None

def inventory_cpu_utilization(info):
    for x in info:
        if len(x) > 0 and x[0] == 'cpu':
            return [(None, "kernel_util_default_levels")]

def check_cpu_utilization(item, params, info):
    global g_counters
    f = [ l for l in info if l[0] == "cpu" ]
    if len(f) != 1:
        return (3, "UNKNOWN - invalid output from plugin")
    line = f[0]
    if len(line) < 8:
        line = line + ['0', '0', '0', '0'] # needed for Linux 2.4

    values = [ int(x) for x in line[1:8] ]
    this_time = int(time.time())
    diff_values = []
    n = 0
    for v in values:
        n += 1
        countername = "cpu.util.%d" % n
        last_time, last_val = g_counters.get(countername, (0, 0))
        diff_values.append(v - last_val)
        g_counters[countername] = (this_time, v)

    sum_jiffies = sum(diff_values[0:7]) # do not account for steal!
    if sum_jiffies == 0:
        return (0, "OK - too short interval")
    user        = diff_values[0] + diff_values[1] # add user + nice
    system      = diff_values[2]
    wait        = diff_values[4]
    user_perc   = 100.0 * float(user)   / float(sum_jiffies)
    system_perc = 100.0 * float(system) / float(sum_jiffies)
    wait_perc   = 100.0 * float(wait)   / float(sum_jiffies)
    perfdata = [
          ( "user",   "%.3f" % user_perc ),
          ( "system", "%.3f" % system_perc ),
          ( "wait",   "%.3f" % wait_perc ) ]

    infotext = " - user: %2.1f%%, system: %2.1f%%, wait: %2.1f%%" % (user_perc, system_perc, wait_perc)

    result = 0
    try:
        warn, crit = params
        if wait_perc >= crit:
            result = 2
            infotext += "(!!)"
        elif wait_perc >= warn:
            result = 1
            infotext += "(!)"
    except:
        pass

    return (result, nagios_state_names[result] + infotext, perfdata)

check_info['kernel.util'] = (check_cpu_utilization, "CPU utilization", 1,  inventory_cpu_utilization)
checkgroup_of['kernel.util'] = "cpu_iowait"

check_info['kernel'] = (check_kernel, "Kernel %s", 1,  inventory_kernel)
checkgroup_of['kernel'] = "vm_counter"


# /home/nagios/check_mk/checks/uptime

def inventory_uptime(info):
    if len(info) >= 1 and len(info[0]) >= 1:
        return [ (None, None) ]

def check_uptime(_no_item, _no_params, info):
    uptime = int(float(info[0][0]))
    seconds = uptime % 60
    rem = uptime / 60
    minutes = rem % 60
    hours = (rem % 1440) / 60
    days = rem / 1440
    now = int(time.time())
    since = time.strftime("%c", time.localtime(now - uptime))
    return (0, "OK - up since %s (%dd %02d:%02d:%02d)" % (since, days, hours, minutes, seconds), [ ("uptime", uptime) ])


check_info["uptime"] = (check_uptime, "Uptime", 1, inventory_uptime)
checkgroup_of["uptime"] = "uptime"


# /home/nagios/check_mk/checks/df.include


filesystem_levels         = [] # obsolete. Just here to check config and warn if changed
filesystem_default_levels = {} # can also be dropped some day in future

inventory_df_exclude_fs            = [ 'nfs', 'smbfs', 'cifs', 'iso9660' ]
inventory_df_exclude_mountpoints   = [ '/dev' ]

filesystem_groups = []


factory_settings["filesystem_default_levels"] = {
    "levels"          : (80, 90), # warn/crit in percent
    "magic_normsize"  : 20,       # Standard size if 20 GB
    "levels_low"      : (50, 60), # Never move warn level below 50% due to magic factor
    "trend_range"     : 24,
    "trend_perfdata"  : True,    # do send performance data for trends
}

def df_inventory(mplist):
    import fnmatch
    group_patterns = {}
    for line in host_extra_conf(g_hostname, filesystem_groups):
        for group_name, pattern in line:
            group_patterns.setdefault(group_name, []).append(pattern)

    inventory = []
    have_groups = set([])
    for mp in mplist:
        in_group = False
        for group_name, patterns in group_patterns.items():
            for pattern in patterns:
                if fnmatch.fnmatch(mp, pattern):
                    have_groups.add(group_name)
                    in_group = True
                    break
        if not in_group:
            inventory.append((mp, {}))

    for group_name in have_groups:
        inventory.append((group_name, { "patterns" : group_patterns[group_name] }))

    return inventory



def get_filesystem_levels(host, mountpoint, size_gb, params):

    levels = factory_settings["filesystem_default_levels"].copy()
    if type(filesystem_default_levels) == dict:
        levels.update(filesystem_default_levels)
    else:
        levels = factory_settings["filesystem_default_levels"].copy()
        levels["levels"] = filesystem_default_levels[:2]
        if len(filesystem_default_levels) == 2:
            levels["magic"] = None
        else:
            levels["magic"] = filesystem_default_levels[2]

    if type(params) == dict:
        levels.update(params)

    else: # simple format - explicitely override levels and magic
        levels["levels"] = params[:2]
        if len(params) >= 3:
            levels["magic"] = params[2]

    warn, crit = levels["levels"]

    magic = levels.get("magic")
    if magic:
        normsize = levels["magic_normsize"]
        hgb_size = size_gb / float(normsize)
        felt_size = hgb_size ** magic
        scale = felt_size / hgb_size
        warn_scaled = 100 - (( 100 - warn ) * scale)
        crit_scaled = 100 - (( 100 - crit ) * scale)

        lowest_warning_level, lowest_critical_level = levels["levels_low"]
        if warn_scaled < lowest_warning_level:
            warn_scaled = lowest_warning_level
        if crit_scaled < lowest_critical_level:
            crit_scaled = lowest_critical_level
    else:
        warn_scaled = warn
        crit_scaled = crit

    size_mb     = size_gb * 1024
    warn_mb     = savefloat(size_mb * warn_scaled / 100)
    crit_mb     = savefloat(size_mb * crit_scaled / 100)
    levels["levels_mb"] = (warn_mb, crit_mb)
    levels["levels_text"] = "(levels at %.1f/%.1f%%)" % (warn_scaled, crit_scaled)
    return levels

def df_check_filesystem(hostname, mountpoint, size_mb, avail_mb, params):
    return df_check_filesystem_list(mountpoint, params, [(mountpoint, size_mb, avail_mb)])

def df_check_filesystem_list(item, params, fslist):
    if "patterns" in params:
        import fnmatch

        patterns = params["patterns"]
        count = 0
        total_size = 0
        total_avail = 0
        for mp, size_mb, avail_mb in fslist:
            for pattern in patterns:
                if fnmatch.fnmatch(mp, pattern):
                    count += 1
                    total_size += size_mb
                    total_avail += avail_mb
                    break
        if count == 0:
            return (3, "UKNOWN - No filesystem matching the patterns")
        else:
            status, infotext, perfdata = df_check_filesystem_single(g_hostname, item, total_size, total_avail, params)
            infotext += " (%d filesystems)" % count
            return status, infotext, perfdata
    else:
        for mp, size_mb, avail_mb in fslist:
            if mp == item:
                return df_check_filesystem_single(g_hostname, mp, size_mb, avail_mb, params)
        return (3, "UNKNOWN - filesystem not found")


def df_check_filesystem_single(hostname, mountpoint, size_mb, avail_mb, params):
    if size_mb == 0:
        return (1, "WARN - size of filesystem is 0 MB")

    used_mb   = size_mb - avail_mb
    used_perc = 100.0 * (float(used_mb) / size_mb)
    size_gb   = size_mb / 1024.0

    levels = get_filesystem_levels(g_hostname, mountpoint, size_gb, params)
    warn_mb, crit_mb = levels["levels_mb"]


    perf_var = mountpoint.replace(" ", "_")
    perfdata = [(perf_var, str(used_mb) + 'MB', warn_mb, crit_mb, 0, size_mb)]
    infotext = "%.1f%% used (%.2f of %.1f GB), %s" % \
                (used_perc, used_mb / 1024.0, size_gb, levels["levels_text"])



    status = 0
    problems = []

    MB = 1024 * 1024.0
    H24 = 60 * 60 * 24

    if levels.get("trend_range"):
        try:
            range = levels["trend_range"] # in hours
            range_sec = range * 3600.0
            this_time = time.time()

            timedif, rate = get_counter("df.%s.delta" % mountpoint, this_time, used_mb, True)
            if levels.get("trend_perfdata"):
                perfdata.append(("growth", rate * H24))

            timedif, rate_avg = get_average("df.%s.trend" % mountpoint,
                                            this_time, rate, range_sec / 60.0, True)

            trend = rate_avg * range_sec
            sign = trend > 0 and "+" or ""
            infotext += ", trend: %s%s / %g hours" % \
                        (sign, get_bytes_human_readable(trend * MB), range)

            warn_perf, crit_perf = None, None

            trend_mb = levels.get("trend_mb")
            if trend_mb:
                wa, cr = trend_mb
                warn_perf, crit_perf = wa, cr
                if trend >= wa:
                    problems.append("growing too fast (levels at %s/%s per %.1fh)!" %
                       ( get_bytes_human_readable(wa * MB), get_bytes_human_readable(cr * MB), range))
                    status = max(1, status)
                    if trend >= cr:
                        status = 2
                        problems[-1] += "!"
            else:
                wa, cr = None, None

            trend_perc = levels.get("trend_perc")
            if trend_perc:
                wa_perc, cr_perc = trend_perc
                wa = wa_perc / 100.0 * size_mb
                cr = cr_perc / 100.0 * size_mb
                if warn_perf != None:
                    warn_perf = min(warn_perf, wa)
                    crit_perf = min(crit_perf, cr)
                else:
                    warn_perf, crit_perf = wa, cr
                if trend >= wa:
                    problems.append("growing too fast (levels at %.3f%%/%.3f%% per %.1fh)!" %
                       ( wa_perc, cr_perc, range))
                    status = max(1, status)
                    if trend >= cr:
                        status = 2
                        problems[-1] += "!"

            if levels.get("trend_perfdata"):
                perfdata.append(("trend", rate_avg * H24,
                                warn_perf != None and (warn_perf / range_sec * H24) or None,
                                crit_perf != None and (crit_perf / range_sec * H24) or None,
                                0, size_mb / range))

            if trend > 0:
                space_left = size_mb - used_mb
                hours_left = space_left / trend * range
                timeleft = levels.get("trend_timeleft")
                if timeleft:
                    wa, cr = timeleft
                    if hours_left <= cr:
                        status = 2
                        problems.append("only %.1fh until disk full!!" % hours_left)
                    elif hours_left <= wa:
                        status = max(status, 1)
                        problems.append("only %.1fh until disk full!" % hours_left)
                    elif hours_left <= wa * 2:
                        problems.append("time left: %.1fh" % hours_left)


        except MKCounterWrapped:

            perfdata = []


    if used_mb >= crit_mb:
        status = 2
    elif used_mb >= warn_mb:
        status = max(1, status)

    if len(problems) > 0:
        infotext += " - " + ", ".join(problems)
    return (status, nagios_state_names[status] + " - " + infotext, perfdata)


# /home/nagios/check_mk/checks/df


def inventory_df(info):
    mplist = []
    for line in info:
        if line[1] in inventory_df_exclude_fs:
            continue # ignore this filesystem type

        size_kb = int(line[2])
        if size_kb == 0 or line[5] == '-':
            continue # exclude filesystems without size

        mountpoint = " ".join(line[6:]).replace('\\', '/') # Windows \ is replaced with /
        if mountpoint in inventory_df_exclude_mountpoints:
            continue # exclude this mount point (/tmp, /proc, whatever user wants)

        mplist.append(mountpoint)

    return df_inventory(mplist)


def check_df(item, params, info):
    fslist = []
    for line in info:
        mountpoint = " ".join(line[6:]).replace('\\', '/')
        if "patterns" in params or item == mountpoint:
            size_mb    = int(line[2]) / 1024.0
            avail_mb   = int(line[4]) / 1024.0
            fslist.append((mountpoint, size_mb, avail_mb))

    return df_check_filesystem_list(item, params, fslist)

check_info['df'] = {
    "check_function"          : check_df,
    "inventory_function"      : inventory_df,
    "service_description"     : "fs_%s",
    "has_perfdata"            : True,
    "group"                   : "filesystem",
    "default_levels_variable" : "filesystem_default_levels",
    "includes"                : [ "df.include" ],
}


# /home/nagios/check_mk/checks/if.include


if_inventory_porttypes = [ '6', '32', '62', '117' ]
if_inventory_portstates = [ '1' ]
if_inventory_uses_description = False
if_inventory_uses_alias = False
if_inventory_pad_portnumbers = True
if_inventory_monitor_speed = True
if_inventory_monitor_state = True
inventory_if_rules = []

factory_settings["if_default_levels"] = {
    "errors" : (0.01, 0.1),
}


if_groups = []

if_default_error_levels = factory_settings["if_default_levels"]["errors"]
if_default_traffic_levels = None, None
if_default_average = None

if_disable_if64_hosts = [] # Binary host list for disabling if64 on some broken devices

def if64_disabled(hostname):
    return in_binary_hostlist(hostname, if_disable_if64_hosts)

def cleanup_if_strings(s):
    if s and s != '':
        return "".join([ c for c in s if c not in nagios_illegal_chars+chr(0) ]).strip()
    else:
        return s

check_config_variables.append("nagios_illegal_chars")

def if_statename(st):
    names = { '1': 'up',      '2': 'down',
              '3': 'testing', '4': 'unknown',
              '5': 'dormant', '6': 'notPresent',
              '7': 'lowerLayerDown' }
    return names.get(st, st)


def if_pad_with_zeroes(info, ifIndex):
    if if_inventory_pad_portnumbers:
        max_index = max([int(line[0]) for line in info])
        digits = len(str(max_index))
        return ("%0"+str(digits)+"d") % int(ifIndex)
    else:
        return ifIndex


def inventory_if_common(info):
    if len(info) == 0 or len(info[0]) != 20:
        return []

    settings = host_extra_conf_merged(g_hostname, inventory_if_rules)
    uses_description    = settings.get('use_desc', if_inventory_uses_description)
    uses_alias          = settings.get('use_alias', if_inventory_uses_alias)
    porttypes           = settings.get('porttypes', if_inventory_porttypes)
    portstates          = settings.get('portstates', if_inventory_portstates)

    pre_inventory        = []
    pre_inventory_groups = []
    group_patterns = {}

    for line in host_extra_conf(g_hostname, if_groups):
        for entry in line:
            if str(entry["iftype"]) in porttypes:
                group_patterns[entry["name"]] = entry

    seen_items  = set([])
    duplicate   = set([])
    have_groups = {}


    for ifIndex, ifDescr, ifType, ifSpeed, ifOperStatus, ifInOctets, \
            inucast, inmcast, inbcast, ifInDiscards, ifInErrors, ifOutOctets, \
            outucast, outmcast, outbcast, ifOutDiscards, ifOutErrors, \
            ifOutQLen, ifAlias, ifPhysAddress in info:
        ifDescr = cleanup_if_strings(ifDescr)
        ifAlias = cleanup_if_strings(ifAlias)

        if uses_description and ifDescr:
            item = ifDescr
        elif uses_alias and ifAlias:
            item = ifAlias
        else:
            item = if_pad_with_zeroes(info, ifIndex)

        is_only_in_group = False
        for group_name, pattern in group_patterns.items():
            if pattern["iftype"] == saveint(ifType):
                have_groups.setdefault(group_name, {"interfaces": []})["iftype"] = pattern["iftype"]
                have_groups[group_name]["interfaces"].append((saveint(ifSpeed), ifOperStatus))
                if pattern.get("single"):
                    is_only_in_group = True

        if not is_only_in_group:
            if item in seen_items: # duplicate
                duplicate.add(item)
            seen_items.add(item)

            if ifType in porttypes and ifOperStatus in portstates:
                params = {}
                if if_inventory_monitor_state:
                    params["state"] = [ifOperStatus]

                if ifSpeed != "" and if_inventory_monitor_speed:
                    params["speed"] = int(ifSpeed)
                pre_inventory.append( (item, "%r" % params, int(ifIndex)) )

    for group_name, values in have_groups.items():
        total_speed = sum([pair[0] for pair in values["interfaces"]])
        one_up = "1" in [pair[1] for pair in values["interfaces"]]
        group_operStatus = one_up and "1" or "2"

        ifType = group_patterns[group_name]["iftype"]
        if str(ifType) in porttypes and group_operStatus in portstates:
            params = { "iftype": ifType, "aggregate": True }
            if if_inventory_monitor_state:
                params["state"] = [ group_operStatus ]

            if ifSpeed != "" and if_inventory_monitor_speed:
                params["speed"] = total_speed
            pre_inventory.append( (group_name, "%r" % params, int(ifIndex)) )

    inventory = []
    for item, params, index in pre_inventory:
        if item in duplicate:
            new_item = "%s %d" % (item, index)
        else:
            new_item = item
        inventory.append((new_item, params))

    return inventory

def check_if_common(item, params, info):
    if params.get("aggregate"):
        matching_interfaces = []
        for element in info:
            if params["iftype"] == saveint(element[2]):
                matching_interfaces.append(element)

        wrapped = False
        this_time = time.time()

        group_info = {
            "ifSpeed" : 0, "ifInOctets" : 0, "inucast" : 0, "inmcast" : 0 , "inbcast" : 0,
            "ifInDiscards" : 0, "ifInErrors" : 0, "ifOutOctets" : 0, "outucast" : 0, "outmcast" : 0,
            "outbcast" : 0, "ifOutDiscards" : 0, "ifOutErrors" : 0, "ifOutQLen" : 0
        }

        for ifIndex, ifDescr, ifType, ifSpeed, ifOperStatus, ifInOctets, \
                inucast, inmcast, inbcast, ifInDiscards, ifInErrors, ifOutOctets, \
                outucast, outmcast, outbcast, ifOutDiscards, ifOutErrors, \
                ifOutQLen, ifAlias, ifPhysAddress in matching_interfaces:
            if if_inventory_uses_description and ifDescr:
                group_item = ifDescr
            elif if_inventory_uses_alias and ifAlias:
                group_item = ifAlias
            else:
                group_item = if_pad_with_zeroes(info, ifIndex)

            perfdata = []

            for name, counter in [
                ( "in",        ifInOctets),
                ( "inucast",   inucast),
                ( "inmcast",   inmcast),
                ( "inbcast",   inbcast),
                ( "indisc",    ifInDiscards),
                ( "inerr",     ifInErrors),

                ( "out",       ifOutOctets),
                ( "outucast",  outucast),
                ( "outmcast",  outmcast),
                ( "outbcast",  outbcast),
                ( "outdisc",   ifOutDiscards),
                ( "outerr",    ifOutErrors) ]:
                try:
                    get_counter("if.%s.%s.%s" % (name, item, group_item), this_time, saveint(counter))
                except MKCounterWrapped:
                    wrapped = True

            group_info["ifSpeed"]       += saveint(ifSpeed)
            group_info["ifInOctets"]    += saveint(ifInOctets)
            group_info["inucast"]       += saveint(inucast)
            group_info["inmcast"]       += saveint(inmcast)
            group_info["inbcast"]       += saveint(inbcast)
            group_info["ifInDiscards"]  += saveint(ifInDiscards)
            group_info["ifInErrors"]    += saveint(ifInErrors)
            group_info["ifOutOctets"]   += saveint(ifOutOctets)
            group_info["outucast"]      += saveint(outucast)
            group_info["outmcast"]      += saveint(outmcast)
            group_info["outbcast"]      += saveint(outbcast)
            group_info["ifOutDiscards"] += saveint(ifOutDiscards)
            group_info["ifOutErrors"]   += saveint(ifOutErrors)
            group_info["ifOutQLen"]     += saveint(ifOutQLen)



        one_up = "1" in [element[4] for element in matching_interfaces]
        group_operStatus = one_up and "1" or "2"

        group_entry = [
                    "ifgroup%s" % item,         # ifIndex
                    item,                       # ifDescr
                    params["iftype"],           # ifType
                    group_info["ifSpeed"],      # ifSpeed
                    group_operStatus,           # ifOperStatus
                    group_info["ifInOctets"],   # ifInOctets
                    group_info["inucast"],      # inucast
                    group_info["inmcast"],      # inmcast
                    group_info["inbcast"],      # inbcast
                    group_info["ifInDiscards"], # ifInDiscards
                    group_info["ifInErrors"],   # ifInErrors

                    group_info["ifOutOctets"],  # ifOutOctets
                    group_info["outucast"],     # outucast
                    group_info["outmcast"],     # outmcast
                    group_info["outbcast"],     # outbcast
                    group_info["ifOutDiscards"],# ifOutDiscards
                    group_info["ifOutErrors"],  # ifOutErrors
                    group_info["ifOutQLen"],    # ifOutQLen
                    "iftype %s" % params["iftype"],        # ifAlias
                    "",                         # ifPhysAddress
        ]
        info.append(group_entry)
        return check_if_common_single(item, params, info, wrapped)

    return check_if_common_single(item, params,info)

def check_if_common_single(item, params, info, force_counter_wrap = False):
    targetspeed        = params.get("speed")
    targetstate        = params.get("state")
    average            = params.get("average")
    unit               = params.get("unit") in ["Bit", "bit"] and "Bit" or "B"
    unit_multiplier    = unit == "Bit" and 8.0 or 1.0

    if params["errors"]:
        err_warn, err_crit = params["errors"]
    else:
        err_warn, err_crit = None, None

    if "traffic" in params:
        bw_warn, bw_crit = params["traffic"]
    else:
        bw_warn, bw_crit = None, None


    for ifIndex, ifDescr, ifType, ifSpeed, ifOperStatus, ifInOctets,  \
            inucast, inmcast, inbcast, ifInDiscards, ifInErrors, ifOutOctets, \
            outucast, outmcast, outbcast, ifOutDiscards, ifOutErrors, \
            ifOutQLen, ifAlias, ifPhysAddress in info:
        ifDescr = cleanup_if_strings(ifDescr)
        ifAlias = cleanup_if_strings(ifAlias)

        if item.lstrip("0") == ifIndex \
            or (item == "0" * len(item) and saveint(ifIndex) == 0) \
            or item == ifAlias \
            or item == ifDescr \
            or item == "%s %s" % (ifAlias, ifIndex) \
            or item == "%s %s" % (ifDescr, ifIndex):

            if item.lstrip("0") == ifIndex \
                and (item == ifAlias or ifAlias == '') \
                and (item == ifDescr or ifDescr == ''): # description trivial
                infotext = ""
            elif item == "%s %s" % (ifAlias, ifIndex) and ifDescr != '': # non-unique Alias
                infotext = "[%s/%s]" % (ifAlias, ifDescr)
            elif item != ifAlias and ifAlias != '': # alias useful
                infotext = "[%s] " % ifAlias
            elif item != ifDescr and ifDescr != '': # description useful
                infotext = "[%s] " % ifDescr
            else:
                infotext = "[%s] " % ifIndex

            state = 0

            operstatus = if_statename(str(ifOperStatus))
            if targetstate and  \
                (ifOperStatus != targetstate
                and not (type(targetstate) in [ list, tuple ] and ifOperStatus in targetstate)):
                state = 2
                infotext += "(%s)(!!) " % operstatus
            else:
                infotext += "(%s) " % operstatus


            speed = saveint(ifSpeed)

            if speed:
                ref_speed = speed / 8.0
            elif targetspeed:
                ref_speed = targetspeed / 8.0
            else:
                ref_speed = None

	    if ifPhysAddress:
                mac = ":".join(["%02s" % hex(ord(m))[2:] for m in ifPhysAddress]).replace(' ', '0')
                infotext += 'MAC: %s, ' % mac

            if speed:
                infotext += get_nic_speed_human_readable(speed)
                if not targetspeed is None and speed != targetspeed:
                    infotext += " (wrong speed, expected: %s)(!)" % get_nic_speed_human_readable(targetspeed)
                    state = max(state, 1)
            elif targetspeed:
                infotext += "assuming %s" % get_nic_speed_human_readable(targetspeed)
            else:
                infotext += "speed unknown"

            if ref_speed:
                if bw_warn != None and type(bw_warn) == float:
                    bw_warn = bw_warn / 100.0 * ref_speed * unit_multiplier
                if bw_crit != None and type(bw_crit) == float:
                    bw_crit = bw_crit / 100.0 * ref_speed * unit_multiplier

            else:
                if bw_warn != None and type(bw_warn) == float:
                    bw_warn = None

                if bw_crit != None and type(bw_crit) == float:
                    bw_crit = None

            if unit == "Bit":
                if bw_crit and bw_crit != None:
                    bw_crit = bw_crit / 8
                if bw_warn and bw_warn != None:
                    bw_warn = bw_warn / 8

            this_time = time.time()
            rates = []
            wrapped = False
            perfdata = []
            for name, counter, warn, crit, mmin, mmax in [
                ( "in",        ifInOctets, bw_warn, bw_crit, 0, ref_speed),
                ( "inucast",   inucast, None, None, None, None),
                ( "innucast",  saveint(inmcast) + saveint(inbcast), None, None, None, None),
                ( "indisc",    ifInDiscards, None, None, None, None),
                ( "inerr",     ifInErrors, err_warn, err_crit, None, None),

                ( "out",       ifOutOctets, bw_warn, bw_crit, 0, ref_speed),
                ( "outucast",  outucast, None, None, None, None),
                ( "outnucast", saveint(outmcast) + saveint(outbcast), None, None, None, None),
                ( "outdisc",   ifOutDiscards, None, None, None, None),
                ( "outerr",    ifOutErrors, err_warn, err_crit, None, None) ]:

                try:
                    timedif, rate = get_counter("if.%s.%s" % (name, item), this_time, saveint(counter))
                    if force_counter_wrap:
                        raise MKCounterWrapped("if.%s.%s" % (name, item), "Forced counter wrap")
                    rates.append(rate)
                    perfdata.append( (name, rate, warn, crit, mmin, mmax) )
                except MKCounterWrapped:
                    wrapped = True

            if wrapped:
                if bw_crit != None:
                    raise MKCounterWrapped("", "Counter wrap, skipping checks this time")
                perfdata = []
            else:
                perfdata.append(("outqlen", saveint(ifOutQLen),"","", unit == "Bit" and "0.0" or "0"))
                get_human_readable = lambda traffic: get_bytes_human_readable(traffic * unit_multiplier, 1024, True, unit)
                for what, errorrate, okrate, traffic in \
                   [ ("in",  rates[4], rates[1] + rates[2], rates[0]),
                     ("out", rates[9], rates[6] + rates[7], rates[5]) ]:

                    infotext += ", %s: %s/s" % (what, get_human_readable(traffic))

                    if ref_speed:
                        perc_used = 100.0 * traffic / ref_speed
                        infotext += "(%.1f%%)" % perc_used

                    if average:
                        timedif, traffic_avg = get_average("if.%s.%s.avg" % (what, item), this_time, traffic, average)
                        infotext += ", %dmin avg: %s/s" % (average, get_human_readable(traffic_avg))
                        perfdata.append( ("%s_avg_%d" % (what, average), traffic_avg, bw_warn, bw_crit, 0, ref_speed) )
                        traffic = traffic_avg # apply levels to average traffic

                    if bw_crit != None and traffic >= bw_crit:
                        state = 2
                        infotext += ' (!!) >= ' + get_human_readable(bw_crit / unit_multiplier) + "/s"
                    elif bw_warn != None and traffic >= bw_warn:
                        state = max(state, 1)
                        infotext += ' (!) >= ' + get_human_readable(bw_warn / unit_multiplier) + "/s"

                    pacrate = okrate + errorrate
                    if pacrate > 0.0: # any packets transmitted?
                        errperc = 100.0 * errorrate / (okrate + errorrate)

                        if errperc > 0:
                            infotext += ", %s-errors: %.2f%%" % (what, errperc)

                        if   err_crit != None and errperc >= err_crit:
                            state = 2
                            infotext += "(!!) >= " + str(err_crit)
                        elif err_warn != None and errperc >= err_warn:
                            state = max(state, 1)
                            infotext += "(!) >= " + str(err_warn)

            return (state, "%s - %s" % (nagios_state_names[state], infotext), perfdata)

    return (3, "UNKNOWN - no such interface")






# /home/nagios/check_mk/checks/lnx_if



check_includes['lnx_if'] = [ "if.include" ]

linux_nic_check = "lnx_if"

def if_lnx_convert_to_if64(info):
    nic_info = {}
    current_nic = None
    index = 0
    for line in info:
        if line[0].startswith('['):
            current_nic = line[0][1:-1]
            index += 1
            nic_info[current_nic]['index'] = index
        elif current_nic == None: # still in perf-counters subsection
            nic = line[0]
            nic_info[nic] = { "counters": map(int, line[1].split()) }
        else:
            nic_info[current_nic][line[0].strip()] = line[1].strip()


    if_table = []
    index = 0
    for nic, attr in nic_info.items():
        counters = attr.get("counters", [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0])
        index += 1
        ifIndex = attr.get("index",index)
        ifDescr = nic
        ifAlias = nic

        if nic == "lo":
            ifType = 24
        else:
            ifType = 6

        speed_text = attr.get("Speed")
        if speed_text == None:
            ifSpeed = ''
        else:
            if speed_text == '65535Mb/s': # unknown
                ifSpeed = ''
            elif speed_text.endswith("Kb/s"):
                ifSpeed = int(speed_text[:-4]) * 1000
            elif speed_text.endswith("Mb/s"):
                ifSpeed = int(speed_text[:-4]) * 1000000
            elif speed_text.endswith("Gb/s"):
                ifSpeed = int(speed_text[:-4]) * 1000000000
            else:
                ifSpeed = ''

        ifInOctets = counters[0]
        inucast = counters[1] + counters[7]
        inmcast = counters[7]
        inbcast = 0
        ifInDiscards = counters[3]
        ifInErrors = counters[2]
        ifOutOctets = counters[8]
        outucast = counters[9]
        outmcast = 0
        outbcast = 0
        ifOutDiscards = counters[11]
        ifOutErrors = counters[10]
        ifOutQLen = counters[12]

        ld = attr.get("Link detected")
        if ld == "yes":
            ifOperStatus = 1
        elif ld == "no":
            ifOperStatus = 2
        else:
            if ifInOctets > 0:
                ifOperStatus = 1 # assume up
            else:
                ifOperStatus = 4 # unknown (NIC has never been used)

        ifPhysAddress = ''

        if_table.append(map(str, [
          ifIndex, ifDescr, ifType, ifSpeed, ifOperStatus,
          ifInOctets, inucast, inmcast, inbcast, ifInDiscards,
          ifInErrors, ifOutOctets, outucast, outmcast, outbcast,
          ifOutDiscards, ifOutErrors, ifOutQLen, ifAlias, ifPhysAddress ]))

    return if_table

def inventory_lnx_if(info):
    if linux_nic_check == "legacy":
        return []
    return inventory_if_common(if_lnx_convert_to_if64(info))

def check_lnx_if(item, params, info):
    return check_if_common(item, params, if_lnx_convert_to_if64(info))

check_info['lnx_if'] = (check_lnx_if, "Interface %s", 1,  inventory_lnx_if)
checkgroup_of['lnx_if'] = "if"
check_default_levels['lnx_if'] = "if_default_levels"


# /home/nagios/check_mk/checks/cpu



cpuload_default_levels = (5, 10)
threads_default_levels = (2000, 4000)

def inventory_cpu_load(info):
    if len(info) == 1 and len(info[0]) >= 5:
        return [(None, "cpuload_default_levels")]

def check_cpu_load(item, params, info):
    load = []
    for i in [ 0, 1, 2 ]:
        load.append(float(info[0][i]))
    if len(info[0]) >= 6:
        num_cpus = int(info[0][5])
    else:
        num_cpus = 1

    warn, crit = params # apply on 15min average, relative to number of CPUs
    warn = warn * num_cpus
    crit = crit * num_cpus
    perfdata = [ ('load' + str(z), l, warn, crit, 0, num_cpus ) for (z,l) in [ (1,load[0]), (5,load[1]), (15, load[2]) ] ]

    if load[2] >= crit:
        return (2, "CRIT - 15min load %.2f at %s CPUs (critical at %.2f)" % (load[2], num_cpus, crit), perfdata)
    elif load[2] >= warn:
        return (1, "WARN - 15min load %.2f at %s CPUs (warning at %.2f)" % (load[2], num_cpus, warn), perfdata)
    else:
        return (0, "OK - 15min load %.2f at %s CPUs" % (load[2], num_cpus), perfdata)

def inventory_cpu_threads(info):
    if len(info) == 1 and len(info[0]) >= 5:
        return [(None, "", "threads_default_levels")]

def check_cpu_threads(item, params, info):
    try:
        nthreads = int(info[0][3].split('/')[1])
    except:
        return (3, "UNKNOWN - invalid output from plugin")
    warn, crit = params
    perfdata = [('threads', nthreads, warn, crit, 0 )]
    if nthreads >= crit:
        return (2, "CRIT - %d threads (critical at %d)" % (nthreads, crit), perfdata)
    elif nthreads >= warn:
        return (1, "WARN - %d threads (warning at %d)" % (nthreads, warn), perfdata)
    else:
        return (0, "OK - %d threads" % (nthreads,), perfdata)

check_info["cpu.loads"] = {
    "check_function"        : check_cpu_load,
    "inventory_function"    : inventory_cpu_load,
    "service_description"   : "CPU load",
    "has_perfdata"          : True,
    "group"                 : "cpu_load",
}

check_info["cpu.threads"] = {
    "check_function"        : check_cpu_threads,
    "inventory_function"    : inventory_cpu_threads,
    "service_description"   : "Number of threads",
    "has_perfdata"          : True,
    "group"                 : "threads",
}



# /home/nagios/check_mk/checks/diskstat.include

diskstat_inventory_mode = "rule" # "summary", "single", "legacy"

diskstat_default_levels = {
}

diskstat_inventory = []


def inventory_diskstat_generic(info):
    if not info:
        return

    if diskstat_inventory_mode == "rule":
        hits = host_extra_conf(g_hostname, diskstat_inventory)
        if len(hits) > 0:
            modes = hits[0]
        else:
            modes = [ "summary" ]

    elif diskstat_inventory_mode == "single":
        modes = [ "physical" ]
    elif diskstat_inventory_mode == "summary":
        modes = [ "summary" ]
    else:
        modes = [ "legacy" ]

    inventory = []
    if "summary" in modes:
        inventory.append( ( "SUMMARY", "diskstat_default_levels" ) )

    if "legacy" in modes:
        inventory += [ ( "read", None ), ( "write", None ) ]

    if "physical" in modes:
        inventory += [ (line[0], "diskstat_default_levels")
                       for line in info
                       if not ' ' in line[0] ]

    if "lvm" in modes:
        inventory += [ (line[0], "diskstat_default_levels")
                       for line in info
                       if line[0].startswith("LVM ") ]

    if "vxvm" in modes:
        inventory += [ (line[0], "diskstat_default_levels")
                       for line in info
                       if line[0].startswith("VxVM ") ]

    return inventory



def check_diskstat_line(this_time, item, params, line):
    average_range = params.get("average")
    perfdata = []
    infos = []
    status = 0
    for what, ctr in [ ("read",  line[1]), ("write", line[2]) ]:
        countername = "diskstat.%s.%s" % (item, what)

        levels = params.get(what)
        if levels:
            warn, crit = levels
        else:
            warn, crit = None, None

        timedif, sectors_per_sec = get_counter(countername, this_time, int(ctr))
        bytes_per_sec = sectors_per_sec * 512
        infos.append("%s/sec %s" % (get_bytes_human_readable(bytes_per_sec), what))
        perfdata.append( (what, bytes_per_sec, warn, crit) )

        if average_range != None:
            timedif, avg = get_average(countername + ".avg", this_time, bytes_per_sec, average_range)
            perfdata.append( (what + ".avg", avg) )
            bytes_per_sec = avg

        if levels != None:
            mb_per_sec = bytes_per_sec / 1048576
            if mb_per_sec >= crit:
                status = 2
                infos[-1] += "(!!)"
            elif mb_per_sec >= warn:
                status = max(status, 1)
                infos[-1] += "(!)"

    if average_range != None:
        perfdata = [ perfdata[0], perfdata[2], perfdata[1], perfdata[3] ]

    ios_per_sec = None
    if len(line) >= 5 and line[3] >= 0 and line[4] > 0:
        reads, writes = map(int, line[3:5])
        ios = reads + writes
        timedif, ios_per_sec = get_counter(countername + ".ios", this_time, ios)
        infos.append("IOs: %.2f/sec" % ios_per_sec)

        if params.get("latency_perfdata"):
            perfdata.append(("ios", ios_per_sec))

    if len(line) >= 6 and line[5] >= 0:
        timems = int(line[5])
        timedif, timems_per_sec = get_counter(countername + ".time", this_time, timems)
        if not ios_per_sec:
            latency = 0.0
        else:
            latency = timems_per_sec / ios_per_sec
        infos.append("Latency: %.2fms" % latency)
        if "latency" in params:
            warn, crit = params["latency"]
            if latency >= crit:
                status = 2
                infos[-1] += "(!!)"
            elif latency >= warn:
                status = max(status, 1)
                infos[-1] += "(!)"
        else:
            warn, crit = None, None

        if params.get("latency_perfdata"):
            perfdata.append(("latency", latency, warn, crit))

    if len(line) >= 8:
        for what, ctr in [ ("read",  line[6]), ("write", line[7]) ]:
            countername = "diskstat.%s.ql.%s" % (item, what)
            levels = params.get(what + "_ql")
            if levels:
                warn, crit = levels
            else:
                warn, crit = None, None

            timedif, qlx = get_counter(countername, this_time, int(ctr))
            ql = qlx / 10000000.0
            infos.append(what.title() + " Queue: %.2f" % ql)

            if levels != None:
                if ql >= crit:
                    status = 2
                    infos[-1] += "(!!)"
                elif ql >= warn:
                    status = max(status, 1)
                    infos[-1] += "(!)"

            if params.get("ql_perfdata"):
                perfdata.append((what + "_ql", ql))


    return (status, nagios_state_names[status] + " - " + ", ".join(infos) , perfdata)


def check_diskstat_generic(item, params, this_time, info):
    if item in [ 'read', 'write' ]:
        return check_diskstat_old(item, params, this_time, info)

    if item == 'SUMMARY': # summary mode (only summarize physical disks!)
        summary_line = [0] * 13
        for line in info:
            devname = line[0]
            if ' ' in devname:
                continue
            summary_line = map(lambda e: e[0] + int(e[1]), zip(summary_line, line[1:]))
        return check_diskstat_line(this_time, "SUMMARY", params, [''] + summary_line)

    for line in info:
        if line[0] == item:
            return check_diskstat_line(this_time, item, params, line)

    return (3, "UNKNOWN - device missing")


def check_diskstat_old(item, params, this_time, info):
    if item == 'read':
        index = 1 # sectors read
    elif item == 'write':
        index = 2 # sectors written
    else:
        return (3, "UNKNOWN - invalid item %s" % (item,))

    this_val  = sum([int(x[index]) for x in info if ' ' not in x[0]])

    timedif, per_sec = get_counter("diskstat." + item, this_time, this_val)
    mb_per_s = per_sec / 2048.0    # Diskstat output is in sectors a 512 Byte
    perfdata = [ (item, "%dc" % this_val ) ]
    return (0, "OK - %.1fMB/s (in last %d secs)" % (mb_per_s, timedif), perfdata)


# /home/nagios/check_mk/checks/diskstat





check_includes['diskstat'] = [ "diskstat.include" ]


def diskstat_parse_info(info):
    info_plain = []
    nameinfo = {}
    phase = 'info'
    for line in info:
        if line[0] == '[dmsetup_info]':
            phase = 'dmsetup_info'
        elif line[0] == '[vx_dsk]':
            phase = 'vx_dsk'
        else:
            if phase == 'info':
                info_plain.append(line)
            elif phase == 'dmsetup_info':
                try:
                    majmin = tuple(map(int, line[1].split(':')))
                    if len(line) == 4:
                        name = "LVM %s" % line[0]
                    else:
                        name = "DM %s" % line[0]
                    nameinfo[majmin] = name
                except:
                    pass # ignore such crap as "No Devices Found"
            elif phase == 'vx_dsk':
                maj = int(line[0], 16)
                min = int(line[1], 16)
                group, disk = line[2].split('/')[-2:]
                name = "VxVM %s-%s" % (group, disk)
                nameinfo[(maj, min)] = name

    return info_plain, nameinfo

def diskstat_rewrite_device(nameinfo, linestart):
    major, minor = map(int, linestart[:2])
    device = linestart[2]
    return nameinfo.get((major, minor), device)

def linux_diskstat_convert(info):
    info, nameinfo = diskstat_parse_info(info)
    rewritten = [
        ( diskstat_rewrite_device(nameinfo, l[0:3]),
        int(l[5]),
        int(l[9]),
        int(l[3]),
        int(l[7]),
        int(l[12])
        ) for l in info[1:] if len(l) >= 13
    ]

    return [ line for line in rewritten if not line[0].startswith("dm-") ]

def inventory_diskstat(info):
    return inventory_diskstat_generic(linux_diskstat_convert(info))

def check_diskstat(item, params, info):
    return check_diskstat_generic(item, params, int(info[0][0]), linux_diskstat_convert(info))

check_info['diskstat'] = (check_diskstat, "Disk IO %s", 1,  inventory_diskstat)
checkgroup_of["diskstat"] = "disk_io"



# /home/nagios/check_mk/checks/mem.include

memused_default_levels = (150.0, 200.0)
mem_extended_perfdata = False

def check_memory(params, meminfo):
    try:
        swapused = meminfo['SwapTotal'] - meminfo['SwapFree']
        memused  = meminfo['MemTotal']  - meminfo['MemFree']
        caches   = meminfo.get('Buffers', 0) + meminfo.get('Cached', 0)
    except:
        return (3, "UNKNOWN - invalid output from plugin")

    extended_perf = []
    extrainfo = ""
    if mem_extended_perfdata:
        mapped = meminfo.get('Mapped')
        if mapped:
            mapped_mb = int(mapped) / 1024
            committed_as = meminfo.get('Committed_AS')
            if committed_as:
                committed_as_mb = int(committed_as) / 1024
            else:
                committed_as = 0
            extended_perf = [
                ('mapped',       str(mapped_mb)       + 'MB', '', '', 0, ''),
                ('committed_as', str(committed_as_mb) + 'MB', '', '', 0, ''),
            ]
            extrainfo = ", %.1f GB mapped, %.1f GB committed" % \
                        (mapped_mb / 1024.0, committed_as_mb / 1024.0)

    totalused_kb = (swapused + memused - caches)
    totalused_mb = totalused_kb / 1024
    totalmem_kb = meminfo['MemTotal']
    totalmem_mb = totalmem_kb / 1024
    totalused_perc = 100 * (float(totalused_kb) / float(totalmem_kb))
    totalvirt_mb = (meminfo['SwapTotal'] + meminfo['MemTotal']) / 1024
    warn, crit = params

    perfdata = [
        ('ramused', str( (memused - caches) / 1024) + 'MB', '', '', 0, totalmem_mb),
        ('swapused', str(swapused / 1024) + 'MB', '', '', 0, meminfo['SwapTotal']/1024) ]


    infotext = ("%.2f GB used (%.2f GB RAM + %.2f GB SWAP, this is %.1f%% of %.2f GB RAM)" % \
               (totalused_mb / 1024.0, (memused-caches) / 1024.0 / 1024, swapused / 1024.0 / 1024,
               totalused_perc, totalmem_mb / 1024.0)) \
               + extrainfo

    if type(warn) == float:
        perfdata.append(('memused', str(totalused_mb)+'MB', int(warn/100.0 * totalmem_mb),
                        int(crit/100.0 * totalmem_mb), 0, totalvirt_mb))
        perfdata += extended_perf
        if totalused_perc >= crit:
            return (2, 'CRIT - %s, critical at %.1f%%' % (infotext, crit), perfdata)
        elif totalused_perc >= warn:
            return (1, 'WARN - %s, warning at %.1f%%' % (infotext, warn), perfdata)
        else:
            return (0, 'OK - %s' % infotext, perfdata)

    else:
        perfdata.append(('memused', str(totalused_mb)+'MB', warn, crit, 0, totalvirt_mb))
        perfdata += extended_perf
        if totalused_mb >= crit:
            return (2, 'CRIT - %s, critical at %.2f GB' % (infotext, crit / 1024.0), perfdata)
        elif totalused_mb >= warn:
            return (1, 'WARN - %s, warning at %.2f GB' % (infotext, warn / 1024.0), perfdata)
        else:
            return (0, 'OK - %s' % infotext, perfdata)



# /home/nagios/check_mk/checks/mem



def parse_proc_meminfo(info):
    return dict([ (i[0][:-1], int(i[1])) for i in info ])

def inventory_mem_used(info):
    meminfo = parse_proc_meminfo(info)
    if "MemTotal" in meminfo and \
        "PageTotal" not in meminfo: # This case is handled by mem.win
        return [(None, "memused_default_levels")]

def check_mem_used(_no_item, params, info):
    meminfo = parse_proc_meminfo(info)
    return check_memory(params, meminfo)

check_info['mem.used'] = {
    "check_function"         : check_mem_used,
    "inventory_function"     : inventory_mem_used,
    "service_description"    : "Memory used",
    "has_perfdata"           : True,
    "group"                  : "memory",
    "check_config_variables" : [ "mem_extended_perfdata" ],
    "includes"               : [ "mem.include" ],
}



check_default_levels['mem.win'] = "memory_win_default_levels"
factory_settings["memory_win_default_levels"] = {
    "memory"   : ( 80.0, 90.0 ),
    "pagefile" : ( 50.0, 70.0 ),
}

def inventory_mem_win(info):
    meminfo = parse_proc_meminfo(info)
    if "PageTotal" in meminfo:
        return [(None, {})]

def check_mem_windows(item, params, info):
    meminfo = parse_proc_meminfo(info)
    perfdata = []
    infotxts = []
    MB = 1024.0 * 1024
    worststate = 0
    for title, what, paramname in [
        ( "Memory",    "Mem",  "memory" ),
        ( "Page file", "Page", "pagefile" )]:
        total_kb = meminfo[what + "Total"]
        free_kb  = meminfo[what + "Free"]
        used_kb  = total_kb - free_kb
        used_mb  = used_kb / 1024.0
        free_mb  = free_kb / 1024.0
        perc     = 100.0 * used_kb / total_kb

        warn, crit = params[paramname]
        if (type(crit) == int and free_mb <= crit) or \
            (type(crit) == float and perc >= crit):
            worststate = 2
            state_code = '(!!)'
        elif (type(warn) == int and free_mb <= warn) or \
            (type(warn) == float and perc >= warn):
            worststate = max(worststate, 1)
            state_code = '(!)'
        else:
            state_code = ""

        if type(warn) == float:
            warn = total_kb * warn / 100 / 1024
        if type(crit) == float:
            crit = total_kb * crit / 100 / 1024

        infotxts.append("%s usage: %.1f%% (%.1f/%.1f GB)%s" %
                (title, perc, used_kb / MB, total_kb / MB, state_code))
        perfdata.append((paramname, used_kb / 1024.0, warn, crit, 0, total_kb / 1024.0))

    return (worststate, "%s - %s" %
            (nagios_state_names[worststate], ", ".join(infotxts)), perfdata)


check_info['mem.win'] = (check_mem_windows, "Memory and pagefile", 1, inventory_mem_win)
checkgroup_of['mem.win'] = "memory_pagefile_win"



mem_vmalloc_default_levels = ( 80.0, 90.0, 64, 32 )

def inventory_mem_vmalloc(info):
    meminfo = parse_proc_meminfo(info)
    if "VmallocTotal" in meminfo:
        vmalloc = meminfo["VmallocTotal"] / 1024.4
        if vmalloc < 4096:
            return [ (None, "mem_vmalloc_default_levels") ]
    return []

def check_mem_vmalloc(item, params, info):
    meminfo = parse_proc_meminfo(info)
    total_mb = meminfo["VmallocTotal"] / 1024.0
    used_mb  = meminfo["VmallocUsed"] / 1024.0
    free_mb  = total_mb - used_mb
    chunk_mb = meminfo["VmallocChunk"] / 1024.0
    warn, crit, warn_chunk, crit_chunk = params

    state = 0
    infotxts = []
    perfdata = []
    for var, w, c, v, neg, what in [
        ( "used",  warn,       crit,       used_mb,  False, "used" ),
        ( "chunk", warn_chunk, crit_chunk, chunk_mb, True,  "largest chunk" )]:

        if type(w) == float:
            w_mb = total_mb * w / 100
        else:
            w_mb = float(w)

        if type(c) == float:
            c_mb = total_mb * c / 100
        else:
            c_mb = float(c)

        infotxt = "%s %.1f MB" % (what, v)
        if (v >= c_mb) != neg:
            s = 2
            infotxt += " (critical at %.1f MB!!)" % c_mb
        elif (v >= w_mb) != neg:
            s = 1
            infotxt += " (warning at %.1f MB!)" % w_mb
        else:
            s = 0
        state = max(state, s)
        infotxts.append(infotxt)
        perfdata.append( (var, v, w_mb, c_mb, 0, total_mb) )
    return (state, nagios_state_names[state] + (" - total %.1f MB, " % total_mb) + ", ".join(infotxts), perfdata)

check_info["mem.vmalloc"] = (check_mem_vmalloc, "Vmalloc address space", 1, inventory_mem_vmalloc)


# /home/nagios/check_mk/checks/mounts

def inventory_mounts(info):
    inventory = []
    for dev, mp, fstype, options, dump, fsck in info:
        if fstype not in [ 'tmpfs' ]:
            opts = options.split(",")
            opts.sort()
            inventory.append( (mp, opts) )
    return inventory

def check_mounts(item, targetopts, info):
    for dev, mp, fstype, options, dump, fsck in info:
        if item == mp:
            opts = options.split(",")

            exceeding = []
            for o in opts:
                if o not in targetopts and not o.startswith("commit=") \
                                       and not o.startswith("localalloc="):
                    exceeding.append(o)

            missing = []
            for o in targetopts:
                if o not in opts and not o.startswith("commit=") \
                                 and not o.startswith("localalloc="):
                    missing.append(o)

            if not missing and not exceeding:
                return (0, "OK - mount options exactly as expected")

            infos = []
            if missing:
                infos.append("missing: %s" % ",".join(missing))
            if exceeding:
                infos.append("exceeding: %s" % ",".join(exceeding))
            infotext = ", ".join(infos)

            if "ro" in exceeding:
                return (2, "CRIT - filesystem has switched to read-only "
                           "and is probably corrupted(!!), " + infotext)

            return (1, "OK - " + infotext)

    return (3, "UNKNOWN - filesystem not mounted")


check_info['mounts'] = ( check_mounts, "Mount options of %s", 0, inventory_mounts)
checkgroup_of['mounts'] = "fs_mount_options"


# /home/nagios/check_mk/checks/tcp_conn_stats

tcp_conn_stats_states = [
 ( "ESTABLISHED", "01"),  # connection up and passing data
 ( "SYN_SENT",    "02"),  # session has been requested by us; waiting for reply from remote endpoint
 ( "SYN_RECV",    "03"),  # session has been requested by a remote endpoint for a socket on which we were listening
 ( "LAST_ACK",    "09"),  # our socket is closed; remote endpoint has also shut down; we are waiting for a final acknowledgement
 ( "CLOSE_WAIT",  "08"),  # remote endpoint has shut down; the kernel is waiting for the application to close the socket
 ( "TIME_WAIT",   "06"),  # socket is waiting after closing for any packets left on the network
 ( "CLOSED",      "07"),  # socket is not being used (FIXME. What does mean?)
 ( "CLOSING",     "0B"),  # our socket is shut down; remote endpoint is shut down; not all data has been sent
 ( "FIN_WAIT1",   "04"),  # our socket has closed; we are in the process of tearing down the connection
 ( "FIN_WAIT2",   "05"),  # the connection has been closed; our socket is waiting for the remote endpoint to shut down
 ( "BOUND",       None),  # Socket did a bound() but TCP stack not yet active (Solaris)
]


tcp_conn_stats_default_levels = { }

def inventory_tcp_conn_stats(info):
    if len(info) > 0:
        return [ (None, 'tcp_conn_stats_default_levels') ]

def check_tcp_conn_stats(item, params, info):
    stats = dict(info)
    worst_state = 0
    info = []
    perfdata = []
    for state, hex in tcp_conn_stats_states:
        num = int(stats.get(state, stats.get(hex, 0)))
        if num > 0:
            infotext = "%s: %d" % (state, num)
        else:
            infotext = None
        levels = params.get(state)
        perf = [state, num]
        if levels:
            warn, crit = levels
            perf.append(warn)
            perf.append(crit)
            if num >= crit:
                worst_state = 2
                infotext += "(!!) (critical at %d)" % crit
            elif num >= warn:
                worst_state = max(1, worst_state)
                infotext += "(!) (warning at %d)" % warn
        perfdata.append(perf)
        if infotext:
            info.append(infotext)
    return (worst_state, "%s - %s" % (nagios_state_names[worst_state], ", ".join(info)), perfdata)

check_info['tcp_conn_stats'] = (check_tcp_conn_stats, "TCP Connections", 1, inventory_tcp_conn_stats)
checkgroup_of['tcp_conn_stats'] = "tcp_conn_stats"


convert_check_info()
clusters = {}
def is_cluster(hostname):
    return False

def is_snmp_host(hostname):
   return False

def is_tcp_host(hostname):
   return True

def snmp_walk_command(hostname):
   return "snmpwalk -v1 -c 'public' -m '' -M '' -Cc"

def is_usewalk_host(hostname):
   return False

ipaddresses = {'host1': '10.117.5.79'}

def lookup_ipaddress(hostname):
   return ipaddresses.get(hostname)

def get_datasource_program(hostname, ipaddress):
    return {'host1': None}[hostname]

def host_is_aggregated(hostname):
    return False

def agent_port_of(hostname):
    return 6556

def snmp_port_spec(hostname):
    return ''

def get_snmp_character_encoding(hostname):
    return None

nagios_illegal_chars = '`;~!$%^&*|\'"<>?,()='
cmctc_pcm_m_sensor_types = {72: 'kW', 73: 'kW', 74: 'hz', 75: 'V', 77: 'A', 79: 'kW', 80: 'kW'}
heartbeat_crm_naildown = True
heartbeat_crm_resources_naildown = True
ipmi_ignore_nr = False
ipmi_ignored_sensors = []
logwatch_dir = '/home/nagios/check_mk/var/logwatch'
logwatch_max_filesize = 500000
logwatch_service_output = 'default'
netctr_counters = ['rx_bytes', 'tx_bytes', 'rx_packets', 'tx_packets', 'rx_errors', 'tx_errors', 'tx_collisions']
oracle_tablespaces_check_default_increment = True
printer_alerts_state_map = {0: [1, 4, 6, 7, 19, 20, 22, 23, 24, 25, 27, 35, 36, 37, 38, 502, 503, 504, 505, 506, 507, 802, 803, 804, 805, 806, 807, 808, 809, 810, 1001, 1002, 1005, 1106, 1107, 1108, 1111, 1113, 1302, 1304, 1501, 1502, 1503, 1504, 1505, 1506, 1509], 1: [2, 9, 12, 13, 801, 1104], 2: [8, 1101, 1102, 1112, 1114, 1115]}
printer_alerts_text_map = {'Energiesparen': 0}
printer_supply_some_remaining_status = 1
winperf_cpu_default_levels = (101.0, 101.0)
winperf_msx_queues = {'Retry Remote Delivery': '4', 'Active Remote Delivery': '2', 'Poison Queue Length': '44', 'Active Mailbox Delivery': '6'}
mem_extended_perfdata = False
try:
    do_check('host1', '10.117.5.79')
except SystemExit, e:
    sys.exit(e.code)
except Exception, e:
    import traceback, pprint
    sys.stdout.write("UNKNOWN - Exception in precompiled check: %s (details in long output)\n" % e)
    sys.stdout.write("Traceback: %s\n" % traceback.format_exc())
    if debug_log:
        l = file(debug_log, "a")
        l.write(("Exception in precompiled check:\n"
                "  Check_MK Version: %s\n"
                "  Date:             %s\n"
                "  Host:             %s\n"
                "  %s\n") % (
                check_mk_version,
                time.strftime("%Y-%d-%m %H:%M:%S"),
                "host1",
                traceback.format_exc().replace('\n', '\n      ')))
        l.close()
    sys.exit(3)
