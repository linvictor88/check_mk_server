# Put your host names here
# all_hosts = [ 'localhost' ]
debug_log = "/var/log/nagios3/check_mk_debug.log"
extra_host_conf["check_interval"] = [("5", ALL_HOSTS)
]
extra_service_conf["normal_check_interval"] = [("5", ALL_HOSTS, ALL_SERVICES)]
all_hosts = [
	'host1',
	'host2'
]
