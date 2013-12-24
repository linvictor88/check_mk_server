# This file has been created during setup of check_mk at Mon Dec 23 16:06:24 SGT 2013.
# Do not edit this file. Also do not try to override these settings
# in main.mk since some of them are hardcoded into several files
# during setup.
#
# If you need to change these settings, you have to re-run setup.sh
# and enter new values when asked, or edit ~/.check_mk_setup.conf and
# run ./setup.sh --yes.

check_mk_version            = '1.2.2p3'
default_config_dir          = '/home/nagios/check_mk'
check_mk_configdir          = '/home/nagios/check_mk/conf.d'
share_dir                   = '/home/nagios/check_mk'
checks_dir                  = '/home/nagios/check_mk/checks'
notifications_dir           = '/home/nagios/check_mk/notifications'
check_manpages_dir          = '/home/nagios/check_mk/doc/checks'
modules_dir                 = '/home/nagios/check_mk/modules'
locale_dir                  = '/home/nagios/check_mk/locale'
agents_dir                  = '/home/nagios/check_mk/agents'
var_dir                     = '/home/nagios/check_mk/var'
lib_dir                     = '/home/nagios/check_mk/lib'
snmpwalks_dir               = '/home/nagios/check_mk/var/snmpwalks'
autochecksdir               = '/home/nagios/check_mk/var/autochecks'
precompiled_hostchecks_dir  = '/home/nagios/check_mk/var/precompiled'
counters_directory          = '/home/nagios/check_mk/var/counters'
tcp_cache_dir		    = '/home/nagios/check_mk/var/cache'
tmp_dir		            = '/home/nagios/check_mk/var/tmp'
logwatch_dir                = '/home/nagios/check_mk/var/logwatch'
nagios_objects_file         = '/etc/nagios3/conf.d/check_mk_objects.cfg'
nagios_command_pipe_path    = '/var/lib/nagios3/rw/nagios.cmd'
check_result_path           = '/var/lib/nagios3/spool/checkresults'
nagios_status_file          = '/var/cache/nagios3/status.dat'
nagios_conf_dir             = '/etc/nagios3/conf.d'
nagios_user                 = 'nagios'
logwatch_notes_url          = '/check_mk/logwatch.py?host=%s&file=%s'
www_group                   = 'nagios'
nagios_config_file          = '/etc/nagios3/nagios.cfg'
nagios_startscript          = '/etc/init.d/nagios3'
nagios_binary               = '/usr/sbin/nagios3'
apache_config_dir           = '/etc/apache2/conf.d'
htpasswd_file               = '/etc/nagios3/htpasswd.users'
nagios_auth_name            = 'Nagios Access'
web_dir                     = '/home/nagios/check_mk/web'
livestatus_unix_socket      = '/var/lib/nagios3/rw/live'
livebackendsdir             = '/home/nagios/check_mk/livestatus'
url_prefix                  = '/'
pnp_url                     = '/pnp4nagios/'
pnp_templates_dir           = '/home/nagios/check_mk/pnp-templates'
doc_dir                     = '/home/nagios/check_mk/doc'
check_mk_automation         = 'sudo -u root /home/nagios/check_mk/bin/check_mk --automation'
