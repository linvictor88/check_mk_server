# vim: tabstop=4 shiftwidth=4 softtabstop=4

import logging
import re
import time

from check_mk.agent.linux import utils
from check_mk.devices import abstract_device

LOG = logging.getLogger(__name__)


class Memory(abstract_device.AbstractDevice):
    """Memory device data collector.

    All variables are in units of KB.
    """

    name = 'memory'

    def get_plain_info(self):
        cmd = ['cat', '/proc/meminfo']
        plain_info = [line.split()
                      for line in utils.execute(cmd).split('\n')
                      if line]
        LOG.debug(_("plain_info: %s"), plain_info)
        return plain_info

    def parse_plain_info(self, plain_info):
        meminfo = self.parse_proc_meminfo(plain_info)
        self.total = meminfo['MemTotal']
        self.used = meminfo['MemTotal'] - meminfo['MemFree']
        self.swapTotal = meminfo['SwapTotal']
        self.swapFree = meminfo['SwapFree']
        self.caches = meminfo['Cached']
        self.buffers = meminfo['Buffers']
        self.active = meminfo['Active']

    def parse_proc_meminfo(self, plain_info):
        return dict([(i[0][:-1], int(i[1])) for i in plain_info])

    def get_device_dict(self):
        return {'total': self.total,
                'used': self.used,
                'swapTotal': self.swapTotal,
                'swapFree': self.swapFree,
                'caches': self.caches,
                'buffers': self.buffers,
                'active': self.active}

    def init_device(self, device_dict):
        self.total = device_dict['total']
        self.used = device_dict['used']
        self.swapTotal = device_dict['swapTotal']
        self.swapFree = device_dict['swapFree']
        self.caches = device_dict['caches']
        self.buffers = device_dict['buffers']
        self.active = device_dict['active']

class Cpu(abstract_device.AbstractDevice):
    """Cpu device data collector."""

    name = 'cpu'
    def get_plain_info(self):
        """Get plain info of cpu.
        In order of user, nice, system, idle, iowait,
        irq, softirq and steal
        """
        cmd = ['cat', '/proc/stat']
        plain_info = [line.split(' ', 1) 
                      for line in utils.execute(cmd).split('\n')
                      if line and line.find('cpu') != -1]
        return plain_info

    def parse_plain_info(self, plain_info):
        cpuinfo = self.parse_proc_meminfo(plain_info)
        LOG.debug(_("cpu_info: %s"), cpuinfo)
        self.count = len(cpuinfo) - 1
        for key, value in cpuinfo.items():
            if key == 'cpu':
                v = [int(x) for x in value.split()]
                if len(v) < 8:
                    v = v + [0, 0, 0, 0]  # needed for Linux 2.4
                self.user = v[0]
                self.nice = v[1]
                self.system = v[2]
                self.idle = v[3]
                self.iowait = v[4]
                self.irq = v[5]
                self.softirq = v[6]
                self.steal = v[7]
                self.total = sum(v[0:7])
                #TODO(berlin) how to calculate the usage
                self.usage = None

    def parse_proc_meminfo(self, plain_info):
        return dict([(i[0], i[1]) for i in plain_info ])

    def get_device_dict(self):
            return {'user': self.user,
                    'nice': self.nice,
                    'system': self.system,
                    'idle': self.idle,
                    'iowait': self.iowait,
                    'irq': self.irq,
                    'softirq': self.softirq,
                    'steal': self.steal,
                    'total': self.total,
                    'count': self.count}

    def init_device(self, device_dict):
        self.count = device_dict['count']
        self.user = device_dict['user']
        self.nice = device_dict['nice']
        self.system = device_dict['system']
        self.idle = device_dict['idle']
        self.iowait = device_dict['iowait']
        self.irq = device_dict['irq']
        self.softirq = device_dict['softirq']
        self.steal = device_dict['steal']
        self.total = device_dict['total']


class System(abstract_device.AbstractDevice):
    """System device data collector."""

    name = 'system'
    def get_plain_info(self):
        """Get plain info of system."""
        cmd = ['cat', '/proc/uptime']
        plain_info = [line.split(' ', 1) 
                      for line in utils.execute(cmd).split('\n')
                      if line]
        return plain_info

    def parse_plain_info(self, plain_info):
        self.uptime = int(plain_info[0][0])

    def get_device_dict(self):
            return {'uptime': self.uptime}

    def init_device(self, device_dict):
        self.uptime = device_dict['uptime']

class Disks(abstract_device.AbstractDevice):
    """Disk device data collector."""

    name = 'disks'
    def get_plain_info(self):
        """Get plain info of system."""
        excludefs="-x smbfs -x tmpfs -x devtmpfs -x cifs -x iso9660 -x udf -x nfsv4 -x nfs -x mvfs -x zfs"
        df_cmd = ['df', '-PTlk', excludefs]
        df_info = [line.split() 
                   for line in utils.execute(df_cmd).split('\n')
                   if line]
        del df_info[0]
        for line in df_info:
            if os.path.islink(line[0]):
                realpath = os.path.realpath(line[0])
                line[0] = os.path.basename(realpath)
            mapping_df[line[0]] = line

        disk_cmd = ['cat', '/proc/diskstats']
        p = re.compile('x?[shv]d[a-z]*|cciss/c[0-9]+d[0-9]+|emcpower[a-z]+|dm-[0-9]+|VxVM.*')
        disk_info = [line.split() 
                     for line in utils.execute(disk_cmd).split('\n')
                     if line and p.search(line)]
        for line in disk_info:
            mapping_disk[line[2]] = map(lambda x: int(x), line[:2]+line[3:14])
            mapping_disk[line[2]].insert(2, line[2])

        for k, v in mapping_disk.items():
            if k in mapping_df.keys():
                mapping_info[k] = mapping_disk[k] + mapping_df[k]
        return mapping_info

    def parse_plain_info(self, plain_info):
        self.count = len(plain_info)
        self.disks = []
        for name, v in plain_info:
            disk = {'name': name}
            disk['readTput'] = v[5] 
            disk['writeTput'] =  v[9]
            disk['iops'] = v[3] + v[7]
            disk['latency'] = v[12]
            disk['total'] = v[15]
            disk['usage'] = v[18]
            disks.append(disk)
        
    def get_device_dict(self):
            return {'count': self.count,
                    'disks': self.disks}

    def init_device(self, device_dict):
        self.time = device_dict['time']
        self.count = device_dict['count']
        self.disks = device_dict['disks']

    def write_device_file(self, hostname):
        """Write device data into file."""
        for disk in self.disks:
            device_dir = os.path.join(DATA_BASE_DIR, hostname, self.name, disk['name'])
            if not os.path.isdir(device_dir):
                os.makedirs(device_dir, 0o755)
            timestamp = int(time.time())
            for k, v in self.get_device_dict().items():
                file_name = os.path.join(device_dir, k)
                data = _("%(timestamp)d %(value)s\n" % {'timestamp': timestamp,
                                                  'value': v})
                utils.write_file(file_name, data)  
