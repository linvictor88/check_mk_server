# vim: tabstop=4 shiftwidth=4 softtabstop=4

import pdb
import logging
import os
import time

from check_mk.agent.linux import utils
from check_mk.devices import abstract_device
from check_mk.devices import devices

LOG = logging.getLogger(__name__)

TenMbKBPerSec = float(10 * 1024 / 8)
TenMbPktsPerSec = float(500000)

class Vm(object):
    name = 'vm'

    def __init__(self, device_objs, hostname=None):
        if hostname:
            self.name = hostname
        device_mapping  = {}
        for device_obj in device_objs:
            device_mapping[device_obj.name] = device_obj
        if 'system' in device_mapping:
            system = device_mapping['system'].get_device_dict()
            self.summary = {}
            self.summary['state'] = system['state']
            self.summary['uptime'] = system['uptime']
        if 'cpu' in device_mapping:
            cpu = device_mapping['cpu'].get_device_dict()
            self.cpu = {}
            self.cpu['corecount'] = cpu['count']
            self.cpu['capacity_provisioned'] = cpu['speed'] * cpu['count']
            self.cpu['usePercent'] = cpu['usage']
            self.cpu['useMhz'] = cpu['speed']
            self.cpu['workload'] = cpu['workload']
        if 'memory' in device_mapping:
            mem = device_mapping['memory'].get_device_dict()
            self.mem = {}
            self.mem['guest_provisioned'] = mem['total']
            #(total - free - buffers -active)/total
            self.mem['guest_usePercent'] = mem['usage']
            self.mem['guest_activePercent'] = float(mem['active']) / float(mem['total']) * 100.0
            self.mem['guest_swapusePercent'] = float(mem['swapFree']) / float(mem['swapTotal']) * 100
            # TODO(berlin): ? workload = usepercent
            self.mem['workload'] = self.mem['guest_usePercent']
        if 'nets' in device_mapping:
            nets = device_mapping['nets'].get_device_dict()
            self.nets = {'nets': []}
            #self.nets['usageAverage'] = ?
            #self.nets['workload']
            for item in nets['nets']:
                net = {'name': item['name']}
                net['pktInRate'] = item['pktInRate']
                net['pktOutRate'] = item['pktOutRate']
                net['capacity'] = item['bandwidth']
                net['rxRate'] = item['inOctets']
                net['txRate'] = item['outOctets']
                self.nets['nets'].append(net)
#        elif 'disks' in device_mapping:
#            disks = device_mapping['disks']
#            self.disks = []
#            for item in disks.get_device_dict()['disks']:
#                disk = {'name': item['name']}
#                disk['usage']
#            

    def get_vm_dict(self):
        return self.__dict__            

    def write_vm_file(self):
        """Write Derived data into files."""
        timestamp = int(time.time())
        for device, data_dict in self.get_vm_dict().items():
            device_dir = os.path.join(abstract_device.DATA_BASE_DIR, self.name, device)
            if not os.path.isdir(device_dir):
                os.makedirs(device_dir, 0o755)
            for k, v in data_dict.items():
                if isinstance(v, list):
                    for list_data in v:
                        list_dir = os.path.join(device_dir, k, list_data['name'])
                        if not os.path.isdir(list_dir):
                            os.makedirs(list_dir, 0o755)
                        for sub_k, sub_v in list_data.items():
                            file_name = os.path.join(list_dir, sub_k)
                            data = _("%(timestamp)d %(value)s\n" % {'timestamp': timestamp,
            'value': sub_v})
                            utils.write_file(file_name, data)
                else:
                    file_name = os.path.join(device_dir, k)
                    data = _("%(timestamp)d %(value)s\n" % {'timestamp': timestamp,
    'value': v})
                    utils.write_file(file_name, data)
