# vim: tabstop=4 shiftwidth=4 softtabstop=4

import pdb
import logging
import os
import time

from check_mk.agent.linux import utils
from check_mk.common import counter
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
        counter.load_counters(self.name)
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
            self.cpu['workload'] = cpu['usage']
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
        if 'disks' in device_mapping:
            disks = device_mapping['disks'].get_device_dict()
            self.disks = {'disks': []}
            self.disks['count'] = disks['count']
            # All disks' throughput (KB/s)
            self.disks['usageAverage'] = 0.0
            self.disks['readAverage'] = 0.0
            self.disks['writeAverage'] = 0.0
            # All disks' capacity (MB)
            self.disks['capacity'] = 0.0
            # All disks' free memory (MB)
            self.disks['freespace'] = 0.0
            self.disks['workload'] = 0.0
            self.disks['readTotalIos'] = 0.0
            self.disks['writeTotalIos'] = 0.0
            self.disks['totalIos'] = 0.0
            self.disks['readTotalLatency'] = 0.0
            self.disks['writeTotalLatency'] = 0.0
            self.disks['totalLatency'] = 0.0
            self.disks['totalIoLatency'] = 0.0
            self.disks['workload'] = 0.0
            for item in disks['disks']:
                disk = {'name': item['name']}
                # disk's average IO number
                disk['commandsAverage'] = item['iops']
                disk['ioLatency'] = item['ioLatency']
                #latency of all pakcets per seconds
                disk['oio'] = disk['commandsAverage'] * disk['ioLatency']
                maxObservedOIO = "%s-disk-%s-maxObservedOIO" % (self.name, disk['name'])
                disk['maxObservedOIO'] = counter.get_counter(maxObservedOIO)
                disk['maxObservedOIO'] = max(disk['maxObservedOIO'], disk['oio'], 32)
                counter.update_counter(maxObservedOIO, disk['maxObservedOIO'])
                disk['demand'] = disk['oio'] / disk['maxObservedOIO'] * 100.0
                self.disks['capacity'] += item['capacity']
                self.disks['freespace'] += item['capacity'] * (100.0 - item['usage']) / 100.0

                # IO number per sec
                self.disks['readTotalIos'] += item['readIos']
                self.disks['writeTotalIos'] += item['writeIos']
                # IO latency per sec
                self.disks['readTotalLatency'] += item['readLatency']
                self.disks['writeTotalLatency'] += item['writeLatency']

                # kB per sec
                self.disks['readAverage'] += item['readTput'] / 1024.0
                self.disks['writeAverage'] += item['writeTput'] / 1024.0
                self.disks['usageAverage'] = self.disks['readAverage'] + self.disks['writeAverage']

                self.disks['workload'] = max(self.disks['workload'], disk['demand'])
                self.disks['disks'].append(disk)
            self.disks['totalIos'] =  self.disks['readTotalIos'] + self.disks['writeTotalIos']
            self.disks['totalLatency'] = self.disks['readTotalLatency'] + self.disks['writeTotalLatency']

            if not self.disks['totalIos']:
                self.disks['totalIoLatency'] = 0.0
            else:
                self.disks['totalIoLatency'] = self.disks['totalLatency'] / self.disks['totalIos']

            if not self.disks['readTotalIos']:
                self.disks['readIoLatency'] = 0.0
            else:
                self.disks['readIoLatency'] = self.disks['readTotalLatency'] / self.disks['readTotalIos']

            if not self.disks['writeTotalIos']:
                self.disks['writeIoLatency'] = 0.0
            else:
                self.disks['writeIoLatency'] = self.disks['writeTotalLatency'] /self.disks['writeTotalIos']

            self.disks['usageAverage'] = self.disks['readAverage'] + self.disks['writeAverage']

        if 'nets' in device_mapping:
            nets = device_mapping['nets'].get_device_dict()
            self.nets = {}
            self.nets['packetsRxPerSec'] = 0.0
            self.nets['packetsTxPerSec'] = 0.0
            self.nets['tputRxPerSec'] = 0.0
            self.nets['tputTxPerSec'] = 0.0
            self.nets['usageAverage'] = 0.0
            for item in nets['nets']:
                net = {'name': item['name']}
                self.nets['packetsRxPerSec'] += item['pktInRate']
                self.nets['packetsTxPerSec'] += item['pktOutRate']
                self.nets['tputRxPerSec'] += item['inOctets'] / 1024.0
                self.nets['tputTxPerSec'] += item['outOctets'] / 1024.0

            self.nets['usageAverage'] = self.nets['tputRxPerSec'] + self.nets['tputTxPerSec']

            maxObservedKBTx = "%s-nets-maxObservedKBTx" % self.name
            self.nets['maxObservedKBTx'] = counter.get_counter(maxObservedKBTx)
            self.nets['maxObservedKBTx'] = max(self.nets['tputTxPerSec'], self.nets['maxObservedKBTx'], TenMbKBPerSec)
            counter.update_counter(maxObservedKBTx, self.nets['maxObservedKBTx'])

            maxObservedKBRx = "%s-nets-maxObservedKBRx" % self.name
            self.nets['maxObservedKBRx'] = counter.get_counter(maxObservedKBRx)
            self.nets['maxObservedKBRx'] = max(self.nets['tputRxPerSec'], self.nets['maxObservedKBRx'], TenMbKBPerSec)
            counter.update_counter(maxObservedKBRx, self.nets['maxObservedKBRx'])

            maxObservedPktRx = "%s-nets-maxObservedPktRx" % self.name
            self.nets['maxObservedPktRx'] = counter.get_counter(maxObservedPktRx)
            self.nets['maxObservedPktRx'] = max(self.nets['packetsRxPerSec'], self.nets['maxObservedPktRx'], TenMbPktsPerSec)
            counter.update_counter(maxObservedPktRx, self.nets['maxObservedPktRx'])

            maxObservedPktTx = "%s-nets-maxObservedPktTx" % self.name
            self.nets['maxObservedPktTx'] = counter.get_counter(maxObservedPktTx)
            self.nets['maxObservedPktTx'] = max(self.nets['packetsTxPerSec'], self.nets['maxObservedPktTx'], TenMbPktsPerSec)
            counter.update_counter(maxObservedPktTx, self.nets['maxObservedPktTx'])

            self.nets['workload'] = max(self.nets['tputTxPerSec'] / self.nets['maxObservedKBTx'],
                                        self.nets['tputRxPerSec'] / self.nets['maxObservedKBRx'],
                                        float(self.nets['packetsTxPerSec']) / self.nets['maxObservedPktTx'],
                                        float(self.nets['packetsRxPerSec']) / self.nets['maxObservedPktRx']) * 100.0

        counter.save_counters(self.name)

    def get_vm_dict(self):
        return self.__dict__            

    def write_vm_file(self):
        """Write Derived data into files."""
        timestamp = int(time.time())
        for device, data_dict in self.get_vm_dict().items():
            if not isinstance(data_dict, dict):
                continue
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
