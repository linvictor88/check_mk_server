# vim: tabstop=4 shiftwidth=4 softtabstop=4

import logging

from check_mk.agent.linux import utils
from check_mk.devices import abstract_device

LOG = logging.getLogger(__name__)

class Memory(abstract_device.AbstractDevice):
    """Memory device data collector.

    All variables are in units of KB.
    """

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
        self.used =  meminfo['MemTotal'] - meminfo['MemFree']
        self.swapTotal = meminfo['SwapTotal']
        self.swapFree = meminfo['SwapFree']
        self.caches = meminfo['Cached']
        self.buffers = meminfo['Buffers']
        self.active = meminfo['Active']

    def parse_proc_meminfo(self, plain_info):
        return dict([ (i[0][:-1], int(i[1])) for i in plain_info ])

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
