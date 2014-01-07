# vim: tabstop=4 shiftwidth=4 softtabstop=4

import abc
import os
import time

import six

from check_mk.agent.linux import utils

DATA_BASE_DIR = os.path.join(os.path.dirname(__file__),'../../var/data')


@six.add_metaclass(abc.ABCMeta)
class AbstractDevice(object):
    """Abstract Device that expose same API.

    Real Devices including cpu,memmory,disk...etc should implement its some
    functions.
    """
    name = 'abstract_device'
    def __init__(self, device_dict=None):
        #TODO(berlin): Here exists problems that None device_dict collected,
        #Server must first check the output before initializing a device.
        if not device_dict:
            self.plain_info = self.get_plain_info()
            self.parse_plain_info(self.plain_info)
        else:
            self.init_device(device_dict)

    @abc.abstractmethod
    def get_plain_info(self):
        """Get the plain info of device through calling shell commands."""
        pass

    @abc.abstractmethod
    def parse_plain_info(self, plain_info):
        """Parse the plain info into device raw data."""
        pass

    @abc.abstractmethod
    def get_device_dict(self):
        """Get device raw data dict."""
        pass

    @abc.abstractmethod
    def init_device(self, device_dict):
        """Initiate a device with device raw dict."""
        pass

    def write_device_file(self, hostname):
        """Write device data into file."""
        device_dir = os.path.join(DATA_BASE_DIR, hostname, self.name)
        if not os.path.isdir(device_dir):
            os.makedirs(device_dir, 0o755)
        timestamp = int(time.time())
        for k, v in self.get_device_dict().items():
            file_name = os.path.join(device_dir, k)
            data = _("%(timestamp)d %(value)s\n" % {'timestamp': timestamp,
                                                    'value': v})
            utils.write_file(file_name, data)  

    def update_device(self, **kwargs):
        """Update a device's data."""
        device_dict = self.get_device_dict()
        device_dict.update(kwargs)
        self.init_device(device_dict)
