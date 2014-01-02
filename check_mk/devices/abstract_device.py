# vim: tabstop=4 shiftwidth=4 softtabstop=4

import abc

import six


@six.add_metaclass(abc.ABCMeta)
class AbstractDevice(object):
    """Abstract Device that expose same API.

    Real Devices including cpu,memmory,disk...etc should implement its some
    functions.
    """

    def __init__(self, device_dict=None):
        if not device_dict:
            self.plain_info = self.get_plain_info()
            self.parse_plain_info(self.plain_info)
        else:
            self.init_device(device_dict)

    @abc.abstractmethod
    def get_plain_info(self):
        """Get the plain info of device through calling commands."""
        pass

    @abc.abstractmethod
    def parse_plain_info(self, plain_info):
        pass

    @abc.abstractmethod
    def get_device_dict(self):
        pass

    @abc.abstractmethod
    def init_device(self, device_dict):
        pass
