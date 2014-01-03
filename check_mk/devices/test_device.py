#!/usr/bin/python
import sys
sys.path.append('/home/nagios/check_mk/')
from check_mk.devices import devices
def get_device_obj(Device):
    device = Device()
    return device

memory = get_device_obj(devices.Memory)
memory.write_device_file('test_host')
