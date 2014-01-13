#!/usr/bin/python
import json
import sys
sys.path.append('/home/nagios/check_mk/')
from check_mk.devices import devices
from check_mk.devices import vm

device_lists = []
def get_device_obj(Device):
    device = Device()
    global device_lists
    device_lists.append(device)
    return device
memory = get_device_obj(devices.Memory)
cpu = get_device_obj(devices.Cpu)
disks = get_device_obj(devices.Disks)
system = get_device_obj(devices.System)
nets = get_device_obj(devices.Nets)
vm = vm.Vm(device_lists)
print json.dumps(vm.get_vm_dict(), indent=4)
vm.write_vm_file()
