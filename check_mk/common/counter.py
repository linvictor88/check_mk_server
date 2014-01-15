# vim: tabstop=4 shiftwidth=4 softtabstop=4

import os

COUNTER_DIR = os.path.join(os.path.dirname(__file__), 
    '../devices/counters')
# Variable                 time_t    value
# netctr.eth.tx_collisions 112354335 818
def load_counters(hostname):
    global g_counters
    filename = COUNTER_DIR + "/" + hostname
    try:
        g_counters = eval(file(filename).read())
    except:
        # Try old syntax
        try:
            lines = file(filename).readlines()
            for line in lines:
                line = line.split()
                g_counters[' '.join(line[0:-1])] = (float(line[-1]) )
        except:
            g_counters = {}


def get_counter(countername):
    global g_counters

    # First time we see this counter? Do not return
    # any data!
    if not countername in g_counters:
        g_counters[countername] = 0.0
    else:
        return g_counters.get(countername)

def update_counter(countername, value):
    global g_counters
    if countername:
        g_counters[countername] = value

def save_counters(hostname):
    global g_counters
    filename = COUNTER_DIR + "/" + hostname
    if not os.path.exists(COUNTER_DIR):
        os.makedirs(COUNTER_DIR)
    file(filename, "w").write("%r\n" % g_counters)
