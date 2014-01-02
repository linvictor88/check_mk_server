#!/usr/bin/python
import os
import sys
CHECK_MK_LIB_MODULE = os.path.join(os.path.dirname(__file__),
                             '..')
sys.path.append(CHECK_MK_LIB_MODULE)
from check_mk.common import utils
print utils.get_hostname()
