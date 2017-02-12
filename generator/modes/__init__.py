import commands as bess_commands
from module import *

@staticmethod
def _choose_arg(arg, kwargs):
    if kwargs:
        if arg:
            raise TypeError('You cannot specify both arg and keyword args')

        for key in kwargs:
            if isinstance(kwargs[key], (Module,)):
                kwargs[key] = kwargs[key].name

        return kwargs

    if isinstance(arg, (Module,)):
        return arg.name
    else:
        return arg

def setup_mclasses(cli, globs):
    MCLASSES = [
        'FlowGen',
        'IPChecksum',
        'Measure',
        'QueueInc',
        'QueueOut',
        'RandomUpdate',
        'Rewrite',
        'RoundRobin',
        'Source',
        'Sink',
        'Timestamp',
        'Update',
    ]
    for name in MCLASSES:
        if name in globals():
            break
        globs[name] = type(str(name), (Module,), {'bess': cli.bess,
                               'choose_arg': _choose_arg})

from udp import UdpMode
from flowgen import FlowGenMode
from http import HttpMode
from gtpu import GtpuMode
