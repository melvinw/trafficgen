import scapy.all as scapy

from generator.common import TrafficSpec, Pipeline
from generator.modes import setup_mclasses
from scapy_gtp import *

def _build_pkt(spec, size):
    eth = scapy.Ether(src=spec.src_mac, dst=spec.dst_mac)
    outer_ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
    outer_udp = scapy.UDP(sport=10001, dport=10002, chksum=0)
    gtpu = GTP_U_Header()
    inner_ip = scapy.IP(src=spec.src_ip, dst=spec.dst_ip)
    inner_udp = scapy.UDP(sport=10001, dport=10002, chksum=0)
    payload = ('hello' + '0123456789' * 200)[:size]
    pkt = eth/outer_ip/outer_udp/gtpu/inner_ip/inner_udp/payload
    return str(pkt)

class GtpuMode(object):
    name = 'gtpu'

    class Spec(TrafficSpec):
        def __init__(self, num_enb=1, flows_per_teid=5, num_teids=1,
                     payload_size=8, dut_decap=False, **kwargs):
            self.num_enb = flows_per_teid
            self.flows_per_teid = flows_per_teid
            self.num_teids = num_teids
            self.payload_size = payload_size
            self.dut_decap = dut_decap
            super(GtpuMode.Spec, self).__init__(**kwargs)

    def __str__(self):
        s = super(GtpuMode.Spec, self).__str__() + '\n'
        attrs = [
            ('num_enb', lambda x: str(x)),
            ('flows_per_teid', lambda x: str(x)),
            ('num_teids', lambda x: str(x)),
            ('payload_size', lambda x: str(x)),
            ('dut_decap', lambda x: 'true' if x else 'false')
        ]
        return s + self._attrs_to_str(attrs, 25)

    def __repr__(self):
        return self.__str__()

    @staticmethod
    def setup_pipeline(cli, port, spec, qid):
        setup_mclasses(cli, globals())
        pkt_templates = [_build_pkt(spec, spec.payload_size)]

        num_enb = spec.num_enb
        flows_per_teid = spec.flows_per_teid

        # Setup tx pipeline
        tx_pipe = Pipeline([
            Source(),
            Rewrite(templates=pkt_templates),
            # generate outer src ip, teid, inner dst_ip (in that order)
            RandomUpdate(fields=[{'offset': 26, 'size': 4, 'min': 0x0a000001,
                                  'max': 0x0a000001 + num_enb - 1},
                                 {'offset': 46, 'size': 4, 'min': 1,
                                  'max': 1 + spec.num_teids},
                                 {'offset': 66, 'size': 4, 'min': 0x0a000001,
                                   'max': 0x0a000001 + flows_per_teid - 1}]),
            IPChecksum(),
            Timestamp(offset=78),
            QueueOut(port=port, qid=qid)
        ])

        if spec.dut_decap:
            rx_offset = 0
        else:
            rx_offset = 78

        # Setup rx pipeline
        rx_pipe = Pipeline([QueueInc(port=port, qid=qid),
                            Measure(offset=rx_offset), Sink()])

        return (tx_pipe, rx_pipe)
