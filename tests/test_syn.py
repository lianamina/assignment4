import unittest
from .common import (
    SYN_MASK,
    TIMEOUT,
    get_free_port,
    launch_client,
    launch_server,
    sniff,
    sr1,
    check_packet_is_valid_synack,
)

class TestCases(unittest.TestCase):
    def test_initiator_syn(self):
        print("Test if the initiator sends a SYN packet.")

        server_port = get_free_port()
        with launch_client(server_port):
            syn_pkts, client_port = sniff(count=0, timeout=TIMEOUT * 3, portno=server_port)

            if len(syn_pkts) == 0:
                print("Did not receive SYN packet from initiator after 3 RTO.")
                assert False

            if syn_pkts[0][UTTCP].flags != SYN_MASK:
                print(
                    f"First packet was not a syn packet. Expect only SYN flag in "
                    f"the first packet, but got {syn_pkts[0][UTTCP].flags}."
                )
                assert False
