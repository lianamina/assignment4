import unittest
from .common import (
    SYN_MASK,
    ACK_MASK,
    TIMEOUT,
    get_free_port,
    launch_server,
    sr1,
    check_packet_is_valid_synack,
)

class TestCases(unittest.TestCase):
    def test_listener_syn_ack(self):
        print("Test if the server sends a valid SYN+ACK packet.")

        server_port = get_free_port()
        client_port = get_free_port()
        
        # Define the SYN packet to send
        syn_packet = UTTCP(plen=23, seq_num=1000, flags=SYN_MASK)

        with launch_server(server_port):
            # Send the SYN packet and wait for the response
            response = sr1(syn_packet, TIMEOUT, server_port, client_port)
            next_seq_num = syn_packet[UTTCP].seq_num + 1
            
            # Validate the response SYN+ACK packet
            if check_packet_is_valid_synack(response, next_seq_num):
                print("Received valid SYN+ACK packet.")
            else:
                print("Failed to receive valid SYN+ACK packet.")
                assert False
