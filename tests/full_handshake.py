import unittest
from .common import (
    SYN_MASK,
    ACK_MASK,
    UTTCP,
    get_free_port,
    launch_server,
    sr1,
    send,
    sniff,
    check_packet_is_valid_synack,
    get_ut,
)

class TestCases(unittest.TestCase):
    
    def test_full_handshake(self):
        """
        Test the full TCP handshake (SYN, SYN-ACK, ACK) between client and server.
        """
        print("Testing full TCP handshake: SYN, SYN-ACK, ACK")

        server_port = get_free_port()  # Get a free port for the server
        client_port = get_free_port()  # Get a free port for the client

        # Step 1: Create SYN packet
        syn_packet = UTTCP(plen=23, seq_num=1000, flags=SYN_MASK)
        expected_ack_num = syn_packet.seq_num + 1

        # Step 2: Launch server (mock server-side)
        with launch_server(server_port):
            # Step 3: Send SYN from client and get SYN-ACK in response
            print("Sending SYN packet from client...")
            resp = sr1(syn_packet, TIMEOUT, server_port, client_port)

            # Validate the SYN-ACK response
            print("Validating SYN-ACK response...")
            if not check_packet_is_valid_synack(resp, expected_ack_num):
                self.fail("Failed to receive a valid SYN-ACK.")

            # Step 4: Create ACK packet to complete handshake
            ack_packet = UTTCP(plen=23, seq_num=1001, ack_num=resp[UTTCP].seq_num + 1, flags=ACK_MASK)

            # Step 5: Send ACK packet back to server
            print("Sending ACK packet to complete handshake...")
            send(ack_packet, client_port, server_port)

            # Step 6: Capture and validate the ACK packet on the server side
            print("Sniffing for ACK packet on the server...")
            ack_pkts, _ = sniff(count=1, timeout=TIMEOUT, portno=server_port)
            if len(ack_pkts) == 0:
                self.fail("No ACK packet received on server.")
            elif ack_pkts[0][UTTCP].flags != ACK_MASK:
                self.fail(f"Received unexpected packet with flags {ack_pkts[0][UTTCP].flags}, expected only ACK.")
            
            print("Handshake completed successfully.")

    def test_syn_ack_with_random_sequence_number(self):
        """
        Test SYN-ACK response handling with a random initial sequence number for SYN packet.
        """
        print("Testing SYN-ACK response with a random initial sequence number")

        server_port = get_free_port()  # Get a free port for the server
        client_port = get_free_port()  # Get a free port for the client

        # Step 1: Create SYN packet with a random sequence number
        syn_packet = UTTCP(plen=23, seq_num=98765, flags=SYN_MASK)
        expected_ack_num = syn_packet.seq_num + 1

        # Step 2: Launch server (mock server-side)
        with launch_server(server_port):
            # Step 3: Send SYN from client and get SYN-ACK in response
            print("Sending SYN packet with random seq_num from client...")
            resp = sr1(syn_packet, TIMEOUT, server_port, client_port)

            # Step 4: Validate the SYN-ACK response
            print("Validating SYN-ACK response...")
            if not check_packet_is_valid_synack(resp, expected_ack_num):
                self.fail("Failed to receive a valid SYN-ACK with random sequence number.")

            print("SYN-ACK response successfully validated.")

    # Feel free to add more tests!

