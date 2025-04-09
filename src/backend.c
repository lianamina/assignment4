/**
 * Copyright (C) 2022 Carnegie Mellon University
 * Copyright (C) 2025 University of Texas at Austin
 */

 #include "backend.h"

 #include <poll.h>
 #include <stdint.h>
 #include <stdio.h>
 #include <stdbool.h>
 #include <stdlib.h>
 #include <string.h>
 #include <sys/socket.h>
 #include <sys/types.h>
 #include <errno.h>

 #include "ut_packet.h"
 #include "ut_tcp.h"

 #define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
 #define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

 void send_empty(ut_socket_t *sock, int s_flags, bool fin_ack, bool send_fin)
 {
   size_t conn_len = sizeof(sock->conn);
   int sockfd = sock->socket;

   uint16_t src = sock->my_port;
   uint16_t dst = ntohs(sock->conn.sin_port);

   uint32_t seq = sock->send_win.last_sent + 1;
   if (send_fin)
   {
     seq = sock->send_fin_seq;
   }
   uint32_t ack = sock->recv_win.next_expect;
   if (fin_ack)
   {
     ack++;
   }

   uint16_t hlen = sizeof(ut_tcp_header_t);
   uint8_t flags = s_flags;
   uint16_t adv_window = MAX(MSS, MAX_NETWORK_BUFFER - sock->received_len);

   uint16_t payload_len = 0;
   uint8_t *payload = &flags;
   uint16_t plen = hlen + payload_len;
   fprintf(stderr, "[DEBUG] send_empty flags: 0x%x\n", flags);

   uint8_t *msg = create_packet(
       src, dst, seq, ack, hlen, plen, flags, adv_window, payload, payload_len);
   sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn), conn_len);
   free(msg);
 }

 bool check_dying(ut_socket_t *sock)
 {
   while (pthread_mutex_lock(&(sock->death_lock)) != 0)
   {
   }
   bool dying = sock->dying;
   if (dying)
   {
     while (pthread_mutex_lock(&(sock->send_lock)) != 0)
     {
     }
     if (sock->sending_len == 0)
     {
       sock->send_fin_seq = sock->send_win.last_write + 1;
     }
     else
     {
       dying = false;
     }
     pthread_mutex_unlock(&(sock->send_lock));
   }
   pthread_mutex_unlock(&(sock->death_lock));
   return dying;
 }

 void handle_pkt_handshake(ut_socket_t *sock, ut_tcp_header_t *hdr)
 {
   /*
   TODOs:
   * The `handle_pkt_handshake` function processes TCP handshake packets for a given socket.
   * It first extracts the flags from the TCP header and determines whether the socket is an initiator or a listener.
   * If the socket is an initiator, it verifies the SYN-ACK response and updates the send and receive windows accordingly.
   * If the socket is a listener, it handles incoming SYN packets and ACK responses, updating the socket’s state and windows as needed.
   */
    uint8_t flags = get_flags(hdr);
    fprintf(stderr, "[HANDSHAKE] flags: %02x, type: %d\n", flags, sock->type);

    if (sock->type == TCP_INITIATOR) {
        if ((flags & SYN_FLAG_MASK) && (flags & ACK_FLAG_MASK)) {
            fprintf(stderr, "[HANDSHAKE] Initiator received SYN-ACK. Updating state...\n");

            // Receive window setup
            sock->recv_win.last_read = get_seq(hdr);
            sock->recv_win.next_expect = get_seq(hdr) + 1;
            sock->recv_win.last_recv = sock->recv_win.next_expect - 1;

            // Send window setup
            sock->send_win.last_ack = get_ack(hdr) - 1;
            sock->send_win.last_sent = sock->send_win.last_ack;
            //sock->send_win.last_write = sock->send_win.last_sent + 1;

            // Flow control: update advertised window
            sock->send_adv_win = get_advertised_window(hdr);

            
            //fprintf(stderr, "[HANDSHAKE] Handshake complete: complete_init = true\n");

            // Send final ACK to complete handshake
            send_empty(sock, ACK_FLAG_MASK, false, false);

            // Mark handshake complete
            sock->complete_init = true;
            sock->send_syn = false;
        }

    } else if (sock->type == TCP_LISTENER) {

        // Case 1: Received SYN, respond with SYN-ACK
        if (flags == SYN_FLAG_MASK) {
            fprintf(stderr, "[HANDSHAKE] Listener received SYN. Sending SYN-ACK...\n");

            // Receive window setup
            sock->recv_win.last_read = get_seq(hdr);
            sock->recv_win.next_expect = get_seq(hdr) + 1;
            sock->recv_win.last_recv = sock->recv_win.next_expect - 1;
            fprintf(stderr, "[HANDSHAKE] Set next_expect = %u\n", sock->recv_win.next_expect);

            // Send window setup
            sock->send_win.last_ack = get_ack(hdr) - 1;
            sock->send_win.last_sent = get_ack(hdr) - 1;
            //sock->send_win.last_write = sock->send_win.last_sent + 1;

            // Flow control
            sock->send_adv_win = get_advertised_window(hdr);
            send_empty(sock, SYN_FLAG_MASK | ACK_FLAG_MASK, false, false);
            //sock->complete_init = true;

        }

        // Case 2: Received ACK to complete handshake
        else if ((flags & ACK_FLAG_MASK) && !(flags & SYN_FLAG_MASK)) {
            fprintf(stderr, "[HANDSHAKE] Listener received ACK. Handshake complete.\n");

            // Update send window
            sock->send_win.last_ack = get_ack(hdr) - 1;
            sock->send_win.last_sent = sock->send_win.last_ack;
            sock->send_win.last_write = sock->send_win.last_sent + 1;

            // Flow control
            sock->send_adv_win = get_advertised_window(hdr);

            // do not recv_win.next_expect here, it was set during SYN

            sock->complete_init = true;
            fprintf(stderr, "[HANDSHAKE] Handshake complete: complete_init = true\n");
        }
    }

 }

 void handle_ack(ut_socket_t *sock, ut_tcp_header_t *hdr)
 {
    fprintf(stderr, "in handle ack\n");
    uint32_t ack = get_ack(hdr);

   if (after(get_ack(hdr), sock->send_win.last_ack))
   {
     while (pthread_mutex_lock(&(sock->send_lock)) != 0)
     {
     }
     /*
     TODOs:
     * Reset duplicated ACK count to zero.
     * Update the congestion window.
     * Update the sender window based on the ACK field.
       * Update `last_ack`, re-allocate the sending buffer, and update the `sending_len` field.
     */

         // Reset duplicate ACK count
        sock->dup_ack_count = 0;

        // // Update the congestion window based on the state
        // if (sock->cong_win < sock->slow_start_thresh)
        // {
        //     // Slow start: Increase congestion window by MSS
        //     sock->cong_win += MSS;

        //     // Transition to congestion avoidance if threshold reached
        //     // if (sock->cong_win >= sock->slow_start_thresh)
        //     // {
        //     //     sock->slow_start_thresh = sock->cong_win;
        //     // }
        // }
        // else
        // {
        //     // Congestion avoidance: Additive increase
        //     sock->cong_win += (MSS * MSS) / sock->cong_win;
        // }

        // Update sender window
        uint32_t prev_ack = sock->send_win.last_ack;
        sock->send_win.last_ack = ack - 1;

        uint32_t offset = ack - prev_ack;
        if (offset > 0 && sock->sending_buf != NULL) {
            if (offset <= sock->sending_len) {
                // Move unacknowledged data to the beginning of the sending buffer
                memmove(sock->sending_buf, sock->sending_buf + offset, sock->sending_len - offset);
                sock->sending_len -= offset;
                fprintf(stderr, "[HANDLE_ACK] After memmove: sending_len=%u\n", sock->sending_len);
            } else {
                fprintf(stderr, "[ERROR] ACK offset %u exceeds sending_len %u\n", offset, sock->sending_len);
                sock->sending_len = 0;  // Safe reset
            }
        }

        pthread_mutex_unlock(&(sock->send_lock));
   }
   // Handle Duplicated ACK.
   else if (get_ack(hdr) == sock->send_win.last_ack)
   {
     if (sock->dup_ack_count == 3)  // `Fast recovery` state
     {
       sock->cong_win += MSS;
     }
     else // `Slow start` or `Congestion avoidance` state
     {
       /*
       TODOs:
       * Increment the duplicated ACK count (Up to 3).
       * If the duplicated ACK count reaches 3, adjust the congestion window and slow start threshold.
       * Retransmit missing segments using Go-back-N (i.e., update the `last_sent` to `last_ack`).
       */
        // Increment the duplicate ACK count
        sock->dup_ack_count++;

        if (sock->dup_ack_count == 3)  // Fast Recovery
        {
            sock->cong_win = MAX(sock->cong_win / 2, MSS);
            sock->slow_start_thresh = sock->cong_win;

            // Retransmit lost packets using Go-back-N (set last_sent to last_ack)
            sock->send_win.last_sent = sock->send_win.last_ack;
            send_pkts_data(sock);
        }
        
     }

   }
   
 }

 void update_received_buf(ut_socket_t *sock, uint8_t *pkt)
 {
   /*
   - This function processes an incoming TCP packet by updating the receive buffer based on the packet's sequence number and payload length.
   - If the new data extends beyond the last received sequence, it reallocates the receive buffer and copies the payload into the correct position.

   TODOs:
   * Extract the TCP header and sequence number from the packet.
   * Determine the end of the data segment and update the receive window if needed.
   * Copy the payload into the receive buffer based on the sequence number:
     * Ensure that the required buffer space does not exceed `MAX_NETWORK_BUFFER` before proceeding.
     * Use `memcpy` to copy the payload:
       memcpy(void *to, const void *from, size_t numBytes);
   * Send an acknowledgment if the packet arrives in order:
     * Use the `send_empty` function to send the acknowledgment.
   */


    ut_tcp_header_t *header = (ut_tcp_header_t *)pkt;
    uint32_t seq = get_seq(header);
    uint32_t len = get_plen(header);
    uint8_t *data = get_payload(pkt);

    if (len == 0) return;

    // fprintf(stderr, "[RECV_BUF] Payload content: ");
    // for (int i = 0; i < len; i++) {
    //     fprintf(stderr, "%c", data[i]); // Or %02x for hex
    // }
    // fprintf(stderr, "\n");

    //sock->received_len = len;


    fprintf(stderr, "[RECV_BUF] Received pkt seq=%u, len=%u, expected=%u\n", seq, len, sock->recv_win.next_expect);

    // Only accept data if it matches what we're expecting
    if (seq != sock->recv_win.next_expect) {
      fprintf(stderr, "[RECV_BUF] Dropping out-of-order packet. Expected %u but got %u\n", sock->recv_win.next_expect, seq);
        return;  // out-of-order, drop it
    }

    // Grow buffer if needed
    sock->received_buf = realloc(sock->received_buf, sock->received_len + len);

    fprintf(stderr, "[RECV_BUF] Allocating receive buffer of size %u\n", sock->received_len + len);


    // Copy payload into receive buffer
    memcpy(sock->received_buf + sock->received_len, data, len);
    sock->received_len += len;

    // fprintf(stderr, "[RECV_BUF] Buffer after copy: ");
    // for (int i = 0; i < sock->received_len; i++) {
    //     fprintf(stderr, "%c", sock->received_buf[i]); // Or %02x
    // }
    // fprintf(stderr, "\n");

    // Advance expected sequence number
    sock->recv_win.next_expect += len;

    // Update last received seq
    sock->recv_win.last_recv = sock->recv_win.next_expect - 1;


    // Send ACK for the new data
    send_empty(sock, ACK_FLAG_MASK, false, false);

 }

 void handle_pkt(ut_socket_t *sock, uint8_t *pkt)
 {

   ut_tcp_header_t *hdr = (ut_tcp_header_t *)pkt;
   uint8_t flags = get_flags(hdr);
   uint32_t ack = get_ack(hdr);
   uint16_t advertised_window = get_advertised_window(hdr);

  fprintf(stderr, "[HANDLE_PKT] flags: %02x, ack: %u, seq: %u, plen: %u\n",
        flags, get_ack(hdr), get_seq(hdr), get_plen(hdr));

   if (!sock->complete_init)
   {
     handle_pkt_handshake(sock, hdr);
     return;
   }
     /*
     TODOs:
     * Handle the FIN flag.
       * Mark the socket as having received a FIN, store the sequence number, and send an ACK response.

     * Update the advertised window.
     * Handle the ACK flag. You will have to handle the following cases:
       1) ACK after sending FIN.
         * If the ACK is for the FIN sequence, mark the socket as FIN-ACKed.
       2) ACK after sending data.
         * If the ACK is for a new sequence, update the send window and congestion control (call `handle_ack`).
     * Update the receive buffer (call `update_received_buf`).
     */

     // Handle FIN
    if (flags & FIN_FLAG_MASK) {
      fprintf(stderr, "[HANDLE_PKT] Received FIN. Sending ACK...\n");

      sock->recv_fin = 1;
      sock->recv_fin_seq = get_seq(hdr);

      // Send ACK for FIN
      send_empty(sock, ACK_FLAG_MASK, true, false);
    }


    // update to be MAX_NETWORK_BUFFER - (last_recv - last_read)?
    // The sender updates the advertised window (sock->send_adv_win) as it processes incoming data.
    sock->send_adv_win = advertised_window;

    if (flags & ACK_FLAG_MASK) {
        // Case 1: ACK after sending FIN
        if (sock->recv_fin == 1) {
            fprintf(stderr, "[HANDLE_PKT] Received ACK for our FIN\n");
            sock->fin_acked = 1;
        }
        // Case 2: ACK for data
        else if (ack > sock->send_win.last_ack) {
            // gets here but not inside???
            fprintf(stderr, "before handle ack\n");
            handle_ack(sock, hdr);
        }
        // Fast retransmit logic

        // else if (ack == sock->send_win.last_ack) {
        //     // Duplicate ACK handling
        //     sock->dup_ack_count++;
        //     if (sock->dup_ack_count == 3) {
        //         fprintf(stderr, "[HANDLE_PKT] Fast retransmit triggered\n");
        //         // TODO: Implement fast retransmit logic
        //     }

        // }

    }

    
    update_received_buf(sock, pkt);
    
 }

 void recv_pkts(ut_socket_t *sock)
 {
    
    fprintf(stderr, "In recv_pkts\n");
   ut_tcp_header_t hdr;
   uint8_t *pkt;
   socklen_t conn_len = sizeof(sock->conn);
   ssize_t len = 0, n = 0;
   uint32_t plen = 0, buf_size = 0;

   struct pollfd ack_fd;
   ack_fd.fd = sock->socket;
   ack_fd.events = POLLIN;
   if (poll(&ack_fd, 1, DEFAULT_TIMEOUT) > 0)
   {
     len = recvfrom(sock->socket, &hdr, sizeof(ut_tcp_header_t),
                    MSG_DONTWAIT | MSG_PEEK, (struct sockaddr *)&(sock->conn),
                    &conn_len);
   }
   else  // TIMEOUT
   {
     /*
     TODOs:
     * Reset duplicated ACK count to zero.
     * Implement the rest of timeout handling
       * Congestion control window and slow start threshold adjustment
       * Adjust the send window for retransmission of lost packets (Go-back-N)
     */

     
     // PART 3 CODE


        // while (pthread_mutex_lock(&(sock->send_lock)) != 0) {}

        // // Reset duplicated ACK count
        // sock->dup_ack_count = 0;

        // // Reset congestion window and slow start threshold
        // sock->cong_win = MSS;
        // sock->slow_start_thresh = MAX(sock->cong_win / 2, MSS);

        // // Retransmit missing packets (Go-back-N)
        // sock->send_win.last_sent = sock->send_win.last_ack;
        // send_pkts_data(sock);

        // pthread_mutex_unlock(&(sock->send_lock));
   }

   if (len >= (ssize_t)sizeof(ut_tcp_header_t))
   {
     plen = get_plen(&hdr);
     pkt = malloc(plen);
    while (buf_size < plen)
    {
      n = recvfrom(sock->socket, pkt + buf_size, plen - buf_size, 0,
                  (struct sockaddr *)&(sock->conn), &conn_len);
      if (n <= 0) break;
      buf_size += n;
    }
     while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
     {
     }
     handle_pkt(sock, pkt);
     pthread_mutex_unlock(&(sock->recv_lock));
     free(pkt);
   }
 }



 void send_pkts_handshake(ut_socket_t *sock)
 {
   /*
   TODOs:
   * Implement the handshake initialization logic.
   * We provide an example of sending a SYN packet by the initiator below:
   */
    if (sock->complete_init) {
      // Handshake already complete, nothing to send
      return;
    }

    if (sock->type == TCP_INITIATOR) {
      if (sock->send_syn) {
        // Send initial SYN
        fprintf(stderr, "[SEND_PKTS] Sending packets, initial SYN\n");
        send_empty(sock, SYN_FLAG_MASK, false, false);
      }
      // Waits for SYN+ACK and then sends ACK handled in handle_pkt_handshake()
    }
    else if (sock->type == TCP_LISTENER) {
      // Listener passively waits — all responses triggered in handle_pkt_handshake()
      // No need to send anything actively here
    }
 }

 void send_pkts_data(ut_socket_t *sock)
 {
   /*
   * Sends packets of data over a TCP connection.
   * This function handles the transmission of data packets over a TCP connection
     using the provided socket. It ensures that the data is sent within the constraints
     of the congestion window, advertised window, and maximum segment size (MSS).

   TODOs:
   * Calculate the available window size for sending data based on the congestion window,
     advertised window, and the amount of data already sent.
   * Iterate the following steps until the available window size is consumed in the sending buffer:
     * Create and send packets with appropriate sequence and acknowledgment numbers,
       ensuring the payload length does not exceed the available window or MSS.
       * Refer to the send_empty function for guidance on creating and sending packets.
     * Update the last sent sequence number after each packet is sent.
   */


    sock->send_adv_win = MAX_NETWORK_BUFFER - (sock->recv_win.last_recv - sock->recv_win.last_read);

    uint32_t window = MIN(sock->cong_win, sock->send_adv_win);

    if (sock->send_win.last_write > sock->send_win.last_sent) {
        uint32_t available_data = sock->send_win.last_write - sock->send_win.last_sent;
        window = MIN(window, available_data);
    } else {
        return; // Nothing to send
    }
    
    //use sending_len to terminate process (everytime you send something), update when you receive ACK
    // last write - last ack
    fprintf(stderr, "[SEND_DATA] Can send: %u bytes, sending_len: %u\n", window, sock->sending_len);

    


    // Send data as long as there's space in the window
    while (window > 0)
    {
        fprintf(stderr, "in while loop\n");

        // ALWAYS 1 SHOULDN'T BE
        //uint32_t unsent_bytes = sock->send_win.last_write - sock->send_win.last_sent;

        //fprintf(stderr, "[MIN] unsent: %u bytes, window: %u, MSS: %u\n", unsent_bytes, window, MSS);
        // Calculate how much data we can send in this packet
        
        uint32_t to_send = MIN(sock->sending_len, MSS);

        // comment out to keep looping
        if (to_send == 0) break;

        // Create a packet to send based on the available window
        uint32_t seq = sock->send_win.last_sent + 1;
        uint32_t ack = sock->recv_win.next_expect;


        size_t conn_len = sizeof(sock->conn);
        int sockfd = sock->socket;

        uint16_t src = sock->my_port;
        uint16_t dst = ntohs(sock->conn.sin_port);


        // be updating received len somewhere (REPLACE)
        //fprintf(stderr, "[REC LEN] Can send: %u bytes, received_len: %u\n", window, sock->received_len);

        uint16_t adv_window = MAX(MSS, MAX_NETWORK_BUFFER - (sock->recv_win.last_recv - sock->recv_win.last_read));
        uint16_t hlen = sizeof(ut_tcp_header_t);
        uint8_t flags = ACK_FLAG_MASK;
      
        // actual packet we want to send to sending buffer
        uint16_t payload_len = to_send;
        sock->sending_buf = malloc(payload_len);
        if (!sock->sending_buf) {
            perror("[SEND_DATA] Failed to allocate sending_buf");
            return;
        }
        uint8_t *payload = sock->sending_buf;
        uint16_t plen = hlen + payload_len;

        fprintf(stderr, "[CREATE] To send: %u bytes, window: %u\n", to_send, window);

        uint8_t *msg = create_packet(
            src, dst, seq, ack, hlen, plen, flags, adv_window, payload, payload_len);

        sendto(sockfd, msg, plen, 0, (struct sockaddr *)&(sock->conn), conn_len);
        free(msg);
        free(sock->sending_buf);
        sock->sending_buf = NULL;


        fprintf(stderr, "[SEND_DATA] Sending data seq=%u, len=%u\n", seq, payload_len);

        // Adjust the sending buffer after sending a packet
        sock->send_win.last_sent += to_send;
        window -= to_send;
        
        // Safely update sending_len
        if (sock->sending_len >= to_send) {
            sock->sending_len -= to_send;
        } else {
            fprintf(stderr, "[WARNING] sending_len underflow detected! Resetting to 0.\n");
            sock->sending_len = 0;
        }
        //sock->sending_buf += to_send;

        fprintf(stderr, "End of while loop, window: %u\n", window);

    }
    
    
 }
 

 void send_pkts(ut_socket_t *sock)
 {
  // GETTING HERE
   if (!sock->complete_init)
   {
     send_pkts_handshake(sock);
   }
   else
   {
     // Stop sending when duplicated ACKs are received and not in fast recovery state.
     if (sock->dup_ack_count < 3 && sock->dup_ack_count > 0)
       return;
     while (pthread_mutex_lock(&(sock->send_lock)) != 0)
     {
     }
     send_pkts_data(sock);
     pthread_mutex_unlock(&(sock->send_lock));
   }
 }

 void *begin_backend(void *in)
 {
   ut_socket_t *sock = (ut_socket_t *)in;
   int death, buf_len, send_signal;
   uint8_t *data;

   while (1)
   {
     if (check_dying(sock))
     {
       if (!sock->fin_acked)
       {
         send_empty(sock, FIN_FLAG_MASK, false, true);
       }
     }

     if (sock->fin_acked && sock->recv_fin)
     {
       // Finish the connection after timeout
       sleep(DEFAULT_TIMEOUT / 1000);
       break;
     }
     send_pkts(sock);
     fprintf(stderr, "[RECV] Waiting for packet...\n");

     recv_pkts(sock);
     fprintf(stderr, "[RECV] Packet received: %u bytes\n", buf_len);

     while (pthread_mutex_lock(&(sock->recv_lock)) != 0)
     {
     }
     uint32_t avail = sock->recv_win.next_expect - sock->recv_win.last_read - 1;
     send_signal = avail > 0;
     pthread_mutex_unlock(&(sock->recv_lock));

     if (send_signal)
     {
       pthread_cond_signal(&(sock->wait_cond));
     }
   }
   pthread_exit(NULL);
   return NULL;
 }