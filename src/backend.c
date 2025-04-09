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

    uint32_t seq = get_seq(hdr);
    uint32_t ack = get_ack(hdr);

    fprintf(stderr, "[HANDSHAKE] flags: %02x, type: %d\n", flags, sock->type);

    if (sock->type == TCP_INITIATOR) {
        if ((flags & SYN_FLAG_MASK) && (flags & ACK_FLAG_MASK)) {
            fprintf(stderr, "[HANDSHAKE] Initiator received SYN-ACK. Updating state...\n");

            sock->send_win.last_ack = ack - 1;
            sock->recv_win.next_expect = seq + 1;
            sock->recv_win.last_read = seq;
            sock->recv_win.last_recv = seq;
            sock->complete_init = true;
            send_empty(sock, ACK_FLAG_MASK, false, false);


            
            //fprintf(stderr, "[HANDSHAKE] Handshake complete: complete_init = true\n");

            // Send final ACK to complete handshake
            // send_empty(sock, ACK_FLAG_MASK, false, false);

            // Mark handshake complete
            // sock->complete_init = true;
        }

    } else if (sock->type == TCP_LISTENER) {

        // Case 1: Received SYN, respond with SYN-ACK
        if (flags == SYN_FLAG_MASK) {
            fprintf(stderr, "[HANDSHAKE] Listener received SYN. Sending SYN-ACK...\n");

            sock->recv_win.last_read = seq;
            sock->recv_win.last_recv = seq;
            sock->recv_win.next_expect = seq + 1;

            sock->send_win.last_ack = ntohl(hdr->seq_num);
            sock->send_win.last_write = 0;
            sock->send_win.last_sent = 0;

            sock->complete_init = false;
            send_empty(sock, SYN_FLAG_MASK | ACK_FLAG_MASK, false, false);

        }

        // Case 2: Received ACK to complete handshake
        else if ((flags & ACK_FLAG_MASK) && !(flags & SYN_FLAG_MASK)) {
            //fprintf(stderr, "[HANDSHAKE] Listener received ACK. Handshake complete.\n");

            sock->complete_init = true;
            //fprintf(stderr, "[HANDSHAKE] Handshake complete: complete_init = true\n");
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

        // Congestion window update (e.g., slow start or congestion avoidance)
        sock->cong_win = MIN(sock->cong_win + MSS, MAX_NETWORK_BUFFER);

        uint32_t acked_bytes = ack - sock->send_win.last_ack - 1;
        sock->send_win.last_ack = ack - 1;

        if (acked_bytes > 0 && acked_bytes <= sock->sending_len)
        {
          memmove(sock->sending_buf, sock->sending_buf + acked_bytes, sock->sending_len - acked_bytes);
          sock->sending_len -= acked_bytes;
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
        if (sock->dup_ack_count == 3)
        {
          sock->slow_start_thresh = sock->cong_win / 2;
          sock->cong_win = sock->slow_start_thresh + 3 * MSS;
          sock->send_win.last_sent = sock->send_win.last_ack;
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


    ut_tcp_header_t *hdr = (ut_tcp_header_t *)pkt;
    uint32_t seq = get_seq(hdr);
    uint16_t hlen = get_hlen(hdr);
    uint16_t plen = get_plen(hdr);
    uint16_t payload_len = plen - hlen;
    uint8_t *payload = pkt + hlen;

    uint32_t offset = seq - sock->recv_win.last_read - 1;

    if (offset + payload_len > MAX_NETWORK_BUFFER)
      return;

    if (offset + payload_len > sock->received_len)
    {
      sock->received_buf = realloc(sock->received_buf, offset + payload_len);
      sock->received_len = offset + payload_len;
    }

     memcpy(sock->received_buf + offset, payload, payload_len);

    if (seq == sock->recv_win.next_expect)
    {
      sock->recv_win.last_recv = seq;
      sock->recv_win.next_expect = seq + payload_len;
      send_empty(sock, ACK_FLAG_MASK, false, false);
    }

    // // Grow buffer if needed
    // sock->received_buf = realloc(sock->received_buf, sock->received_len + len);

    // fprintf(stderr, "[RECV_BUF] Allocating receive buffer of size %u\n", sock->received_len + len);


    // // Copy payload into receive buffer
    // memcpy(sock->received_buf + sock->received_len, data, len);
    // sock->received_len += len;

    // fprintf(stderr, "[RECV_BUF] Buffer after copy: ");
    // for (int i = 0; i < sock->received_len; i++) {
    //     fprintf(stderr, "%c", sock->received_buf[i]); // Or %02x
    // }
    // fprintf(stderr, "\n");

    // // Advance expected sequence number
    // sock->recv_win.next_expect += len;

    // // Update last received seq
    // sock->recv_win.last_recv = sock->recv_win.next_expect - 1;


    // // Send ACK for the new data
    // send_empty(sock, ACK_FLAG_MASK, false, false);

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

      if (flags & FIN_FLAG_MASK)
      {
        sock->recv_fin = true;
        sock->recv_fin_seq = get_seq(hdr);
        send_empty(sock, ACK_FLAG_MASK, true, false);
      }

      // Update advertised window
      sock->send_adv_win= get_advertised_window(hdr);

      if (flags & ACK_FLAG_MASK)
      {
        if (sock->send_fin_seq > 0 && get_seq(ack) == sock->send_fin_seq + 1)
        {
          sock->fin_acked = true;
        }
        else
        {
          handle_ack(sock, hdr);
        }
      }

    
    update_received_buf(sock, pkt);
    
 }

 void recv_pkts(ut_socket_t *sock)
 {
    
    fprintf(stderr, "In recv_pkts");
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
        while (pthread_mutex_lock(&(sock->send_lock)) != 0) {}

        sock->dup_ack_count = 0;

        // Timeout-based congestion control
        sock->slow_start_thresh = sock->cong_win / 2;
        sock->cong_win = MSS;

        // Go-back-N retransmit from last_ack
        sock->send_win.last_sent = sock->send_win.last_ack;

        pthread_mutex_unlock(&(sock->send_lock));
        return;
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


    uint32_t last_sent = sock->send_win.last_sent;
    uint32_t last_ack = sock->send_win.last_ack;
    uint16_t adv_win = sock->send_adv_win;

    uint32_t in_flight = last_sent - last_ack;
    uint32_t win = MIN(sock->cong_win, adv_win);

    while (in_flight < win && in_flight < sock->sending_len)
    {
      uint32_t send_off = in_flight;
      uint32_t remaining = sock->sending_len - send_off;
      uint16_t payload_len = MIN(remaining, MSS);

      uint16_t plen = sizeof(ut_tcp_header_t) + payload_len;
      uint32_t seq = last_ack + 1 + send_off;
      uint32_t ack = sock->recv_win.next_expect;

      uint8_t *payload = sock->sending_buf + send_off;

      uint8_t *pkt = create_packet(
          sock->my_port,
          ntohs(sock->conn.sin_port),
          seq,
          ack,
          sizeof(ut_tcp_header_t),
          plen,
          ACK_FLAG_MASK,
          MAX(MSS, MAX_NETWORK_BUFFER - sock->received_len),
          payload,
          payload_len);

      sendto(sock->socket, pkt, plen, 0, (struct sockaddr *)&(sock->conn), sizeof(sock->conn));
      free(pkt);

      sock->send_win.last_sent += payload_len;
      in_flight += payload_len;
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