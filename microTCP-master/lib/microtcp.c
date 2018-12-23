/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "microtcp.h"
#include "../utils/crc32.h"

/*util_functions and macros*/
#define MIN_2(a,b) ((a) < (b) ? (a):(b))
#define MIN_3(a,b,c) (MIN_2(MIN_2((a),(b)),(c)))

void prepare_send_header(microtcp_header_t *header_snd) {
  header_snd->seq_number = htonl(header_snd->seq_number);
  header_snd->ack_number = htonl(header_snd->ack_number);
  header_snd->control = htons(header_snd->control);
  header_snd->window = htons(header_snd->window);
  header_snd->data_len = htonl(header_snd->data_len);
  header_snd->future_use0 = 0;
  header_snd->future_use1 = 0;
  header_snd->future_use2 = 0;
  header_snd->checksum = htonl(header_snd->checksum);
  header_snd->left_sack = htonl(header_snd->left_sack);
  header_snd->right_sack = htonl(header_snd->right_sack);
}

void prepare_checksum_header(microtcp_header_t *header_snd, uint32_t seq,
                             uint32_t ack, uint16_t control, uint16_t win,
                             uint32_t dlen) {
  memset(header_snd, 0, sizeof(microtcp_header_t));
  header_snd->seq_number = seq;
  header_snd->ack_number = ack;
  header_snd->control = control;
  header_snd->window = win;
  header_snd->data_len = dlen;
  header_snd->future_use0 = 0;
  header_snd->future_use1 = 0;
  header_snd->future_use2 = 0;
  header_snd->checksum = 0;
  header_snd->left_sack = header_snd->ack_number;
  header_snd->right_sack = header_snd->ack_number;
}

void prepare_read_header(microtcp_header_t *packet_read,
                         microtcp_header_t *header_rcv) {
  packet_read->seq_number = ntohl(header_rcv->seq_number);
  packet_read->ack_number = ntohl(header_rcv->ack_number);
  packet_read->control = ntohs(header_rcv->control);
  packet_read->window = ntohs(header_rcv->window);
  packet_read->data_len = ntohl(header_rcv->data_len);
  packet_read->future_use0 = 0;
  packet_read->future_use1 = 0;
  packet_read->future_use2 = 0;
  packet_read->checksum = ntohl(header_rcv->checksum);
  packet_read->left_sack = ntohl(header_rcv->left_sack);
  packet_read->right_sack = ntohl(header_rcv->right_sack);
}

uint32_t retransmit_send(microtcp_sock_t *socket, const void *buffer, uint32_t seq, size_t length){
  /*Retransmits length bytes from seq */
  size_t s = sizeof(microtcp_header_t);
  uint8_t send_buffer[MICROTCP_MSS+s];
  microtcp_header_t header_send;
  uint32_t bytes_to_send;
  uint32_t tmp_bytes;
  uint32_t actual_data_sent=0;
  size_t message_len;
  int packets_num; 
  size_t data_sent = 0;
  uint32_t tmpChecksum;
  int i = 0;
  struct timespec tmp_time;
  double elapsed;
  
  bytes_to_send = MIN_3(socket->curr_win_size, socket->cwnd, length);

  packets_num = bytes_to_send / MICROTCP_MSS; 

  for (i = 0; i < packets_num; i++) {

    message_len = MICROTCP_MSS;
    
    prepare_checksum_header(&header_send, seq ,socket->ack_number, ACK, socket->curr_win_size,
                            message_len);

    memset(send_buffer, '\0', MICROTCP_MSS + s);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + data_sent, message_len);

    /*Checksums*/
    tmpChecksum = crc32(send_buffer, sizeof(send_buffer));
    header_send.checksum = tmpChecksum;

    prepare_send_header(&header_send);

    memset(send_buffer, '\0', MICROTCP_MSS + s);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + data_sent, message_len);

    // printf("IP: %zu \n", ntohl(socket->sin->sin_addr.s_addr));
    // printf("Port: %u\n", ntohs(socket->sin->sin_port));

    if ((tmp_bytes = sendto(socket->sd, (void *)send_buffer, MICROTCP_MSS+s, 0, (struct sockaddr *)socket->sin,
                          socket->address_len)) == -1) {
      perror("failed to send the packet inside  the helper function\n");
      return -1;
    }

    clock_gettime (CLOCK_MONOTONIC_RAW, &tmp_time);
    if( socket->last_sent.tv_nsec == 0){
      /*First packet*/
      socket->last_sent.tv_sec = tmp_time.tv_sec;
      socket->last_sent.tv_nsec = tmp_time.tv_nsec;
    }else{
      elapsed = tmp_time.tv_sec - socket->last_sent.tv_sec + (tmp_time.tv_nsec - socket->last_sent.tv_nsec) * 1e-9;
      if( socket->tx_min_inter == 0 || elapsed < socket->tx_min_inter ){
        socket->tx_min_inter = elapsed;
      }
      if( socket->tx_max_inter == 0 || elapsed > socket->tx_max_inter ){
        socket->tx_max_inter = elapsed;
      }
      socket->tx_mean_inter = (socket->tx_mean_inter + elapsed) / socket->packets_send;
    }
    
    //printf("Retransmiting : %s\n", send_buffer+sizeof(header_send));

    seq += message_len;
    /*At the moment we suppose everything */
    data_sent += message_len;
    actual_data_sent += tmp_bytes - sizeof(microtcp_header_t);   
  }

  if ((bytes_to_send % MICROTCP_MSS) > 0){
    /*perisepsan kapoia bytes < apo MSS bytes*/
    packets_num++;
    message_len = bytes_to_send % MICROTCP_MSS;

    prepare_checksum_header(&header_send, seq ,socket->ack_number, ACK, socket->curr_win_size,
                            message_len);

    memset(send_buffer, '\0', MICROTCP_MSS+s);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + data_sent, message_len);
    
    /*Checksums*/
    tmpChecksum = crc32(send_buffer, message_len + s);
    header_send.checksum = tmpChecksum;

    prepare_send_header(&header_send);
  
    memset(send_buffer, '\0', MICROTCP_MSS+s);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + data_sent, message_len);

    if ((tmp_bytes = sendto(socket->sd, (void *)send_buffer, message_len + s, 0, (struct sockaddr *)socket->sin,
                          socket->address_len)) == -1) {
      perror("failed to send the packet inside helper if segment\n");
      return -1;
    }
    
    clock_gettime (CLOCK_MONOTONIC_RAW, &tmp_time);
    if( socket->last_sent.tv_nsec == 0){
      /*First packet*/
      socket->last_sent.tv_sec = tmp_time.tv_sec;
      socket->last_sent.tv_nsec = tmp_time.tv_nsec;
    }else{
      elapsed = tmp_time.tv_sec - socket->last_sent.tv_sec + (tmp_time.tv_nsec - socket->last_sent.tv_nsec) * 1e-9;
      if( socket->tx_min_inter == 0 || elapsed < socket->tx_min_inter ){
        socket->tx_min_inter = elapsed;
      }
      if( socket->tx_max_inter == 0 || elapsed > socket->tx_max_inter ){
        socket->tx_max_inter = elapsed;
      }
      socket->tx_mean_inter = (socket->tx_mean_inter + elapsed) / socket->packets_send;
    }
    
    seq += message_len;
  }
  socket->packets_send += packets_num;
  return seq; /*san target ack*/
}

void print_stats(microtcp_sock_t *socket){
  /*Print stats for the socket*/
  printf("packets recieved  : %d\n",socket->packets_received);
  printf("packets sent : %d\n",socket->packets_send);
  printf("packets lost : %d\n",socket->packets_lost);
  printf("rx_min_inter : %lf\n", socket->rx_min_inter);
  printf("rx_max_inter : %lf\n", socket->rx_max_inter);
  printf("rx_mean_inter : %lf\n", socket->rx_mean_inter);
  printf("tx_min_inter : %lf\n", socket->tx_min_inter);
  printf("tx_max_inter : %lf\n", socket->tx_max_inter);
  printf("tx_mean_inter : %lf\n", socket->tx_mean_inter);
}
/*end*/

microtcp_sock_t microtcp_socket(int domain, int type, int protocol) {
  /* Your code here */
  microtcp_sock_t new_socket;
  new_socket.sd = socket(domain, type, protocol);
  if (new_socket.sd == -1) {
    perror("MICRO_TCP_Socket creation failed\n");
    new_socket.state = INVALID;
    return new_socket;
  }
  new_socket.state = UNKNOWN;
  new_socket.init_win_size = MICROTCP_WIN_SIZE;
  new_socket.curr_win_size = MICROTCP_WIN_SIZE;
  new_socket.cwnd = MICROTCP_INIT_CWND;
  new_socket.ssthresh = MICROTCP_INIT_SSTHRESH;
  new_socket.recvbuf = malloc(MICROTCP_RECVBUF_LEN);
  new_socket.buf_fill_level = 0;
  new_socket.seq_number = 0;
  new_socket.ack_number = 0;
  new_socket.packets_send=0;
  new_socket.packets_received=0;
  new_socket.packets_lost=0;
  new_socket.bytes_send=0;
  new_socket.bytes_lost=0;
  new_socket.index=0;
  new_socket.poll_flag=0;
  new_socket.rx_min_inter=0;
  new_socket.rx_max_inter=0;
  new_socket.rx_mean_inter=0;
  new_socket.tx_min_inter=0;
  new_socket.tx_max_inter=0;
  new_socket.tx_mean_inter=0;
  new_socket.last_sent.tv_sec = 0;
  new_socket.last_sent.tv_nsec = 0;
  new_socket.last_rcvd.tv_sec = 0;
  new_socket.last_rcvd.tv_nsec = 0;
  return new_socket;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len) {
  int bind_status;
  bind_status = bind(socket->sd, address, address_len);
  /* Your code here */
  if (bind_status < 0) {
    perror("MICRO_TCP_bind failed\n");
    return bind_status;
  }
  return bind_status;
}

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len) {
  /* Your code here */
  uint8_t rcvbuf[sizeof(microtcp_header_t)];
  microtcp_header_t *header_rcv;
  microtcp_header_t packet_read;
  microtcp_header_t header_snd;
  size_t i;
  uint32_t seq_n = 0; /*N*/
  int s = sizeof(microtcp_header_t);
  uint32_t tmp_checksum;
  uint8_t checksum_buf[sizeof(microtcp_header_t)];

  printf("1\n");
  srand(time(NULL));
  /*Send first packet*/
  /*Set header fields*/
  seq_n = (rand() % 1024 + 1);
  socket->seq_number = seq_n;
  prepare_checksum_header(&header_snd, socket->seq_number, 0, SYN,
                          MICROTCP_WIN_SIZE, 0);

  /*Set buffer values to 0*/
  for (i = 0; i < sizeof(microtcp_header_t); i++) {
    checksum_buf[i] = '\0';
  }
  memcpy(checksum_buf, &header_snd, sizeof(header_snd));
  header_snd.checksum = crc32(checksum_buf, sizeof(checksum_buf));
  prepare_send_header(&header_snd);
	ssize_t snt = 0;
  /*send SYN packet*/
  printf("2\n");
  if ((snt=sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0,
             address, address_len)) == -1) {
    perror("Send SYN packet failed\n");
    printf("skata\n");
    socket->state = INVALID;
    return -1;
  }
  printf("3\n");
  socket->seq_number += s;
  /*Waiting for SYN_ACK from server*/
  /*Receive second packet*/
  header_rcv = (microtcp_header_t *)malloc(sizeof(microtcp_header_t *));

  if (recvfrom(socket->sd, rcvbuf, sizeof(microtcp_header_t), 0,
               (struct sockaddr *)address, &address_len) == -1) {
    perror("Something went wrong while receiving SYN_ACK\n");
    socket->state = INVALID;
    return -1;
  }
  printf("4\n");
  memcpy(header_rcv, (microtcp_header_t *)rcvbuf, sizeof(microtcp_header_t));

  prepare_read_header(&packet_read, header_rcv);

  tmp_checksum = packet_read.checksum;
  packet_read.checksum = 0;

  for (i = 0; i < sizeof(microtcp_header_t); i++) {
    checksum_buf[i] = '\0';
    rcvbuf[i] = '\0';
  }
  memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
  packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));

  if (tmp_checksum != packet_read.checksum) {
    perror("Checksum is invalid\n");
    socket->state = INVALID;
    return -1;
  }

  if (packet_read.control != SYN_ACK) {
    perror("SYN_ACK didn't received\n");
    socket->state = INVALID;
    return -1;
  }
  if (packet_read.ack_number != socket->seq_number) {
    perror("expected N+s didnt get it\n");
    socket->state = INVALID;
    return -1;
  }

  /*Sending second packet*/
  /*SYN_ACK received, send the 3rd packet*/
  prepare_checksum_header(&header_snd, socket->seq_number,
                          packet_read.seq_number + s, ACK, MICROTCP_WIN_SIZE,
                          0);

  for (i = 0; i < sizeof(microtcp_header_t); i++) {
    checksum_buf[i] = '\0';
  }
  memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
  header_snd.checksum = crc32(checksum_buf, sizeof(checksum_buf));
  prepare_send_header(&header_snd);
  printf("5\n");
  if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0,
             address, address_len) == -1) {
    perror("Send SYN packet failed\n");
    socket->state = INVALID;
    return -1;
  } else {
    printf("6\n");
    socket->state = ESTABLISHED;
    socket->ack_number = packet_read.seq_number +s;  // den lambanoume genika acks opote doesnt matter for now
    socket->left_sack = socket->ack_number;
    socket->right_sack = socket->ack_number;
    socket->init_win_size = MICROTCP_WIN_SIZE;
    socket->sin = (struct sockaddr_in *)address;
    printf("received connection sin_port %u\n", htons(socket->sin->sin_port));
    socket->address_len = address_len;
    // socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN * sizeof(uint8_t));

    printf("Telos connect\n");

    printf("%u my sec,%u their seq,%d s",socket->seq_number,packet_read.seq_number+s,s);
    return 0;
  }
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len) {
  /* Your code here */
  uint32_t seq_n = 0; /*M*/
  size_t i = 0;
  int s = sizeof(microtcp_header_t);
  uint8_t rcvbuf[sizeof(microtcp_header_t)];
  microtcp_header_t *header_rcv;
  microtcp_header_t packet_read;
  microtcp_header_t header_snd;
  struct sockaddr_in *sin;
  uint32_t tmp_checksum;
  uint8_t checksum_buf[sizeof(microtcp_header_t)];

  srand(time(NULL));
  printf("1\n");
  /*RECEIVE 1st Packet*/
  header_rcv = (microtcp_header_t *)malloc(sizeof(microtcp_header_t *));
  
  if (recvfrom(socket->sd, rcvbuf, sizeof(microtcp_header_t), 0, address,
               &address_len) == -1) {
    perror("recvfrom failed edw pera\n");
    socket->state = INVALID;
    return -1;
  }
  printf("2\n");
  memcpy(header_rcv, (microtcp_header_t *)rcvbuf, sizeof(microtcp_header_t));

  /*isws xreiastei na diabasoume kai ta alla gia to checksum checking*/
  prepare_read_header(&packet_read, header_rcv);
  tmp_checksum = packet_read.checksum;
  packet_read.checksum = 0;

  // printf("%zu to check sum pou elaba sto diko mou indianes\n", tmp_checksum);
  for (i = 0; i < sizeof(microtcp_header_t); i++) {
    checksum_buf[i] = '\0';
  }
  memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
  packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));

  if (tmp_checksum != packet_read.checksum) {
    perror("Checksum is invalid\n");
    socket->state = INVALID;
    return -1;
  }

  if (packet_read.control != SYN) {
    perror("tried to establish connection without sending SYN\n");
    socket->state = INVALID;
    return -1;
  }

  /*Sending second packet*/
  /* setting up the header to send*/
  seq_n = (rand() % 1024 + 1);
  socket->seq_number = seq_n;
  prepare_checksum_header(&header_snd, socket->seq_number,
                          packet_read.seq_number + s, SYN_ACK,
                          MICROTCP_WIN_SIZE, 0);

  for (i = 0; i < sizeof(microtcp_header_t); i++) {
    checksum_buf[i] = '\0';
  }
  memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
  header_snd.checksum = crc32(checksum_buf, sizeof(checksum_buf));
  prepare_send_header(&header_snd);

  /*setting up the socket*/
  socket->ack_number = packet_read.seq_number + s;
  socket->init_win_size = MICROTCP_WIN_SIZE;

  socket->sin = (struct sockaddr_in *)address;
  socket->address_len = address_len;

  /*send a response because no data inside we dont need buffer,just send
   * header*/
  if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0,
             address, address_len) == -1) {
    socket->state = INVALID;
    perror("failed to send synack packet\n");
    return -1;
  }
  socket->seq_number += s;

  /*Receive third packet*/
  /*we cleanup buffer and the recieve header to re read data*/
  for (i = 0; i < sizeof(microtcp_header_t); i++) {
    rcvbuf[i] = 0;
  }
  memset(rcvbuf, '\0', sizeof(microtcp_header_t));
  memset(header_rcv, '\0', sizeof(microtcp_header_t));

  if (recvfrom(socket->sd, rcvbuf, sizeof(microtcp_header_t), 0, address,
               &address_len) == -1) {
    perror("recvfrom failed in the last step from server\n");
    socket->state = INVALID;
    return -1;
  }
  memcpy(header_rcv, (microtcp_header_t *)rcvbuf, sizeof(microtcp_header_t));

  /*isws xreiastei na diabasoume kai ta alla gia to checksum checking*/
  prepare_read_header(&packet_read, header_rcv);
  tmp_checksum = packet_read.checksum;
  packet_read.checksum = 0;

  // printf("%zu to check sum pou elaba sto diko mou indianes\n", tmp_checksum);
  for (i = 0; i < sizeof(microtcp_header_t); i++) {
    checksum_buf[i] = '\0';
  }
  memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
  packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));

  if (tmp_checksum != packet_read.checksum) {
    perror("Checksum is invalid\n");
    socket->state = INVALID;
    return -1;
  }

  if (packet_read.control != ACK) {
    perror("tried to establish connection without sending SYN\n");
    socket->state = INVALID;
    return -1;
  }
  if (packet_read.ack_number == socket->seq_number && packet_read.seq_number == socket->ack_number) {
    /*setting up the socket a final time*/
    socket->state = ESTABLISHED;
    // socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN * sizeof(uint8_t));
    socket->left_sack = socket->ack_number;
    socket->right_sack = socket->ack_number;
    printf("telos accept\n");
    printf("%u my ack accept and my sec number %u also %d \n",socket->ack_number,socket->seq_number,s);
    return 0;
  } else {
    perror(" seq numbers didnt much with ack numbers");
    socket->state = INVALID;
    return -1;
  }
}

int microtcp_shutdown(microtcp_sock_t *socket, int how) {
  /* Your code here */
  int i = 0;
  int s = sizeof(microtcp_header_t);
  uint8_t rcvbuf[s];
  microtcp_header_t header_rcv;
  microtcp_header_t packet_read;
  microtcp_header_t header_snd;
  uint32_t tmp_checksum;
  uint8_t checksum_buf[s];
  uint8_t fin_checksum_buf[MICROTCP_MSS + s];
  /*Allocate memory to read the packet*/
  // header_rcv = (microtcp_header_t *)malloc(sizeof(microtcp_header_t *));

  printf("SHUTDOWN\n"); 
  //Timeout timer for socket
  struct timeval tv;
  tv.tv_sec = 0;
  tv.tv_usec = 0;

  if(setsockopt(socket->sd , SOL_SOCKET ,SO_RCVTIMEO , &tv, sizeof(struct timeval)) < 0) {
    perror("setsockopt timeout\n");
    socket->state = INVALID;
    return -1; /*mas todinan 0 sthn ekfwnish alla afou kaleite me if (microtcp send ==-1 perror .....)*/
  }
  
  if (socket->state == CLOSING_BY_PEER) {
    /*O D*/
    /*Prepare header to send FIN*/
    prepare_checksum_header(&header_snd, socket->seq_number, socket->ack_number + s, FIN_ACK, socket->curr_win_size,0);
    
    memset(checksum_buf, '\0', s);
    memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
    header_snd.checksum =crc32(checksum_buf, sizeof(checksum_buf));

    prepare_send_header(&header_snd);
    

    /*Send the FIN_ACK packet*/
    if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0,
               (struct sockaddr *)socket->sin, socket->address_len) == -1) {
      socket->state = INVALID;
      perror("failed to send FIN packet\n");
      return -1;
    }
    printf("FIN_ACK sended code %u\n",header_snd.control);
    /*we remember that we answered x+s ,we will check next seq number with ack
     * number of socket(without +s again)*/
    socket->ack_number += s;
  
    prepare_checksum_header(&header_snd, socket->seq_number, socket->ack_number, FIN, socket->curr_win_size,0);

    memset(checksum_buf, '\0', s);
    memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
    header_snd.checksum = crc32(checksum_buf, sizeof(checksum_buf));

    prepare_send_header(&header_snd);

    /*Send the FIN packet*/
    if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0,
               (struct sockaddr *)socket->sin, socket->address_len) == -1) {
      socket->state = INVALID;
      perror("failed to send FIN packet\n");
      return -1;
    }
    socket->seq_number += s;
    if (recvfrom(socket->sd, rcvbuf, s, 0,
                 (struct sockaddr *)socket->sin, &socket->address_len) == -1) {
      perror("Something went wrong while receiving FIN_ACK\n");
      socket->state = INVALID;
      return -1;
    }

    memset(&header_rcv, '\0', sizeof(microtcp_header_t));
    memcpy(&header_rcv, (microtcp_header_t *)rcvbuf, sizeof(microtcp_header_t));

    prepare_read_header(&packet_read, &header_rcv);

    tmp_checksum = packet_read.checksum;
    packet_read.checksum = 0;

    memset(checksum_buf, '\0',s);
    memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
    packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));


    if (tmp_checksum != packet_read.checksum) {
      perror("Checksum is invalid\n");
      socket->state = INVALID;
      return -1;
    }
    if (packet_read.ack_number != (socket->seq_number) ||
        packet_read.seq_number != (socket->ack_number)) {
      perror("expected N+s didnt get it\n");
      socket->state = INVALID;
      return -1;
    }

    if (packet_read.control != FIN_ACK) {
      perror("FIN_ACK didn't received\n");
      socket->state = INVALID;
      return -1;
    } else {
      /*Ola kala -> Close connection*/
      socket->state = CLOSED;
    }
  } /*Telos o D*/
  else {
    /*O S*/
    /*Prepare header to send FIN*/

    prepare_checksum_header(&header_snd, socket->seq_number, socket->ack_number,
    FIN, socket->curr_win_size, 0);

    memset(fin_checksum_buf, '\0', MICROTCP_MSS+s);
    memcpy(fin_checksum_buf, &header_snd, sizeof(microtcp_header_t));
    header_snd.checksum = crc32(fin_checksum_buf, sizeof(fin_checksum_buf));

    prepare_send_header(&header_snd);

    /*Send the FIN packet*/
    if (sendto(socket->sd, (void *)&header_snd, MICROTCP_MSS+s, 0,
               (struct sockaddr *)socket->sin, socket->address_len) == -1) {
      socket->state = INVALID;
      perror("failed to send FIN packet\n");
      return -1;
    }
    printf("FIN sended\n");

    socket->seq_number += s;
    while(1){

      if (recvfrom(socket->sd, rcvbuf, s, 0,
                  (struct sockaddr *)socket->sin, &socket->address_len) == -1) {
        perror("Something went wrong while receiving\n");
        socket->state = INVALID;
        return -1;
      }

      memset(&header_rcv, '\0', sizeof(microtcp_header_t));
      memcpy(&header_rcv, (microtcp_header_t *)rcvbuf, sizeof(microtcp_header_t));
    
      prepare_read_header(&packet_read, &header_rcv);
      printf("code i got %u\n",packet_read.control);

      tmp_checksum = packet_read.checksum;
      packet_read.checksum = 0;

      memset(checksum_buf, '\0', s);
      memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
      packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));
      
      if (packet_read.control != FIN_ACK) {
        perror("FIN_ACK didn't received\n");
        socket->state = INVALID;
        continue;
        // return -1;
      } else {
        socket->state = CLOSING_BY_HOST;
        socket->ack_number = packet_read.seq_number;
        break;
      }
      
      if (tmp_checksum != packet_read.checksum) {
        perror("Checksum is invalid\n");
        socket->state = INVALID;
        return -1;
      }

      if (packet_read.ack_number != socket->seq_number) {
        printf("expected N+s didnt get it phra seq number %u\n",packet_read.ack_number);//htan perror
        socket->state = INVALID;
        return -1;
      }

    } /*while*/

    /*Waiting fot FIN from D*/
    if (recvfrom(socket->sd, rcvbuf, MICROTCP_RECVBUF_LEN, 0,
                 (struct sockaddr *)socket->sin, &socket->address_len) == -1) {
      perror("Something went wrong while receiving FIN\n");
      socket->state = INVALID;
      return -1;
    }

    printf("Got FIN\n");
    memset(&header_rcv, '\0', sizeof(microtcp_header_t));
    memcpy(&header_rcv, (microtcp_header_t *)rcvbuf, sizeof(microtcp_header_t));

    prepare_read_header(&packet_read, &header_rcv);

    tmp_checksum = packet_read.checksum;
    packet_read.checksum = 0;

    memset(checksum_buf, '\0', s);
    memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
    packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));

    if (tmp_checksum != packet_read.checksum) {
      perror("Checksum is invalid\n");
      socket->state = INVALID;
      return -1;
    }

    if (packet_read.control != FIN) {
      perror("FIN didn't received\n");
      socket->state = INVALID;
      return -1;
    } else {
      socket->ack_number = packet_read.seq_number + s;
    }

    prepare_checksum_header(&header_snd, socket->seq_number, socket->ack_number,
    FIN_ACK, socket->curr_win_size, 0);

    memset(checksum_buf, '\0', s);
    memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
    header_snd.checksum = crc32(checksum_buf, sizeof(checksum_buf));

    prepare_send_header(&header_snd);

    /*Send the FIN_ACK packet*/
    if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0,
               (struct sockaddr *)socket->sin, socket->address_len) == -1) {
      socket->state = INVALID;
      perror("failed to send FIN_ACK packet\n");
      return -1;
    } else {
      printf("FIN_ACK sended\n");
      socket->state = CLOSED;
    }

  } /*To megalo else*/

  print_stats(socket);

  return 0;
}

ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer,
                      size_t length, int flags) {
  /* Your code here */
  size_t s = sizeof(microtcp_header_t);
  uint8_t send_buffer[MICROTCP_MSS+s];
  uint8_t header_rcvbuf[s];
  microtcp_header_t header_send;
  microtcp_header_t packet_read;
  microtcp_header_t header_rcv;
  uint32_t bytes_to_send;
  size_t message_len;
  size_t packets_num; 
  size_t data_sent = 0;
  size_t remaining = 0;
  size_t actual_data_sent = 0;
  size_t tmp_bytes = 0;
  size_t bytes_rcv;
  uint64_t packets_sent;
  uint32_t tmpChecksum,tmp_calc_checksum;
  uint8_t checksum_buf[s];
  size_t i = 0;
  uint32_t last_left = 0;
  uint32_t init_seq = 0;
  uint32_t last_ack_rcvd = 0;
  uint32_t target_ack = 0;
  uint32_t re_target_ack = 0;
  int dup_cnt = 0;
  int slow_start = 0;
  int retransmit = 0; /*0 for no retransmit, 1 for triple duplicate*/
  struct timespec tmp_time;
  double elapsed;

  last_ack_rcvd = socket->seq_number;
  init_seq = socket->seq_number;
  last_left = last_ack_rcvd;

  remaining = length;
  while( data_sent <= length ){
    bytes_to_send = MIN_3(socket->curr_win_size,socket->cwnd,remaining);

    packets_num = bytes_to_send / MICROTCP_MSS;

    if(socket->poll_flag == 1 ){
      printf("polling\n");
      /*Wait random time between 0 and MICROTCP_ACK_TIMEOUT_US*/
      srand(time(NULL));
      wait( rand() % MICROTCP_ACK_TIMEOUT_US );
    }

    for (i = 0; i < packets_num; i++) {

      message_len = MICROTCP_MSS; 
      
      prepare_checksum_header(&header_send, socket->seq_number,socket->ack_number, ACK, socket->curr_win_size,
                              message_len);

      memset(send_buffer, '\0', MICROTCP_MSS + s);
      memcpy(send_buffer, &header_send, sizeof(header_send));
      memcpy(send_buffer + sizeof(header_send), buffer + data_sent, message_len);

      /*Checksums*/
      tmpChecksum = crc32(send_buffer, sizeof(send_buffer));
      header_send.checksum = tmpChecksum;

      prepare_send_header(&header_send);

      memset(send_buffer, '\0', MICROTCP_MSS + s);
      memcpy(send_buffer, &header_send, sizeof(header_send));
      memcpy(send_buffer + sizeof(header_send), buffer + data_sent, message_len);

      // printf("IP: %zu \n", ntohl(socket->sin->sin_addr.s_addr));
      // printf("Port: %u\n", ntohs(socket->sin->sin_port));
      printf("%u 8a steilw seq number mesa sth for\n",socket->seq_number);

      if ((tmp_bytes = sendto(socket->sd, (void *)send_buffer, MICROTCP_MSS+s, 0, (struct sockaddr *)socket->sin,
                            socket->address_len)) == -1) {
        perror("failed to send the packet\n");
        return -1;
      }

      clock_gettime (CLOCK_MONOTONIC_RAW, &tmp_time);
      if( socket->last_sent.tv_nsec == 0){
        /*First packet*/
        socket->last_sent.tv_sec = tmp_time.tv_sec;
        socket->last_sent.tv_nsec = tmp_time.tv_nsec;
      }else{
        elapsed = tmp_time.tv_sec - socket->last_sent.tv_sec + (tmp_time.tv_nsec - socket->last_sent.tv_nsec) * 1e-9;
        if( socket->tx_min_inter == 0 || elapsed < socket->tx_min_inter ){
          socket->tx_min_inter = elapsed;
        }
        if( socket->tx_max_inter == 0 || elapsed > socket->tx_max_inter ){
          socket->tx_max_inter = elapsed;
        }
      }

     // printf("Sending : %s\n", send_buffer+sizeof(header_send));

      socket->seq_number += message_len;
      /*At the moment we suppose everything */
      data_sent += message_len;
      actual_data_sent += tmp_bytes - sizeof(microtcp_header_t);   
    }

    if ( (bytes_to_send % MICROTCP_MSS) > 0 || socket->poll_flag == 1 ){
      /*perisepsan kapoia bytes < apo MSS bytes*/
      packets_num++;
      message_len = bytes_to_send % MICROTCP_MSS;

      prepare_checksum_header(&header_send, socket->seq_number,socket->ack_number, ACK, socket->curr_win_size,
                              message_len);
  
      memset(send_buffer, '\0', MICROTCP_MSS+s);
      memcpy(send_buffer, &header_send, sizeof(header_send));
      memcpy(send_buffer + sizeof(header_send), buffer + data_sent, message_len);
      
      /*Checksums*/
      tmpChecksum = crc32(send_buffer, message_len + s);
      header_send.checksum = tmpChecksum;

      prepare_send_header(&header_send);
    
      memset(send_buffer, '\0', MICROTCP_MSS+s);
      memcpy(send_buffer, &header_send, sizeof(header_send));
      memcpy(send_buffer + sizeof(header_send), buffer + data_sent, message_len);
      printf("%u 8a steilw seq number mesa sth for\n",socket->seq_number);
      if ((tmp_bytes = sendto(socket->sd, (void *)send_buffer, message_len + s, 0, (struct sockaddr *)socket->sin,
                            socket->address_len)) == -1) {
        perror("failed to send the packet\n");
        return -1;
      }

      clock_gettime (CLOCK_MONOTONIC_RAW, &tmp_time);
      if( socket->last_sent.tv_nsec == 0){
        /*First packet*/
        socket->last_sent.tv_sec = tmp_time.tv_sec;
        socket->last_sent.tv_nsec = tmp_time.tv_nsec;
      }else{
        elapsed = tmp_time.tv_sec - socket->last_sent.tv_sec + (tmp_time.tv_nsec - socket->last_sent.tv_nsec) * 1e-9;
        if( socket->tx_min_inter == 0 || elapsed < socket->tx_min_inter ){
          socket->tx_min_inter = elapsed;
        }
        if( socket->tx_max_inter == 0 || elapsed > socket->tx_max_inter ){
          socket->tx_max_inter = elapsed;
        }
      }

     // printf("Sending : %s\n", send_buffer+sizeof(header_send));
      socket->seq_number += message_len;
      /*At the moment we suppose everything */
      data_sent += message_len;
      actual_data_sent += tmp_bytes - sizeof(microtcp_header_t);
      
    }

    target_ack = socket->seq_number;

    //Timeout timer for socket
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = MICROTCP_ACK_TIMEOUT_US;

    if(setsockopt(socket->sd , SOL_SOCKET ,SO_RCVTIMEO , &tv, sizeof(struct timeval)) < 0) {
      perror("setsockopt timeout\n");
      socket->state = INVALID;
      return -1; /*mas todinan 0 sthn ekfwnish alla afou kaleite me if (microtcp send ==-1 perror .....)*/
    }
    
    /*Kanoyme receive ta acks gia ta paketa poy steilame*/
    while(1){
      /*Perimeno to ack moy*/
      if (recvfrom(socket->sd, header_rcvbuf,s,0,(struct sockaddr *)socket->sin, &socket->address_len) == -1) {
        /*Timeout*/
        perror("Timeout\n");
        slow_start=1;
        socket->ssthresh = socket->cwnd/2;
        socket->cwnd = MIN_2(MICROTCP_MSS, socket->ssthresh);
        retransmit = 1; /*Timeout flag value*/
        socket->bytes_lost += target_ack - last_ack_rcvd;
        if( last_left > last_ack_rcvd){
          re_target_ack = retransmit_send(socket, buffer+(last_ack_rcvd - init_seq), last_ack_rcvd, last_left - last_ack_rcvd);                        
        }else{
          re_target_ack = retransmit_send(socket, buffer+(last_ack_rcvd - init_seq), last_ack_rcvd, target_ack - last_ack_rcvd);                        
        }
        continue;
      } 
    
      /*Den fagame timeout*/
      memset(&header_rcv, '\0', sizeof(microtcp_header_t));
      memcpy(&header_rcv, (microtcp_header_t *)header_rcvbuf, sizeof(microtcp_header_t));

      prepare_read_header(&packet_read, &header_rcv);
      tmpChecksum = packet_read.checksum;
      packet_read.checksum = 0;

      memset(checksum_buf, '\0', s);
      memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
      tmp_calc_checksum = crc32(checksum_buf, sizeof(checksum_buf));

      if (tmp_calc_checksum != tmpChecksum) {
        perror("Checksum in ack (send) error\n");
        printf("%u received, %u calc \n", tmpChecksum, tmp_calc_checksum);
        /*Ignore the packet, may induce timeout*/
        continue;
      }

      if( packet_read.control != ACK){
        perror("I didn't received an ACK packet(send)\n");
        /*Ignore the packet ??*/
        continue;    
      }

        socket->curr_win_size = packet_read.window;
        printf("%u\n", socket->curr_win_size);
        if(socket->curr_win_size == 0){
          printf("gonna poll\n");
          socket->poll_flag = 1;
        }else{
          socket->poll_flag = 0;
        }

      /*Slow start flag??*/
      if(slow_start && last_ack_rcvd < packet_read.ack_number ){
        socket->cwnd = socket->cwnd + MICROTCP_MSS;
      }

      /*Its an ack*/
      if(packet_read.ack_number == target_ack){
        /*ir8an osa perimena*/
        last_ack_rcvd = packet_read.ack_number;
        printf("Got ack for ack num %u, RTT\n", packet_read.ack_number );
        if( !slow_start ){
          /*Congestion avoidance*/
          socket->cwnd = socket->cwnd + MICROTCP_MSS;
        }

        dup_cnt = 0;
        retransmit = 0;
        break;
      }


      if (retransmit && last_ack_rcvd == packet_read.ack_number ){
        continue;
      }

      /*Check for duplicate ack */
      if( last_ack_rcvd == packet_read.ack_number ){
        last_left = packet_read.left_sack;
        dup_cnt++;
        /*Check if its the 3rd dplicate*/
        if(dup_cnt == 3 ){
          dup_cnt = 0;
          if(!(packet_read.ack_number == packet_read.left_sack && packet_read.ack_number==packet_read.right_sack)){
            retransmit = 1; /*Retransmit flag value for 3ple dup*/
            /*triple dup*/
            socket->bytes_lost += packet_read.left_sack - packet_read.ack_number;
            socket->ssthresh = socket->cwnd/2;
            socket->cwnd = socket->cwnd/2 + MICROTCP_MSS; 
            socket->curr_win_size = packet_read.window;
            re_target_ack = retransmit_send(socket, buffer+(last_ack_rcvd - init_seq), last_ack_rcvd, packet_read.left_sack - packet_read.ack_number);          
          }
        }
      }

      last_ack_rcvd = packet_read.ack_number;
      
      if( retransmit == 1 ){
        /*Retransmitting 3ple dup*/
        if( packet_read.ack_number == re_target_ack){
          if( !slow_start ){
            /*Congestion avoidance*/
            socket->cwnd = socket->cwnd + MICROTCP_MSS;
          }
          socket->curr_win_size = packet_read.window;
          if( packet_read.left_sack > packet_read.ack_number){
            re_target_ack = retransmit_send(socket, buffer+(last_ack_rcvd - init_seq), last_ack_rcvd, packet_read.left_sack - packet_read.ack_number);                        
          }else{
            re_target_ack = retransmit_send(socket, buffer+(last_ack_rcvd - init_seq), last_ack_rcvd, target_ack - packet_read.ack_number);                        
          }
        }

      }
      
      if( socket->cwnd <= socket->ssthresh ){
        /*Slow start*/
        /*Gia ka8e paketo stelnoyme allo ena*/
        slow_start = 1;
      } else{
        slow_start = 0;
        /*Congestion avoidance*/
        /*Afksanoyme to window kata 1*/
      }
    
    }/*while rcv acks*/
    
    if( socket->cwnd <= socket->ssthresh ){
      /*Slow start*/
      /*Gia ka8e paketo stelnoyme allo ena*/
      slow_start = 1;
    } else{
      slow_start = 0;
      /*Congestion avoidance*/
      /*Afksanoyme to window kata 1*/
    }

    remaining -= bytes_to_send;
    data_sent += bytes_to_send;
    socket->packets_send += packets_num;

  }/*ekso while*/
  socket->bytes_send = last_ack_rcvd - init_seq;  
  socket->tx_mean_inter = (socket->tx_mean_inter + elapsed) / socket->packets_send;

  return socket->bytes_send;
}

ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length,
                      int flags) {
  /* Your code here */
  int running = 1;
  size_t remaining =0;
  int send_dup = 0;
  int tmpindex=0;
  int flashed_fin=0;
  size_t i = 0;
  int s = sizeof(microtcp_header_t);
  uint8_t rcvbuf[MICROTCP_MSS+s];
  uint8_t tmpbuf[MICROTCP_RECVBUF_LEN];/*ekei mpainoun paketa meta apo tripa*/
  uint8_t data[MICROTCP_MSS];
  size_t bytes_transfered = 0;
  size_t bytes_on_buffer = 0;
  size_t actual_bytes_rcv = 0;
  size_t total_bytes_lost = 0;
  microtcp_header_t header_rcv;
  microtcp_header_t packet_read;
  microtcp_header_t header_snd;
  uint32_t tmp_checksum;
  uint32_t tmp_calc_checksum;
  uint8_t checksum_buf[MICROTCP_MSS+s];
  struct timespec tmp_time;
  double elapsed;


  memset(&tmpbuf,'\0',MICROTCP_RECVBUF_LEN);
  remaining = length;

  if(socket->state == CLOSING_BY_PEER){
    printf("emeinan %d\n", socket->index);
    /*ir8e FIN alla emeinan data ston recvbuffer*/
    if( length <= socket->index){
      memcpy(buffer, socket->recvbuf, length);
      for(i = 0; i< socket->index - length; i++){
        socket->recvbuf[i] = socket->recvbuf[length+i];
      }
      socket->index -= length;
      memset(socket->recvbuf+socket->index,'\0',MICROTCP_RECVBUF_LEN - socket->index);
    }
    if( length > socket->index && socket->index !=0){
      memcpy(buffer, socket->recvbuf, socket->index);
      memset(socket->recvbuf,'\0',MICROTCP_RECVBUF_LEN);
      socket->index = 0;
      return -1;
    }    
    if( socket->index == 0) {
      return -1;
    }else{
      return length;
    }
  }

  while(running){

    /*Waiting for FIN from D*/
    if ((bytes_transfered = recvfrom(socket->sd, rcvbuf, MICROTCP_MSS+s,0,
                                    (struct sockaddr *)socket->sin,
                                    &socket->address_len)) == -1) {
      perror("recv error\n");
      socket->state = INVALID;
      return 0;
    }
    
    clock_gettime (CLOCK_MONOTONIC_RAW, &tmp_time);
    if( socket->last_rcvd.tv_nsec == 0){
      /*First packet*/
      socket->last_rcvd.tv_sec = tmp_time.tv_sec;
      socket->last_rcvd.tv_nsec = tmp_time.tv_nsec;
    }else{
      elapsed = tmp_time.tv_sec - socket->last_rcvd.tv_sec + (tmp_time.tv_nsec - socket->last_rcvd.tv_nsec) * 1e-9;
      if( socket->rx_min_inter == 0 || elapsed < socket->rx_min_inter ){
        socket->rx_min_inter = elapsed;
      }
      if( socket->rx_max_inter == 0 || elapsed > socket->rx_max_inter ){
        socket->rx_max_inter = elapsed;
      }
      socket->rx_mean_inter = (socket->rx_mean_inter + elapsed) / socket->packets_received;
    }
    
    memset(&header_rcv, '\0', sizeof(microtcp_header_t));
    memcpy(&header_rcv, (microtcp_header_t *)rcvbuf, sizeof(microtcp_header_t));

    prepare_read_header(&packet_read, &header_rcv);

    tmp_checksum = packet_read.checksum;
    packet_read.checksum = 0;

    memset(checksum_buf, '\0', MICROTCP_MSS + s);
    memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
    memcpy(checksum_buf + sizeof(microtcp_header_t),
          rcvbuf + sizeof(microtcp_header_t), packet_read.data_len);
    tmp_calc_checksum = crc32(checksum_buf, bytes_transfered);

    if (tmp_calc_checksum != tmp_checksum) {
      perror("noise may have altered the bytes in recv\n");
      if(socket->curr_win_size > MICROTCP_MSS){
        total_bytes_lost += MICROTCP_MSS;
      }
      else{
        total_bytes_lost +=socket->curr_win_size;
      }
      /*apantaw me dup apeu8eias,kati phge straba sto checksum*/
      memset(&header_snd, '\0', sizeof(microtcp_header_t));
      prepare_checksum_header(&header_snd, socket->seq_number, socket->ack_number, ACK, socket->curr_win_size,0);
      header_snd.left_sack = socket->left_sack;
      header_snd.right_sack = socket->right_sack;

      memset(checksum_buf, '\0', s);
      memcpy(checksum_buf, &header_snd, sizeof(header_snd));
      header_snd.checksum = crc32(checksum_buf, s);   

      // printf("sended code %u\n",header_snd.control);
      prepare_send_header(&header_snd);

      if ( sendto(socket->sd, (void *)&header_snd ,s, 0, (struct sockaddr *)socket->sin,
                          socket->address_len) == -1) {
        perror("failed to send the packet\n");
      }
      continue;
    } /*cheksumcheck*/

    printf("data len %u\n", packet_read.data_len);
    /*deal with packet as if it was normal*/
    if (packet_read.control == ACK) {
      socket->packets_received++;
      if( socket->ack_number == packet_read.seq_number ){
        /*Ir8e paketo poy perimena eite den exo kamia trypa eite tis gemizo */
        if( socket->left_sack == packet_read.seq_number ){
            /*Ola me sosti seira*/
            socket->ack_number = packet_read.seq_number + packet_read.data_len;
            socket->left_sack = socket->ack_number;
            socket->right_sack = socket->ack_number;
            memcpy(socket->recvbuf+socket->index, checksum_buf + sizeof(microtcp_header_t),packet_read.data_len);
            printf("Message in socket: %s\n", socket->recvbuf + socket->index); 
            printf("Previous left space %u \n", MICROTCP_RECVBUF_LEN - socket->index);
            socket->index += packet_read.data_len;
            printf("Current left space %u \n", MICROTCP_RECVBUF_LEN - socket->index);
            /*Change window size*/
            socket->curr_win_size -= packet_read.data_len;
            actual_bytes_rcv += packet_read.data_len;
            if( (int)socket->curr_win_size <= 0){
              printf("Rcvbuf filled\n");
              socket->curr_win_size = 0;
            } 
        }else if(packet_read.seq_number + packet_read.data_len  < socket->left_sack){
            /*Siga siga gemizei i tripa*/
            socket->ack_number = packet_read.seq_number + packet_read.data_len;
            memcpy(socket->recvbuf+socket->index, checksum_buf + sizeof(microtcp_header_t),packet_read.data_len);
            socket->index += packet_read.data_len;
            socket->curr_win_size -= packet_read.data_len;
            actual_bytes_rcv += packet_read.data_len;
        }else if( packet_read.seq_number + packet_read.data_len  == socket->left_sack){
            /*Molis gemise i tripa*/
            socket->ack_number = socket->right_sack;
            socket->left_sack = socket->right_sack;
            memcpy(socket->recvbuf+socket->index, checksum_buf + sizeof(microtcp_header_t),packet_read.data_len);
            actual_bytes_rcv += packet_read.data_len;
            socket->index += packet_read.data_len;
            socket->curr_win_size -= packet_read.data_len;
            memcpy(socket->recvbuf+socket->index,tmpbuf,tmpindex);
            socket->index+=tmpindex;
            actual_bytes_rcv += tmpindex;
            tmpindex=0;
            memset(&tmpbuf,'\0',MICROTCP_RECVBUF_LEN);
        }
      }else if(packet_read.seq_number > socket->ack_number) {
        /*Ir8e paketo me la8os seq, eite yparxei tripa eite gemise tin tripa me la8os seira*/
        if( socket->right_sack < packet_read.seq_number){
          if (socket->left_sack == socket->ack_number){
            /*Exo tripa apo piso*/
            socket->left_sack = packet_read.seq_number;
            total_bytes_lost += socket->left_sack - socket->ack_number;
          }
          memcpy(tmpbuf+tmpindex, checksum_buf + sizeof(microtcp_header_t),packet_read.data_len);
          tmpindex += packet_read.data_len;
          socket->right_sack = packet_read.seq_number+packet_read.data_len;
          socket->curr_win_size -= packet_read.data_len;
        }
      } else if( packet_read.seq_number < socket->ack_number ||
                          (socket->left_sack <= packet_read.seq_number && packet_read.seq_number <= socket->right_sack) ){
        /*ignore*/
        printf("%u my ack ,%u their seq\n",socket->ack_number,packet_read.seq_number);
        printf("ignore we have it already\n");
      }

      /*edw stelnw to ack*/
      memset(&header_snd, '\0', sizeof(microtcp_header_t));
      prepare_checksum_header(&header_snd, socket->seq_number, socket->ack_number, ACK, socket->curr_win_size,0);
      header_snd.left_sack = socket->left_sack;
      header_snd.right_sack = socket->right_sack;

      memset(checksum_buf, '\0', s);
      memcpy(checksum_buf, &header_snd, sizeof(header_snd));
      header_snd.checksum = crc32(checksum_buf, s);   
      printf("win size %hu\n", header_snd.window);
      // printf("sended code %u\n",header_snd.control);
      prepare_send_header(&header_snd);
      
      if ( sendto(socket->sd, (void *)&header_snd ,s, 0, (struct sockaddr *)socket->sin,
                          socket->address_len) == -1) {
        perror("failed to send the packet\n");
      }
           
      if(remaining<=socket->index){ /*estw zhthse 20k se kapoia fash emine na gurisw 700 kai to index htan sto 800*/
        running=0;                 /*idia logikh kai an eixe zhthsei 512 alla egw me to kalhmera phra 1400*/
        memcpy(buffer, socket->recvbuf, remaining);
        socket->curr_win_size+=remaining;
        for(i = 0; i< socket->index - remaining;i++){
          socket->recvbuf[i] = socket->recvbuf[remaining+i];
        }
        socket->index -=remaining;
        memset(socket->recvbuf+socket->index,'\0',MICROTCP_RECVBUF_LEN - socket->index);
        remaining = 0;
      }else if(remaining > socket->index && socket->index == MICROTCP_RECVBUF_LEN - 1){
        remaining -= MICROTCP_RECVBUF_LEN;
        socket->curr_win_size+=MICROTCP_RECVBUF_LEN;
        memcpy(buffer,socket->recvbuf,MICROTCP_RECVBUF_LEN);
        memset(socket->recvbuf,'\0',MICROTCP_RECVBUF_LEN);
        socket->index =0;
      }/*prwta kanw to flashidi an xreiastei gia nar8ei to fresko curr_win_size),alliws balto katw sto allo comment*/

      /*ta tou xronou to do*/
    } else if (packet_read.control == FIN) {
      printf("got FIN\n");
      socket->state = CLOSING_BY_PEER;
      socket->packets_received++;
      socket->ack_number = packet_read.seq_number;
      socket->bytes_received += actual_bytes_rcv;
      socket->bytes_lost = total_bytes_lost;

      if( length <= socket->index){
        memcpy(buffer, socket->recvbuf, length);
        for(i = 0; i< socket->index - length; i++){
         socket->recvbuf[i] = socket->recvbuf[length+i];
        }
        socket->index -= length;
        memset(socket->recvbuf+socket->index,'\0',MICROTCP_RECVBUF_LEN - socket->index);
      }
      if( length > socket->index && socket->index != 0){
        memcpy(buffer, socket->recvbuf, socket->index);
        memset(socket->recvbuf,'\0',MICROTCP_RECVBUF_LEN);
        flashed_fin = socket->index;
        socket->index = 0;
        return flashed_fin;
      }    
      if( socket->index == 0) {
        return -1;
      }else{
        return length;
      }
    }

  }/*while*/

  socket->bytes_received += actual_bytes_rcv;
  socket->bytes_lost = total_bytes_lost;
  return length;
}
