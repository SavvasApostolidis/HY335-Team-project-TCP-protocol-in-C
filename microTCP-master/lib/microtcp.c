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

/*util_functions*/
// void set_socket(microtcp_state_t state_s,size_t curr_win_size_s)
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
  // printf("in prepare network order %u\n", header_rcv->checksum);
  // printf("in prepare converted to host %u\n", ntohl(header_rcv->checksum));
  packet_read->checksum = ntohl(header_rcv->checksum);
  packet_read->left_sack = ntohl(header_rcv->left_sack);
  packet_read->right_sack = ntohl(header_rcv->right_sack);
}

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
  new_socket.empty_start=0;
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
  if ((snt=sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0,
             address, address_len)) == -1) {
    perror("Send SYN packet failed\n");
    socket->state = INVALID;
    return -1;
  }

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

  if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0,
             address, address_len) == -1) {
    perror("Send SYN packet failed\n");
    socket->state = INVALID;
    return -1;
  } else {
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

  /*RECEIVE 1st Packet*/
  header_rcv = (microtcp_header_t *)malloc(sizeof(microtcp_header_t *));

  if (recvfrom(socket->sd, rcvbuf, sizeof(microtcp_header_t), 0, address,
               &address_len) == -1) {
    perror("recvfrom failed\n");
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
  socket->ack_number = ntohl(packet_read.seq_number + s);
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
  if (packet_read.ack_number == (socket->seq_number) || packet_read.seq_number == socket->ack_number) {
    /*setting up the socket a final time*/
    socket->state = ESTABLISHED;
    // socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN * sizeof(uint8_t));
    socket->left_sack = socket->ack_number;
    socket->right_sack = socket->ack_number;
    printf("telos accept\n");

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
  if (socket->state == CLOSING_BY_PEER) {
    /*O D*/
    /*Prepare header to send FIN*/
    // prepare_send_header(&header_snd, socket->seq_number, socket->ack_number +
    // s, FIN_ACK, socket->curr_win_size, 0);    

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

    /* waste some time maybe process last data in buffer remaining,free your
     * resources i guess?*/
    //
    //
    //
    // prepare_send_header(&header_snd, socket->seq_number, socket->ack_number,
    // FIN, socket->curr_win_size, 0);
  
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
      /*TODO free if recvbuf used*/
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
    if (recvfrom(socket->sd, rcvbuf, s, 0,
                 (struct sockaddr *)socket->sin, &socket->address_len) == -1) {
      perror("Something went wrong while receiving FIN_ACK\n");
      socket->state = INVALID;
      return -1;
    }
    printf("theoretically got FIN_ACK\n");

    memset(&header_rcv, '\0', sizeof(microtcp_header_t));
    memcpy(&header_rcv, (microtcp_header_t *)rcvbuf, sizeof(microtcp_header_t));
   
    prepare_read_header(&packet_read, &header_rcv);
    printf("code i got %u\n",packet_read.control);

    printf("1\n");
    tmp_checksum = packet_read.checksum;
    packet_read.checksum = 0;

    memset(checksum_buf, '\0', s);
    memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
    packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));
    printf("2\n");
    printf("%u to diko mou prwto check pou phra \n", packet_read.checksum);
    if (tmp_checksum != packet_read.checksum) {
      perror("Checksum is invalid\n");
      socket->state = INVALID;
      return -1;
    }
    printf("3\n");
    if (packet_read.ack_number != socket->seq_number) {
      perror("expected N+s didnt get it\n");
      socket->state = INVALID;
      return -1;
    }
    printf("4\n");

    if (packet_read.control != FIN_ACK) {
      perror("FIN_ACK didn't received\n");
      socket->state = INVALID;
      return -1;
    } else {
      socket->state = CLOSING_BY_HOST;
      socket->ack_number = packet_read.seq_number;
    }
    printf("5\n");
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
    printf("6\n");
    tmp_checksum = packet_read.checksum;
    packet_read.checksum = 0;

    memset(checksum_buf, '\0', s);
    memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
    packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));
    printf("7\n");

    if (tmp_checksum != packet_read.checksum) {
      perror("Checksum is invalid\n");
      socket->state = INVALID;
      return -1;
    }
    printf("8\n");
    if (packet_read.control != FIN) {
      perror("FIN didn't received\n");
      socket->state = INVALID;
      return -1;
    } else {
      socket->ack_number = packet_read.seq_number + s;
    }
    printf("9\n");
    prepare_checksum_header(&header_snd, socket->seq_number, socket->ack_number,
    FIN_ACK, socket->curr_win_size, 0);
    printf("10\n");
    memset(checksum_buf, '\0', s);
    memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
    header_snd.checksum = crc32(checksum_buf, sizeof(checksum_buf));

    prepare_send_header(&header_snd);
    printf("11\n");
    /*Send the FIN_ACK packet*/
    if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0,
               (struct sockaddr *)socket->sin, socket->address_len) == -1) {
      socket->state = INVALID;
      perror("failed to send FIN_ACK packet\n");
      return -1;
    } else {
      printf("FIN_ACK sended\n");
      socket->state = CLOSED;
      /*TODO free recvbuf*/
    }

  } /*To megalo else*/

  printf("packets recieved  : %d\n",socket->packets_received);
  printf("packets sent : %d\n",socket->packets_send);
  printf("packets lost : %d\n",socket->packets_lost);



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
  uint32_t data_to_send;
  size_t message_len;
  size_t packets_num; 
  size_t bytes_sent = 0;
  size_t actual_bytes_sent = 0;
  size_t tmp_bytes = 0;
  size_t bytes_rcv;
  uint64_t packets_sent;
  uint32_t tmpChecksum,tmp_calc_checksum;
  uint8_t checksum_buf[s];
  size_t i = 0;
 
  packets_num = length / MICROTCP_MSS; //- sizeof(microtcp_header_t));

  message_len = MICROTCP_MSS; //- sizeof(microtcp_header_t);

  for (i = 0; i < packets_num; i++) {
    prepare_checksum_header(&header_send, socket->seq_number,
                            socket->ack_number, ACK, socket->curr_win_size,
                            message_len);

    memset(send_buffer, '\0', MICROTCP_MSS + s);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + bytes_sent, message_len);

    /*Checksums*/
    tmpChecksum = crc32(send_buffer, sizeof(send_buffer));
    header_send.checksum = tmpChecksum;

    prepare_send_header(&header_send);

    memset(send_buffer, '\0', MICROTCP_MSS + s);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + bytes_sent, message_len);

    // printf("IP: %zu \n", ntohl(socket->sin->sin_addr.s_addr));
    // printf("Port: %u\n", ntohs(socket->sin->sin_port));

    if ((tmp_bytes = sendto(socket->sd, (void *)send_buffer /*send_buffer*/,
                           MICROTCP_MSS+s, 0, (struct sockaddr *)socket->sin,
                           socket->address_len)) == -1) {
      perror("failed to send the packet\n");
      return actual_bytes_sent;
    }
    printf("Sending : %s\n", send_buffer+sizeof(header_send));

    socket->seq_number += message_len;
    // socket->seq_number += 1;
    /*At the moment we suppose everything */
    bytes_sent += message_len;
    actual_bytes_sent += tmp_bytes - sizeof(microtcp_header_t);
    
    /*Perimeno to ack moy*/
    if (recvfrom(socket->sd, header_rcvbuf,s,0,(struct sockaddr *)socket->sin,
                                    &socket->address_len) == -1) {
      perror("Something went wrong while receiving a packet\n");
    } 

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
    }

    if( packet_read.control != ACK){
      perror("I didn't received an ACK packet(send)\n");
    } 
    // printf("i got code %hu\n", packet_read.control);
    
  }
  if (length % MICROTCP_MSS){
    packets_num++;
    message_len = length % MICROTCP_MSS;

    prepare_checksum_header(&header_send, socket->seq_number,
                            socket->ack_number, ACK, socket->curr_win_size,
                            message_len);
    
    memset(send_buffer, '\0', MICROTCP_MSS+s);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + bytes_sent, message_len);
    
    /*Checksums*/
    tmpChecksum = crc32(send_buffer, message_len + s);
    header_send.checksum = tmpChecksum;

    prepare_send_header(&header_send);
  
    memset(send_buffer, '\0', MICROTCP_MSS+s);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + bytes_sent, message_len);

    if ((tmp_bytes = sendto(socket->sd, (void *)send_buffer /*send_buffer*/,
                          message_len + s, 0, (struct sockaddr *)socket->sin,
                          socket->address_len)) == -1) {
      perror("failed to send the packet\n");
      return actual_bytes_sent;
    }
    
    printf("Sending : %s\n", send_buffer+sizeof(header_send));
    socket->seq_number += message_len;
    /*At the moment we suppose everything */
    bytes_sent += message_len;
    actual_bytes_sent += tmp_bytes - sizeof(microtcp_header_t);
    
    /*Perimeno to ack moy*/
    if (recvfrom(socket->sd, header_rcvbuf,s,0,(struct sockaddr *)socket->sin,
                                    &socket->address_len) == -1) {
      perror("Something went wrong while receiving a packet\n");
    } 
    
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
    }

    if( packet_read.control != ACK){
      perror("I didn't received an ACK packet(send)\n");
    } 
    // printf("i got code %hu\n", packet_read.control);

  }
  //   // printf("seq %u\n", header_send.seq_number);
  //   // printf("ack %u\n", header_send.ack_number);
  //   // printf("control %hu\n", header_send.control);
  //   // printf("win %hu\n", header_send.window);
  //   // printf("datalen %u\n", header_send.data_len);
  //   // printf("checksum %hu\n", header_send.checksum);
  //   // printf("-----------\n");
  //   // printf("seq %u\n", header_send.seq_number);
  //   // printf("ack %u\n", header_send.ack_number);
  //   // printf("control %hu\n", header_send.control);
  //   // printf("win %hu\n", header_send.window);
  //   // printf("datalen %u\n", header_send.data_len);
  //   // printf("checksum %hu\n", header_send.checksum);

  socket->bytes_send = actual_bytes_sent;
  socket->bytes_lost = bytes_sent - actual_bytes_sent;
  socket->packets_send += packets_num;

  return socket->bytes_send;
}

ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length,
                      int flags) {
  /* Your code here */
  int running = 1;
  size_t remaining =0;
  int send_dup = 0;
  int tmpindex=0;
  size_t i = 0;
  int s = sizeof(microtcp_header_t);
  uint8_t rcvbuf[MICROTCP_MSS+s];
  uint8_t tmpbuf[MICROTCP_RECVBUF_LEN];/*ekei mpainoun paketa meta apo tripa*/
  uint8_t data[MICROTCP_MSS];
  // size_t  bytes_prommised=0;
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

  memset(&tmpbuf,'\0',MICROTCP_RECVBUF_LEN);
  remaining = length;
  
    while(running){

      /*Waiting for FIN from D*/
      if ((bytes_transfered = recvfrom(socket->sd, rcvbuf, MICROTCP_MSS+s,0,
                                      (struct sockaddr *)socket->sin,
                                      &socket->address_len)) == -1) {
        perror("Something went wrong while receiving a packet\n");
        socket->state = INVALID;
        return 0;
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
        printf("bytes transferred %u \n", bytes_transfered);
        printf("%u received, %u calc \n", tmp_checksum, tmp_calc_checksum);
        /*todo*/
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

      // if (packet_read.data_len > bytes_transfered - sizeof(microtcp_header_t)) {
      //   perror("some bytes of data where not transfered\n");
      //   /*todo*/
      //   // actual_bytes_rcv += bytes_transfered - sizeof(microtcp_header_t);
      //   total_bytes_lost += packet_read.data_len - (bytes_transfered - sizeof(microtcp_header_t));
      //   send_dup = 1;
      // }
  
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
              // memset(socket->recvbuf, '\0', packet_read.data_len);
              memcpy(socket->recvbuf+socket->index, checksum_buf + sizeof(microtcp_header_t),packet_read.data_len);
              printf("Message: %s\n", socket->recvbuf + socket->index); 
              // memcpy(buffer, socket->recvbuf, packet_read.data_len);
              printf("Old start %u \n",socket->index);
              socket->index += packet_read.data_len;
              printf("new start %u \n",socket->index);
              /*Change window size*/
              printf("Old win %u \n",socket->curr_win_size);
              socket->curr_win_size -= packet_read.data_len;//socket->init_win_size - socket->index;
              actual_bytes_rcv += packet_read.data_len;
              if( (int)socket->curr_win_size <= 0){
                printf("Rcvbuf filled\n");
                socket->curr_win_size = 0;
              } 
              printf("New win %u \n",socket->curr_win_size);  
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
        }
        /*edw stelnw to ack*/
        
        if(remaining<=socket->index){ /*estw zhthse 20k se kapoia fash emine na gurisw 700 kai to index htan sto 800*/
          running=0;                 /*idia logikh kai an eixe zhthsei 512 alla egw me to kalhmera phra 1400*/
          remaining = 0;
          memcpy(buffer, socket->recvbuf, remaining);
          socket->curr_win_size+=remaining;
          for(i = 0; i< socket->index - remaining;i++){
           socket->recvbuf[i] = socket->recvbuf[remaining+i];
          }
          socket->index -=remaining;
          memset(socket->recvbuf+socket->index,'\0',MICROTCP_RECVBUF_LEN - socket->index);
        }else if(remaining > socket->index && socket->index == MICROTCP_RECVBUF_LEN - 1){
          remaining -= MICROTCP_RECVBUF_LEN;
          socket->curr_win_size+=MICROTCP_RECVBUF_LEN;
          memcpy(buffer,socket->recvbuf,MICROTCP_RECVBUF_LEN);
          memset(socket->recvbuf,'\0',MICROTCP_RECVBUF_LEN);
          socket->index =0;
        }/*prwta kanw to flashidi an xreiastei gia nar8ei to fresko curr_win_size),alliws balto katw sto allo comment*/

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

        /*ta tou xronou to do*/
      } else if (packet_read.control == FIN) {
        printf("got FIN\n");
        socket->state = CLOSING_BY_PEER;
        socket->packets_received++;
        socket->ack_number = packet_read.seq_number;
        socket->bytes_received += actual_bytes_rcv;
        socket->bytes_lost = total_bytes_lost;      
        return -2;/*sumbash gia na stamatisei to while running sto client.c*/
      }
      /*palia toxa edw,wste to currwindowsize natan 0 sto ack pousteila,gia na steilei ontws o sender ena paketaki xwris payload opws 8eloun autoi*/
      /*nmz edw prepei nanai*/
    }/*while*/
    //memcpy(buffer, socket->recvbuf, length);
    socket->bytes_received += actual_bytes_rcv;
    socket->bytes_lost = total_bytes_lost;
    // memset(socket->recvbuf, '\0', MICROTCP_RECVBUF_LEN);
    // socket->curr_win_size = MICROTCP_WIN_SIZE;
    // socket->index = 0;
    
  return actual_bytes_rcv;
}
