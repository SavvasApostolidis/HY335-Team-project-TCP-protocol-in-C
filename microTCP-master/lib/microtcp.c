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
//void set_socket(microtcp_state_t state_s,size_t curr_win_size_s)
void prepare_send_header(microtcp_header_t *header_snd, uint32_t seq, uint32_t ack, uint16_t control, uint16_t win, uint32_t dlen)
{
  header_snd->seq_number = htonl(seq);
  header_snd->ack_number = htonl(ack);
  header_snd->control = htons(control);
  header_snd->window = htons(win);
  header_snd->data_len = htons(dlen);
  header_snd->future_use0 = 0;
  header_snd->future_use1 = 0;
  header_snd->future_use2 = 0;
  header_snd->checksum = 0;
  header_snd->left_sack = header_snd->ack_number;
  header_snd->right_sack = header_snd->ack_number;
}

void prepare_read_header(microtcp_header_t *packet_read, microtcp_header_t *header_rcv)
{
  packet_read->seq_number = ntohl(header_rcv->seq_number);
  packet_read->ack_number = ntohl(header_rcv->ack_number);
  packet_read->control = ntohs(header_rcv->control);
  packet_read->window = ntohs(header_rcv->window);
  packet_read->data_len = ntohs(header_rcv->data_len);
  packet_read->future_use0 = 0;
  packet_read->future_use1 = 0;
  packet_read->future_use2 = 0;
  packet_read->checksum = ntohl(header_rcv->checksum);
  packet_read->left_sack = ntohl(header_rcv->left_sack);
  packet_read->right_sack = ntohl(header_rcv->right_sack);
}

microtcp_sock_t
microtcp_socket(int domain, int type, int protocol)
{
  /* Your code here */
  microtcp_sock_t new_socket;
  new_socket.sd = socket(domain, type, protocol);
  if (new_socket.sd == -1)
  {
    perror("MICRO_TCP_Socket creation failed\n");
    new_socket.state = INVALID;
    return new_socket;
  }
  new_socket.state = UNKNOWN;
  // new_socket.init_win_size = MICROTCP_WIN_SIZE;
  new_socket.curr_win_size = MICROTCP_WIN_SIZE;
  new_socket.cwnd = MICROTCP_INIT_CWND;
  new_socket.ssthresh = MICROTCP_INIT_SSTHRESH;
  new_socket.recvbuf = NULL;
  new_socket.buf_fill_level = 0;
  new_socket.seq_number = 0;
  new_socket.ack_number = 0;
  return new_socket;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  int bind_status;
  bind_status = bind(socket->sd, address, address_len);
  /* Your code here */
  if (bind_status < 0)
  {
    perror("MICRO_TCP_bind failed\n");
    return bind_status;
  }
  return bind_status;
}

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len)
{
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

  /*Set header fields*/
  seq_n = (rand() % 1024 + 1);
  socket->seq_number = seq_n;
  prepare_send_header(&header_snd, socket->seq_number, 0, SYN, MICROTCP_WIN_SIZE, 0);

  /*Set buffer values to 0*/
  for (i = 0; i < sizeof(microtcp_header_t); i++)
  {
    checksum_buf[i] = 0;
  }
  memcpy(checksum_buf, &header_snd, sizeof(header_snd));
  header_snd.checksum = htonl(crc32(checksum_buf, sizeof(checksum_buf)));

  /*send SYN packet*/
  if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0, address, address_len) == -1)
  {
    perror("Send SYN packet failed\n");
    socket->state = INVALID;
    return -1;
  }
  socket->seq_number += s;
  /*Waiting for SYN_ACK from server*/
  header_rcv = (microtcp_header_t *)malloc(sizeof(microtcp_header_t *));

  if (recvfrom(socket->sd, rcvbuf, sizeof(microtcp_header_t), 0, address, &address_len) == -1)
  {
    perror("Something went wrong while receiving SYN_ACK\n");
    socket->state = INVALID;
    return -1;
  }

  header_rcv = (microtcp_header_t *)rcvbuf;

  prepare_read_header(&packet_read, header_rcv);

  tmp_checksum = packet_read.checksum;
  packet_read.checksum = 0;
  for (i = 0; i < sizeof(microtcp_header_t); i++)
  {
    checksum_buf[i] = 0;
    rcvbuf[i] = 0;
  }
  memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
  packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));

  if (tmp_checksum != packet_read.checksum)
  {
    perror("Checksum is invalid\n");
    socket->state = INVALID;
    return -1;
  }

  if (packet_read.control != SYN_ACK)
  {
    perror("SYN_ACK didn't received\n");
    socket->state = INVALID;
    return -1;
  }
  if (packet_read.ack_number != socket->seq_number)
  {
    perror("expected N+s didnt get it\n");
    socket->state = INVALID;
    return -1;
  }

  /*SYN_ACK received, send the 3rd packet*/

  prepare_send_header(&header_snd, socket->seq_number, packet_read.seq_number + s, ACK, MICROTCP_WIN_SIZE, 0);

  for (i = 0; i < sizeof(microtcp_header_t); i++)
  {
    checksum_buf[i] = 0;
  }
  memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
  header_snd.checksum = htonl(crc32(checksum_buf, sizeof(checksum_buf)));

  if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0, address, address_len) == -1)
  {
    perror("Send SYN packet failed\n");
    socket->state = INVALID;
    return -1;
  }
  else
  {
    socket->state = ESTABLISHED;
    socket->ack_number = packet_read.seq_number + s; //den lambanoume genika acks opote doesnt matter for now
    socket->init_win_size = MICROTCP_WIN_SIZE;
    socket->address_len = address_len;
    socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN * sizeof(uint8_t));
  }
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len)
{
  /* Your code here */
  uint32_t seq_n = 0; /*M*/
  size_t i = 0;
  int s = sizeof(microtcp_header_t);
  uint8_t rcvbuf[sizeof(microtcp_header_t)];
  microtcp_header_t *header_rcv;
  microtcp_header_t packet_read;
  microtcp_header_t header_snd;
  uint32_t tmp_checksum;
  uint8_t checksum_buf[sizeof(microtcp_header_t)];
  srand(time(NULL));

  header_rcv = (microtcp_header_t *)malloc(sizeof(microtcp_header_t *));

  if (recvfrom(socket->sd, rcvbuf, sizeof(microtcp_header_t), 0, address, &address_len) == -1)
  {
    perror("recvfrom failed\n");
    socket->state = INVALID;
    return -1;
  }
  header_rcv = (microtcp_header_t *)rcvbuf;

  /*isws xreiastei na diabasoume kai ta alla gia to checksum checking*/
  prepare_read_header(&packet_read, header_rcv);

  tmp_checksum = packet_read.checksum;
  packet_read.checksum = 0;
  for (i = 0; i < sizeof(microtcp_header_t); i++)
  {
    checksum_buf[i] = 0;
  }
  memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
  packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));

  if (tmp_checksum != packet_read.checksum)
  {
    perror("Checksum is invalid\n");
    socket->state = INVALID;
    return -1;
  }

  if (packet_read.control != SYN)
  {
    perror("tried to establish connection without sending SYN\n");
    socket->state = INVALID;
    return -1;
  }
  /* setting up the header to send*/
  seq_n = (rand() % 1024 + 1);
  socket->seq_number = seq_n;
  prepare_send_header(&header_snd, socket->seq_number, packet_read.seq_number + s, SYN_ACK, MICROTCP_WIN_SIZE, 0);

  for (i = 0; i < sizeof(microtcp_header_t); i++)
  {
    checksum_buf[i] = 0;
  }
  memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
  header_snd.checksum = htonl(crc32(checksum_buf, sizeof(checksum_buf)));

  /*setting up the socket*/
  socket->ack_number = ntohl(packet_read.seq_number + s);
  socket->init_win_size = MICROTCP_WIN_SIZE;
  //socket->sin = (struct sockaddr_in)*address;
  socket->address_len = address_len;

  /*send a response because no data inside we dont need buffer,just send header*/
  if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0, address, address_len) == -1)
  {
    socket->state = INVALID;
    perror("failed to send synack packet\n");
    return -1;
  }
  socket->seq_number += s;
  /*we cleanup buffer and the recieve header to re read data*/
  for (i = 0; i < sizeof(microtcp_header_t); i++)
  {
    rcvbuf[i] = 0;
  }

  if (recvfrom(socket->sd, rcvbuf, sizeof(microtcp_header_t), 0, address, &address_len) == -1)
  {
    perror("recvfrom failed in the last step from server\n");
    socket->state = INVALID;
    return -1;
  }
  header_rcv = (microtcp_header_t *)rcvbuf;

  prepare_read_header(&packet_read, header_rcv);

  tmp_checksum = packet_read.checksum;
  packet_read.checksum = 0;
  for (i = 0; i < sizeof(microtcp_header_t); i++)
  {
    checksum_buf[i] = 0;
  }
  memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
  packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));

  if (tmp_checksum != packet_read.checksum)
  {
    perror("Checksum is invalid\n");
    socket->state = INVALID;
    return -1;
  }

  for (i = 0; i < sizeof(microtcp_header_t); i++)
  {
    rcvbuf[i] = 0;
    checksum_buf[i] = 0;
  }
  if (packet_read.control != ACK)
  {
    perror("tried to establish connection without sending SYN\n");
    socket->state = INVALID;
    return -1;
  }
  if (packet_read.ack_number == (socket->seq_number) || packet_read.seq_number == socket->ack_number)
  {
    /*setting up the socket a final time*/
    socket->state = ESTABLISHED;
    socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN * sizeof(uint8_t));
    return 0;
  }
  else
  {
    perror(" seq numbers didnt much with ack numbers");
    socket->state = INVALID;
    return -1;
  }
}

int microtcp_shutdown(microtcp_sock_t *socket, int how)
{
  /* Your code here */
  int i = 0;
  int s = sizeof(microtcp_header_t);
  uint8_t rcvbuf[MICROTCP_RECVBUF_LEN];
  microtcp_header_t *header_rcv;
  microtcp_header_t packet_read;
  microtcp_header_t header_snd;
  uint32_t tmp_checksum;
  uint8_t checksum_buf[MICROTCP_RECVBUF_LEN];
  /*Allocate memory to read the packet*/
  header_rcv = (microtcp_header_t *)malloc(sizeof(microtcp_header_t *));

  if (socket->state == CLOSING_BY_PEER)
  {
    /*O D*/
    /*Prepare header to send FIN*/
    prepare_send_header(&header_snd, socket->seq_number, socket->ack_number + s, FIN_ACK, socket->curr_win_size, 0);
    for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
    {
      checksum_buf[i] = 0;
    }
    memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
    header_snd.checksum = htonl(crc32(checksum_buf, sizeof(checksum_buf)));
    /*Send the FIN_ACK packet*/
    if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0, (struct sockaddr *)&socket->sin, socket->address_len) == -1)
    {
      socket->state = INVALID;
      perror("failed to send FIN packet\n");
      return -1;
    }
    /*we remember that we answered x+s ,we will check next seq number with ack number of socket(without +s again)*/
    socket->ack_number += s;

    /* waste some time maybe process last data in buffer remaining,free your resources i guess?*/
    //
    //
    //
    prepare_send_header(&header_snd, socket->seq_number, socket->ack_number, FIN, socket->curr_win_size, 0);
    for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
    {
      checksum_buf[i] = 0;
    }
    memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
    header_snd.checksum = htonl(crc32(checksum_buf, sizeof(checksum_buf)));
    /*Send the FIN packet*/
    if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0, (struct sockaddr *)&socket->sin, socket->address_len) == -1)
    {
      socket->state = INVALID;
      perror("failed to send FIN packet\n");
      return -1;
    }
    socket->seq_number += s;
    if (recvfrom(socket->sd, rcvbuf, MICROTCP_RECVBUF_LEN, 0, (struct sockaddr *)&socket->sin, &socket->address_len) == -1)
    {
      perror("Something went wrong while receiving FIN_ACK\n");
      socket->state = INVALID;
      return -1;
    }

    header_rcv = (microtcp_header_t *)rcvbuf;

    prepare_read_header(&packet_read, header_rcv);

    tmp_checksum = packet_read.checksum;
    packet_read.checksum = 0;
    for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
    {
      checksum_buf[i] = 0;
      rcvbuf[i] = 0;
    }
    memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
    packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));

    if (packet_read.ack_number != (socket->seq_number) || packet_read.seq_number != (socket->ack_number))
    {
      perror("expected N+s didnt get it\n");
      socket->state = INVALID;
      return -1;
    }

    if (tmp_checksum != packet_read.checksum)
    {
      perror("Checksum is invalid\n");
      socket->state = INVALID;
      return -1;
    }

    if (packet_read.control != FIN_ACK)
    {
      perror("FIN_ACK didn't received\n");
      socket->state = INVALID;
      return -1;
    }
    else
    {
      /*Ola kala -> Close connection*/
      socket->state = CLOSED;
      /*TODO free if recvbuf used*/
    }
  } /*Telos o D*/
  else
  {
    /*O S*/
    /*Prepare header to send FIN*/

    prepare_send_header(&header_snd, socket->seq_number, socket->ack_number, FIN, socket->curr_win_size, 0);

    for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
    {
      checksum_buf[i] = 0;
    }
    memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
    header_snd.checksum = htonl(crc32(checksum_buf, sizeof(checksum_buf)));

    /*Send the FIN packet*/
    if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0, (struct sockaddr *)&socket->sin, socket->address_len) == -1)
    {
      socket->state = INVALID;
      perror("failed to send FIN packet\n");
      return -1;
    }
    socket->seq_number += s;
    if (recvfrom(socket->sd, rcvbuf, MICROTCP_RECVBUF_LEN, 0, (struct sockaddr *)&socket->sin, &socket->address_len) == -1)
    {
      perror("Something went wrong while receiving FIN_ACK\n");
      socket->state = INVALID;
      return -1;
    }

    header_rcv = (microtcp_header_t *)rcvbuf;

    prepare_read_header(&packet_read, header_rcv);

    tmp_checksum = packet_read.checksum;
    packet_read.checksum = 0;
    for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
    {
      checksum_buf[i] = 0;
      rcvbuf[i] = 0;
    }
    memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
    packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));

    if (packet_read.ack_number != socket->seq_number)
    {
      perror("expected N+s didnt get it\n");
      socket->state = INVALID;
      return -1;
    }

    if (tmp_checksum != packet_read.checksum)
    {
      perror("Checksum is invalid\n");
      socket->state = INVALID;
      return -1;
    }

    if (packet_read.control != FIN_ACK)
    {
      perror("FIN_ACK didn't received\n");
      socket->state = INVALID;
      return -1;
    }
    else
    {
      socket->state = CLOSING_BY_HOST;
      socket->ack_number = packet_read.seq_number;
    }

    /*Waiting fot FIN from D*/
    if (recvfrom(socket->sd, rcvbuf, MICROTCP_RECVBUF_LEN, 0, (struct sockaddr *)&socket->sin, &socket->address_len) == -1)
    {
      perror("Something went wrong while receiving FIN_ACK\n");
      socket->state = INVALID;
      return -1;
    }

    header_rcv = (microtcp_header_t *)rcvbuf;

    prepare_read_header(&packet_read, header_rcv);

    tmp_checksum = packet_read.checksum;
    packet_read.checksum = 0;
    for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
    {
      checksum_buf[i] = 0;
      rcvbuf[i] = 0;
    }
    memcpy(checksum_buf, &packet_read, sizeof(microtcp_header_t));
    packet_read.checksum = crc32(checksum_buf, sizeof(checksum_buf));

    if (tmp_checksum != packet_read.checksum)
    {
      perror("Checksum is invalid\n");
      socket->state = INVALID;
      return -1;
    }

    if (packet_read.control != FIN)
    {
      perror("FIN didn't received\n");
      socket->state = INVALID;
      return -1;
    }
    else
    {
      socket->ack_number = packet_read.seq_number + s;
    }

    prepare_send_header(&header_snd, socket->seq_number, socket->ack_number, FIN_ACK, socket->curr_win_size, 0);

    for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
    {
      checksum_buf[i] = 0;
    }
    memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
    header_snd.checksum = htonl(crc32(checksum_buf, sizeof(checksum_buf)));

    /*Send the FIN_ACK packet*/
    if (sendto(socket->sd, (void *)&header_snd, sizeof(microtcp_header_t), 0, (struct sockaddr *)&socket->sin, socket->address_len) == -1)
    {
      socket->state = INVALID;
      perror("failed to send FIN_ACK packet\n");
      return -1;
    }
    else
    {
      socket->state = CLOSED;
      /*TODO free recvbuf*/
    }

  } /*To megalo else*/
  return 0;
}

ssize_t
microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length,
              int flags)
{
  /* Your code here */
  void *send_buffer;
  microtcp_header_t header_send;
  uint32_t data_to_send;
  uint32_t message_len;
  size_t packets_num;
  size_t bytes_sent = 0;
  size_t actual_bytes_sent = 0;
  size_t tmp_bytes = 0;
  size_t bytes_rcv;
  uint64_t packets_sent;
  uint32_t tmpChecksum;
  // uint8_t checksum_buf;
  size_t i = 0, cleanup;

  packets_num = length / (MICROTCP_MSS - sizeof(microtcp_header_t));

  message_len = MICROTCP_MSS - sizeof(microtcp_header_t);
  send_buffer = malloc(MICROTCP_MSS);

  for (i = 0; i < packets_num; i++)
  {
    prepare_send_header(&header_send, socket->seq_number, socket->ack_number, ACK, socket->curr_win_size, message_len);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + bytes_sent, message_len);

    /*Checksums*/
    tmpChecksum = crc32(send_buffer, sizeof(send_buffer));
    header_send.checksum = htonl(tmpChecksum);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + bytes_sent, message_len);

    if (tmp_bytes = sendto(socket->sd, (void *)&send_buffer, MICROTCP_MSS, 0, (struct sockaddr *)&socket->sin, socket->address_len) == -1)
    {
      perror("failed to send the packet\n");
      return actual_bytes_sent;
    }
    //socket->seq_number += message_len;
    socket->seq_number += 1;
    /*At the moment we suppose everything */
    bytes_sent += message_len;
    actual_bytes_sent += tmp_bytes - sizeof(send_buffer);
  }
  free(send_buffer);
  if (length % (MICROTCP_MSS - sizeof(microtcp_header_t)))
  {

    message_len = length % (MICROTCP_MSS - sizeof(microtcp_header_t));
    send_buffer = malloc(message_len + sizeof(microtcp_header_t));

    /*Den xoragan se akeraio ari8mo paketon, stelnoyme ena akoma*/
    // for (cleanup = 0; cleanup < MICROTCP_MSS; cleanup++)
    // {
    //   send_buffer[cleanup] = 0;
    // }

    prepare_send_header(&header_send, socket->seq_number, socket->ack_number, ACK, socket->curr_win_size, message_len);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + bytes_sent, message_len);

    tmpChecksum = crc32(send_buffer, sizeof(send_buffer));
    header_send.checksum = htonl(tmpChecksum);
    memcpy(send_buffer, &header_send, sizeof(header_send));
    memcpy(send_buffer + sizeof(header_send), buffer + bytes_sent, message_len);
    /*edw einai smaller*/
    if (tmp_bytes = sendto(socket->sd, (void *)&send_buffer, MICROTCP_MSS, 0, (struct sockaddr *)&socket->sin, socket->address_len) == -1)
    {
      perror("failed to send the packet\n");
      return actual_bytes_sent;
    }
    //socket->seq_number += message_len;
    socket->seq_number += 1;
    /*At the moment we suppose everything */
    bytes_sent += message_len;
    actual_bytes_sent += tmp_bytes - sizeof(header_send);
  }
  /*Clean the buffer*/

  socket->bytes_send = actual_bytes_sent;
  socket->bytes_lost = bytes_sent - actual_bytes_sent;
  socket->packets_send = packets_num;

  return socket->bytes_send;
}

ssize_t
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  /* Your code here */
  int running = 1;
  size_t i = 0;
  int s = sizeof(microtcp_header_t);
  uint8_t rcvbuf[MICROTCP_MSS];
  uint8_t *data;
  //size_t  bytes_prommised=0;
  size_t bytes_transfered = 0;
  size_t actual_bytes_rcv = 0;
  size_t total_bytes_lost = 0;
  microtcp_header_t *header_rcv;
  microtcp_header_t packet_read;
  //microtcp_header_t header_snd;
  uint32_t tmp_checksum;
  uint32_t tmp_calc_checksum;
  uint8_t checksum_buf[MICROTCP_MSS];
  /*Allocate memory to read the packet*/
  header_rcv = (microtcp_header_t *)malloc(sizeof(microtcp_header_t *));
  while (running)
  {
    /*Waiting fot FIN from D*/
    if (bytes_transfered = recvfrom(socket->sd, rcvbuf, MICROTCP_MSS, 0, (struct sockaddr *)&socket->sin, &socket->address_len) == -1)
    {
      perror("Something went wrong while receiving a packet\n");
      socket->state = INVALID;
      break;
    }
    header_rcv = (microtcp_header_t *)rcvbuf;
    data = rcvbuf + sizeof(microtcp_header_t);
    prepare_read_header(&packet_read, header_rcv);
    tmp_checksum = packet_read.checksum;
    packet_read.checksum = 0;
    for (i = 0; i < MICROTCP_MSS; i++)
    {
      checksum_buf[i] = 0;
      rcvbuf[i] = 0;
    }
    memcpy(checksum_buf, &packet_read, sizeof(packet_read));
    memcpy(checksum_buf + sizeof(packet_read), data, packet_read.data_len);

    tmp_calc_checksum = crc32(checksum_buf, sizeof(checksum_buf));

    if (tmp_calc_checksum != tmp_checksum)
    {
      perror("noise may have altered the bytes\n");
      /*todo*/
      continue; /*tmp*/
    }
    if (packet_read.data_len > bytes_transfered - sizeof(microtcp_header_t))
    {
      perror("some bytes of data where not transfered\n");
      /*todo*/
      actual_bytes_rcv += bytes_transfered - sizeof(microtcp_header_t);
      total_bytes_lost += packet_read.data_len - bytes_transfered - sizeof(microtcp_header_t);
      continue; /*tmp*/
    }
    if (socket->ack_number < packet_read.seq_number)
    { /*xa8hke paketo*/
      socket->packets_lost = packet_read.seq_number - socket->ack_number;
      //total_bytes_lost += packet_read.data_len*(packet_read.seq_number - socket->ack_number);
    }
    /*deal with packet as if it was normal*/
    if (packet_read.control == ACK)
    {
      socket->packets_received++;
      socket->ack_number = packet_read.seq_number++; /*proxoraw kata 1 gia na kanw expect swsto 1h fash*/
      actual_bytes_rcv += packet_read.data_len;
      printf("%s\n", (char *)data); /*may induse seg*/
      printf("eutasa edw\n");
      /*ta tou xronou to do*/
    }
    else if (packet_read.control == FIN)
    {
      socket->state = CLOSING_BY_PEER;
      socket->packets_received++;
      socket->ack_number = packet_read.seq_number;
      /*todo isws mas poun oti 8a erxontai data sto shutdown diabaseta ola,isws looparw th rcvfrom h steilw acks*/
      /*todo xrono*/
      break;
    }

  } /*h while*/
socket->bytes_received = actual_bytes_rcv;
socket->bytes_lost = total_bytes_lost;
return actual_bytes_rcv;
}
