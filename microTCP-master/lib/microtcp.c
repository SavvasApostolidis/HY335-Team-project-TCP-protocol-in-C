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
  new_socket.state = UKNOWN;
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
  uint8_t rcvbuf[MICROTCP_RECVBUF_LEN];
  microtcp_header_t *header_rcv;
  microtcp_header_t packet_read;
  microtcp_header_t header_snd;
  int i;
  uint32_t seq_n = 0; /*N*/
  int s = sizeof(microtcp_header_t);
  uint32_t tmp_checksum;
  uint8_t checksum_buf[MICROTCP_RECVBUF_LEN];

  srand(time(NULL));

  /*Set header fields*/
  seq_n = (rand() % 1024 + 1);
  header_snd.seq_number = htonl(seq_n);
  header_snd.ack_number = 0;
  header_snd.control = htons(SYN);
  header_snd.window = htons(MICROTCP_WIN_SIZE);
  header_snd.data_len = 0;
  header_snd.future_use0 = 0;
  header_snd.future_use1 = 0;
  header_snd.future_use2 = 0;
  header_snd.checksum = 0;
  header_snd.left_sack = header_snd.ack_number;
  header_snd.right_sack = header_snd.ack_number;

  /*Set buffer values to 0*/
  for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
  {
    checksum_buf[i] = 0;
  }
  memcpy(checksum_buf, &header_snd, sizeof(header_snd));
  header_snd.checksum = htonl(crc32(checksum_buf, sizeof(checksum_buf)));

  /*send SYN packet*/
  if (sendto(socket->sd, (void *)&header_snd, sizeof( microtcp_header_t), 0, address, address_len) == -1)
  {
    perror("Send SYN packet failed\n");
    socket->state = INVALID;
    return -1;
  }

  /*Waiting for SYN_ACK from server*/
  header_rcv = (microtcp_header_t *)malloc(sizeof( microtcp_header_t *));

  if (recvfrom(socket->sd, rcvbuf, MICROTCP_RECVBUF_LEN, 0, address, &address_len) == -1)
  {
    perror("Something went wrong while receiving SYN_ACK\n");
    socket->state = INVALID;
    return -1;
  }

  header_rcv = ( microtcp_header_t *)rcvbuf;
  packet_read.seq_number = ntohl(header_rcv->seq_number);
  packet_read.ack_number = ntohl(header_rcv->ack_number);
  packet_read.control = ntohs(header_rcv->control);
  packet_read.checksum = ntohl(header_rcv->checksum);
  packet_read.window = ntohs(header_rcv->window);
  packet_read.data_len = ntohs(header_rcv->data_len);
  packet_read.future_use0 = 0;
  packet_read.future_use1 = 0;
  packet_read.future_use2 = 0;
  packet_read.left_sack = ntohl(header_rcv->left_sack);
  packet_read.right_sack = ntohl(header_rcv->right_sack);
  /*isws xreiastei na diabasoume kai ta alla gia to checksum checking*/

  tmp_checksum = packet_read.checksum;
  packet_read.checksum = 0;
  for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
  {
    checksum_buf[i] = 0;
  }
  memcpy(checksum_buf, &packet_read, sizeof( microtcp_header_t));
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
  if (packet_read.ack_number != (seq_n + s))
  {
    perror("expected N+s didnt get it\n");
    socket->state = INVALID;
    return -1;
  }

  /*SYN_ACK received, send the 3rd packet*/
  header_snd.seq_number = htonl(seq_n + s);
  header_snd.ack_number = htonl(packet_read.seq_number + s);
  header_snd.control = htons(ACK);
  header_snd.window = htons(MICROTCP_WIN_SIZE);
  header_snd.data_len = 0;
  header_snd.future_use0 = 0;
  header_snd.future_use1 = 0;
  header_snd.future_use2 = 0;
  header_snd.checksum = 0;
  header_snd.left_sack = header_snd.ack_number;
  header_snd.right_sack = header_snd.ack_number;

  for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
  {
    checksum_buf[i] = 0;
  }
  memcpy(checksum_buf, &header_snd, sizeof( microtcp_header_t));
  header_snd.checksum = htonl(crc32(checksum_buf, sizeof(checksum_buf)));

  if (sendto(socket->sd, (void *)&header_snd, sizeof( microtcp_header_t), 0, address, address_len) == -1)
  {
    perror("Send SYN packet failed\n");
    socket->state = INVALID;
    return -1;
  }
  else
  {
    socket->state = ESTABLISHED;
    socket->seq_number = seq_n + s;
    socket->ack_number = header_snd.ack_number;
    socket->init_win_size = MICROTCP_WIN_SIZE;
    socket->address_len = address_len;
    socket->recvbuf = malloc(MICROTCP_RECVBUF_LEN * sizeof(uint8_t));
  }
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len)
{
  /* Your code here */
  int syn_rcv = 0;
  uint32_t seq_n = 0; /*M*/
  int i = 0;
  int s = sizeof(microtcp_header_t);
  uint8_t rcvbuf[MICROTCP_RECVBUF_LEN];
  microtcp_header_t *header_rcv;
  microtcp_header_t packet_read;
  microtcp_header_t header_snd;
  uint32_t tmp_checksum;
  uint8_t checksum_buf[MICROTCP_RECVBUF_LEN];
  srand(time(NULL));

  header_rcv = (microtcp_header_t *)malloc(sizeof(microtcp_header_t *));
  //header_snd = (microtcp_header_t)malloc(sizeof(struct microtcp_header_t));

  if (recvfrom(socket->sd, rcvbuf, MICROTCP_RECVBUF_LEN, 0, address, &address_len) == -1)
  {
    perror("recvfrom failed\n");
    socket->state = INVALID;
    return -1;
  }
  header_rcv = (microtcp_header_t *)rcvbuf;
  packet_read.seq_number = ntohl(header_rcv->seq_number);
  packet_read.ack_number = ntohl(header_rcv->ack_number);
  packet_read.control = ntohs(header_rcv->control);
  packet_read.checksum = ntohl(header_rcv->checksum);
  packet_read.window = ntohs(header_rcv->window);
  packet_read.data_len = ntohs(header_rcv->data_len);
  packet_read.future_use0 = 0;
  packet_read.future_use1 = 0;
  packet_read.future_use2 = 0;
  packet_read.left_sack = ntohl(header_rcv->left_sack);
  packet_read.right_sack = ntohl(header_rcv->right_sack);

  /*isws xreiastei na diabasoume kai ta alla gia to checksum checking*/

  tmp_checksum = packet_read.checksum;
  packet_read.checksum = 0;
  for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
  {
    checksum_buf[i] = 0;
  }
  memcpy(checksum_buf, &packet_read, sizeof( microtcp_header_t));
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
  header_snd.seq_number = htonl(seq_n);
  header_snd.ack_number = htonl(packet_read.seq_number + s);
  header_snd.control = htons(SYN_ACK);
  header_snd.window = htons(socket->init_win_size);
  header_snd.data_len = 0;
  header_snd.future_use0 = 0;
  header_snd.future_use1 = 0;
  header_snd.future_use2 = 0;
  header_snd.checksum = 0; /*before sending calculate the checksum*/
  header_snd.left_sack = htonl(header_snd.ack_number);
  header_snd.right_sack = htonl(header_snd.ack_number);

  for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
  {
    checksum_buf[i] = 0;
  }
  memcpy(checksum_buf, &header_snd, sizeof(microtcp_header_t));
  header_snd.checksum = htonl(crc32(checksum_buf, sizeof(checksum_buf)));

  /*setting up the socket*/
  socket->seq_number = seq_n;
  socket->ack_number = ntohl(header_snd.ack_number);
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

  /*we cleanup buffer and the recieve header to re read data*/
  for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
  {
    rcvbuf[i] = 0;
  }

  if (recvfrom(socket->sd, rcvbuf, MICROTCP_RECVBUF_LEN, 0, address, &address_len) == -1)
  {
    perror("recvfrom failed in the last step from server\n");
    socket->state = INVALID;
    return -1;
  }
  header_rcv = (microtcp_header_t *)rcvbuf;
  packet_read.seq_number = ntohl(header_rcv->seq_number);
  packet_read.ack_number = ntohl(header_rcv->ack_number);
  packet_read.control = ntohs(header_rcv->control);
  packet_read.checksum = ntohl(header_rcv->checksum);
  packet_read.window = ntohs(header_rcv->window);
  packet_read.data_len = ntohs(header_rcv->data_len);
  packet_read.future_use0 = 0;
  packet_read.future_use1 = 0;
  packet_read.future_use2 = 0;
  packet_read.left_sack = ntohl(header_rcv->left_sack);
  packet_read.right_sack = ntohl(header_rcv->right_sack);

  tmp_checksum = packet_read.checksum;
  packet_read.checksum = 0;
  for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
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

  /*isws xreiastei na diabasoume kai ta alla gia to checksum checking*/
  for (i = 0; i < MICROTCP_RECVBUF_LEN; i++)
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
  if (packet_read.ack_number == (socket->seq_number + s) || packet_read.seq_number == socket->ack_number)
  {
    /*setting up the socket a final time*/
    socket->seq_number = seq_n + s;
    socket->ack_number = packet_read.ack_number;
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
}

ssize_t
microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length,
              int flags)
{
  /* Your code here */
}

ssize_t
microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags)
{
  /* Your code here */
}
