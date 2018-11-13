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
  new_socket.init_win_size = MICROTCP_WIN_SIZE;
  new_socket.curr_win_size = MICROTCP_WIN_SIZE;
  new_socket.cwnd = MICROTCP_INIT_CWND;
  new_socket.ssthresh = MICROTCP_INIT_SSTHRESH;

  return new_socket;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address,
                  socklen_t address_len)
{
  int bind_status;
  bind_status = bind(socket->sd,address,address_len);
  /* Your code here */
  if(bind_status < 0){
    perror("MICRO_TCP_bind failed\n");
    return bind_status;
  }
  return bind_status;
}



int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address,
                     socklen_t address_len)
{
  /* Your code here */
  uint8_t buffer [socket->init_win_size];
  //microtcp_header_t
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address,
                    socklen_t address_len)
{
  /* Your code here */
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
