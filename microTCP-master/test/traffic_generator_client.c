/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2017  Manolis Surligas <surligas@gmail.com>
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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../lib/microtcp.h"
#include "../utils/log.h"

static char running = 1;

static void sig_handler(int signal) {
  if (signal == SIGINT) {
    LOG_INFO("Stopping traffic generator client...");
    running = 0;
  }
}

int main(int argc, char **argv) {
  // uint16_t port;
  uint16_t randomport;
  // int sock; // our socket file descriptor
  struct sockaddr_in sin, sin_server;  // sin for us sin_server for server
  socklen_t addr_size;
  unsigned short int connecting_port;
  int shutdown=0;
  ssize_t se, re;
  microtcp_sock_t socket;
  randomport = atoi(argv[1]);
  connecting_port = atoi(argv[2]);
  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(randomport);
  sin.sin_addr.s_addr = INADDR_ANY;

  memset(&sin_server, 0, sizeof(struct sockaddr_in));
  sin_server.sin_family = AF_INET;
  sin_server.sin_port = htons(connecting_port);
  sin_server.sin_addr.s_addr = inet_addr("127.0.0.1");

  socket = microtcp_socket(AF_INET, SOCK_DGRAM, 0);

  // memset(socket.sin, 0, sizeof(struct sockaddr_in *));
  socket.sin = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in *));

  socket.sin->sin_family = AF_INET;
  socket.sin->sin_port = htons(connecting_port);
  socket.sin->sin_addr.s_addr = inet_addr("127.0.0.1");

  if (socket.state == INVALID) {
    perror("Opening TCP sending socket");
    exit(EXIT_FAILURE);
  }
  /*
   * Register a signal handler so we can terminate the client with
   * Ctrl+C
   */
  signal(SIGINT, sig_handler);

  if (microtcp_bind(&socket, (struct sockaddr *)&sin,
                    sizeof(struct sockaddr_in)) == -1) {
    perror("TCP bind");
    exit(EXIT_FAILURE);
  }

  LOG_INFO("Start receiving traffic from port %u, ip %s", connecting_port, inet_ntoa(sin_server.sin_addr));
  /*TODO: Connect using microtcp_connect() */
  /* Connect to another socket */
  if (microtcp_connect(&socket, (struct sockaddr *)&sin_server,
                       sizeof(struct sockaddr_in)) == -1) {
    perror("FAILED TO Connect to TCP server");
    exit(EXIT_FAILURE);
  }
  uint8_t buffer[MICROTCP_RECVBUF_LEN];
  int i;
  while (running) {
    /* TODO: Measure time */
    /* TODO: Receive using microtcp_recv()*/
    memset(buffer, '\0', MICROTCP_RECVBUF_LEN);
    shutdown = microtcp_recv(&socket, buffer, MICROTCP_RECVBUF_LEN, 0);
    printf("in buffer\n");
    for(i=0;i<MICROTCP_RECVBUF_LEN; i++){
      printf("%c",buffer[i]);
    }
    printf("\n");
    if(shutdown == -2){
      running = 0;
    }
    /* TODO: Measure time */
    /* TODO: Do other stuff... */
  }

  microtcp_shutdown(&socket, SHUT_RDWR);
  /* Ctrl+C pressed! Store properly time measurements for plotting */
}
