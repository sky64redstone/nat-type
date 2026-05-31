#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>

#define BUF_SIZE 1024

typedef struct {
  char ip[64];
  int port;
} mapped_addr_t;

/* STUN header */
typedef struct {
  uint16_t type;
  uint16_t length;
  uint32_t magic_cookie;
  uint8_t transaction_id[12];
} stun_header_t;

/* CHANGE-REQUEST attribute */
typedef struct {
  uint16_t type;
  uint16_t length;
  uint32_t flags;
} change_req_t;

void build_request(unsigned char* buf, int change_ip, int change_port) {
  stun_header_t* hdr = (stun_header_t*)buf;

  hdr->type = htons(0x0001);
  hdr->length = htons(change_ip || change_port ? 8 : 0);
  hdr->magic_cookie = htonl(0x2112A442);

  for (int i = 0; i < 12; i++)
      hdr->transaction_id[i] = rand() % 256;

  if (change_ip || change_port) {
    change_req_t* attr = (change_req_t*)(buf + sizeof(stun_header_t));
    attr->type = htons(0x0003);
    attr->length = htons(4);

    uint32_t flags = 0;
    if (change_ip) flags |= 0x04;
    if (change_port) flags |= 0x02;

    attr->flags = htonl(flags);
  }
}

int parse_response(unsigned char* buf, int len, mapped_addr_t* out) {
  for (int i = 20; i < len; i++) {
    if (buf[i] == 0x00 && buf[i+1] == 0x20) {
      int port = ntohs(*(uint16_t*)(buf + i + 6)) ^ 0x2112;

      uint32_t ip_raw = *(uint32_t*)(buf + i + 8) ^ htonl(0x2112A442);
      struct in_addr addr;
      addr.s_addr = ip_raw;

      strcpy(out->ip, inet_ntoa(addr));
      out->port = port;
      return 1;
    }
  }
  return 0;
}

int stun_test(
  const char* host, int port, int change_ip,
  int change_port, mapped_addr_t* result
) {

  int sock;
  struct sockaddr_in server;
  unsigned char buf[BUF_SIZE];

  sock = socket(AF_INET, SOCK_DGRAM, 0);

  struct hostent* he = gethostbyname(host);
  if (!he) return 0;

  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_port = htons(port);
  memcpy(&server.sin_addr, he->h_addr, he->h_length);

  build_request(buf, change_ip, change_port);

  sendto(sock, buf, 20 + (change_ip || change_port ? 8 : 0), 0,
         (struct sockaddr*)&server, sizeof(server));

  struct timeval tv = {2, 0};
  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

  socklen_t len = sizeof(server);
  int recv_len = recvfrom(sock, buf, BUF_SIZE, 0,
                          (struct sockaddr*)&server, &len);

  close(sock);

  if (recv_len <= 0) return 0;

  return parse_response(buf, recv_len, result);
}

int main(int argc, char** argv) {
  /* Help */
  for (int i = 1; i < argc; ++i) {
    if (!strcmp(argv[i], "help") || !strcmp(argv[i], "--help")) {
      printf("Usage: %s [stun server addr 1] [stun server addr 2]\n", argv[0]);
      printf("Public stun server: https://gist.github.com/mondain/b0ec1cf5f60ae726202e\n");
      return 0;
    }
  }

  /* Stun server */
  const char* stun_server1 = "stun1.l.google.com";
  const char* stun_server2 = "stun2.l.google.com";
  if (argc > 1) {
    stun_server1 = argv[1];
    if (argc > 2) {
      stun_server2 = argv[2];
    }
  }

  mapped_addr_t m1, m2;

  printf("Running NAT detection...\n");

  /* Test I */
  if (!stun_test(stun_server1, 19302, 0, 0, &m1)) {
      printf("UDP Blocked\n");
      return 0;
  }

  printf("Mapped Address: %s:%d\n", m1.ip, m1.port);

  /* Test II (change IP + port) */
  if (stun_test(stun_server1, 19302, 1, 1, &m2)) {
      printf("Open Internet or Full Cone NAT\n");
      return 0;
  }

  /* Test I to different server */
  if (!stun_test(stun_server2, 19302, 0, 0, &m2)) {
      printf("Error contacting second server\n");
      return 0;
  }

  if (strcmp(m1.ip, m2.ip) != 0 || m1.port != m2.port) {
      printf("Symmetric NAT\n");
      return 0;
  }

  /* Test III (change port only) */
  if (stun_test(stun_server2, 19302, 0, 1, &m2)) {
      printf("Restricted Cone NAT\n");
  } else {
      printf("Port Restricted Cone NAT\n");
  }

  return 0;
}
