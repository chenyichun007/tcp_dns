#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <regex.h>
#include <sys/types.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <sys/wait.h>
#include <time.h>
#include <errno.h>
#include <assert.h>

typedef struct {
  unsigned short id;
  unsigned short flag;
  unsigned short questions;
  unsigned short answerRRs;
  unsigned short authorityRRs;
  unsigned short additionalRRs;
} DnsPkgHeader, *DnsPkgHeaderPtr;
typedef struct {
  unsigned char * dns_name;
  unsigned short dns_type;
  unsigned short dns_class;
} DnsPkgQuery, * DnsPkgQueryPtr;
typedef struct{
  unsigned short dns_name;
  unsigned short dns_type;
  unsigned short dns_class;
  unsigned short dns_ttl;
  unsigned char* data;
} DnsResponseAnswer, *DnsResponseAnswerPtr;

int pkg_dns(
    const char* domain,unsigned char* dns_buff, unsigned short dns_id) {
  char *domainstr = strdup(domain);
  int domainLen = strlen(domain);
  int offset = 2;
  if(domainLen <= 0)
    return -1;

  DnsPkgHeader nphp;
  DnsPkgQuery dkqp;

  nphp.id = htons(dns_id);//dns transaction id, given randomly
  nphp.flag = htons(0x0100); //dns standard query;
  nphp.questions = htons(0x0001); //num of questions;
  nphp.answerRRs = htons(0x0000);
  nphp.authorityRRs = htons(0x0000);
  nphp.additionalRRs = htons(0x0000);
  memcpy(dns_buff+offset, (unsigned char*)&nphp, sizeof(DnsPkgHeader));
  offset += sizeof(DnsPkgHeader);

  char* tok = NULL;
  tok = strtok(domainstr, ".");
  unsigned char dot = '\0';
  while (tok != NULL) {
    dot = (unsigned char)strlen(tok);
    memcpy(dns_buff + offset, &dot, sizeof(unsigned char));
    offset += sizeof(unsigned char);
    memcpy(dns_buff + offset, tok, strlen(tok));
    offset += strlen(tok);
    tok = strtok(NULL, ".");
  }
  dns_buff[offset++] = 0x00;
  dkqp.dns_type = htons(0x0001);  //Type   : A
  dkqp.dns_class = htons(0x0001); //Class : IN

  memcpy(dns_buff + offset, (unsigned char*)&dkqp.dns_type,
         sizeof(unsigned short));
  offset += sizeof(unsigned short);
  memcpy(dns_buff + offset, (unsigned char*)&dkqp.dns_class,
         sizeof(unsigned short));
  offset += sizeof(unsigned short);
  free(domainstr);
  assert(offset < 1024);
  dns_buff[0] = (char)((offset - 2) >> 8);
  dns_buff[1] = (char)(offset - 2);

  return offset;
}

int recv_analyse(
    unsigned char* buf, size_t buf_size, size_t send_size,
    char ip_vect[][16], unsigned int *ttl) { 
  int ip_count = 0;
  unsigned char* p = buf;
  char *ip = NULL;

  p += 2;//dns id
  unsigned short flag =ntohs(*((unsigned short*)p));// p[0] * 0x100 + p[1];
  if (flag & 0xF9FF != 0X8180)
  return 0; /*error hapened*/
  p += 2;//dns flag
  p += 2;//dns questions
  //p[0] * 0x100 + p[1];//dns answer RRs
  unsigned short answerRRs = ntohs(*((unsigned short*)p));
  p = buf + send_size;//p point to Answers
  unsigned short type;
  unsigned short dataLen;
  int i = 0;
  for (; i < answerRRs; i++) {
    if (*((unsigned char*)p) == 0xc0) { // compressed name
      p += 2;//Name
    } else {
      unsigned char label_len = 0;
      do {
        label_len = *((unsigned char*)p); // get current label length
        p += (label_len + 1);
      } while (label_len != 0);
    }
    type = ntohs(*((unsigned short*)p));//p[0] * 0x100 + p[1];
    p += 2;//Type;
    if (type == 0x0001) {
      p += 2;//Class
      *ttl = ntohl(*((unsigned int*)p));
      p += 4;//TTL
      dataLen = ntohs(*((unsigned short*)p));//p[0] * 0x100 + p[1];
      p += 2;//Data Length
      ip = inet_ntoa(*(struct in_addr*)p);
      if (ip) {
        assert(strlen(ip) < 16);
        strcpy(ip_vect[ip_count++], ip);
      }
      p += dataLen;
      if (ip_count >= 5) break;
      continue;
    }
    p += 2;//Class 
    p += 4;//TTL 
    dataLen = ntohs(*((unsigned short*) p));//p[0] * 0x100 + p[1]; 
    p += 2;//Data Length 
    p += dataLen;//data 
  }
  return ip_count;
}

void QueryDns(const char* domain, const char* nameserver) {
  int sock;
  struct sockaddr_in host;
  int received = 0;
  int data_len = 1024;
  char data[data_len];
  if ((sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
    printf("Tcp create socket failed!\n");
    return;
  }
  struct timeval tv;
  tv.tv_sec = 5; /* 3 Secs Timeout */
  tv.tv_usec = 0; // Not init'ing this can cause strange errors

  setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(struct timeval));
  /* Construct the server sockaddr_in structure */
  memset(&host, 0, sizeof(host)); /* Clear struct */
  host.sin_family = AF_INET; /* Internet/IP */
  host.sin_addr.s_addr = inet_addr(nameserver); /* IP address */
  host.sin_port = htons(53); /* server port */

  if (connect(sock, (struct sockaddr *) &host, sizeof(host)) < 0) {
    printf("Tcp connect socket failed!\n");
    close(sock);
    return;
  }
  unsigned char payload[1024];
  int packet_len = pkg_dns(domain, payload, 115);
  if (packet_len == -1) {
    printf("packet failed\n");
    close(sock);
    return;
  }

  if (send(sock, payload, packet_len, 0) != packet_len) {
    printf("Tcp sent len failed!\n");
    close(sock);
    return;
  }
  if ((received = recv(sock, data, data_len, 0)) < 0) {
    printf("Tcp receive failed!%lu\n", pthread_self());
    close(sock);
    return;
  }

  unsigned int ttl = 0;
  char ip_vect[5][16];
  memset(ip_vect, 0, sizeof(ip_vect));
  int ip_count = recv_analyse(data+2, received-2, packet_len-2, ip_vect, &ttl);
  if (ip_count == 0) {
    printf("nothing received\n");
  } else {
    int i = 0;
    for (; i < ip_count; i++) {
      printf("%s\n", ip_vect[i]);
    }
  }

  close(sock);
  return;
}

int main(int argc, char* argv[])
{
  if (argc != 3) {
    printf("Usage: ./tcpdns domain nameserver;\nlike ./tcpdns www.google.com 8.8.8.8\n");
    return 0;
  }
  QueryDns(argv[1], argv[2]);
  return 0;
}

