tcp_dns
=======
resolve a domain by tcp

Build:
  gcc -o tcpdns tcp_dns.c

Usage:
  ./tcpdns domain nameserver
  like: ./tcpdns www.google.com 8.8.8.8
