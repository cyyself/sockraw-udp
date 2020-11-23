#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <net/if.h>
#include <net/ethernet.h>
const char* bind_interface = "ens33";

char mymac[6];

int sock_fd;

void sigint_handler(sig_t s){
	close(sock_fd);
	exit(1); 
}

void print_mac_addr(unsigned char *mac) {
	for (int i=0;i<6;i++) printf("%02x%c",(unsigned char)mac[i],i==5?'\n':' ');
}

unsigned short endian_reverse(unsigned short x) {
	return (x << 8) | (x >> 8);
}

void recv_ipv4(unsigned char *packet,int len) {
	struct iphdr l3_header;
	memcpy(&l3_header,packet,sizeof(l3_header));
	struct in_addr saddr, daddr;
	memcpy(&saddr,&l3_header.saddr,sizeof(saddr));
	memcpy(&daddr,&l3_header.daddr,sizeof(saddr));
	char *src_ip_s = inet_ntoa(saddr);
	printf("src ip: %s\n",src_ip_s);
	char *dst_ip_s = inet_ntoa(daddr);
	printf("dst ip: %s\n",dst_ip_s);
}

void recv_eth(unsigned char *frame,int len) {
	struct ethhdr l2_header;
	memcpy(&l2_header,frame,sizeof(l2_header));
	printf("mac dst: ");
	print_mac_addr(l2_header.h_dest);
	printf("mac src: ");
	print_mac_addr(l2_header.h_source);
	switch (endian_reverse(l2_header.h_proto)) {
		case ETH_P_IP:
			printf("IPv4\n");
			recv_ipv4(frame+sizeof(l2_header),len-sizeof(l2_header));
			break;
		case ETH_P_IPV6:
			printf("IPv6\n");
			break;
		case ETH_P_ARP:
			printf("ARP\n");
			break;
		default:
			printf("unknow protocol %04x\n",endian_reverse(l2_header.h_proto));
	}
}
void test_packet() {
	char buf[2048] = {0x16,0x7d,0xda,0xa6,0x6c,0x65,0x00,0x0c,0x29,0x32,0x2f,0x61,0x08,0x00,0x45,0x00,0x00,0x54,0x1f,0x8f,0x40,0x00,0x40,0x01,0x3c,0x6e,0xc0,0xa8,0x1c,0x02,0x01,0x01,0x01,0x01,0x08,0x00,0xba,0x52,0x00,0x06,0x00,0x01,0xa2,0xd1,0xbb,0x5f,0x00,0x00,0x00,0x00,0x1d,0xa2,0x03,0x00,0x00,0x00,0x00,0x00,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37};
	recv_eth(buf,98);
}

int main() {
	signal(SIGINT,(__sighandler_t)sigint_handler);
	sock_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	struct sockaddr_ll sll;
	memset(&sll,0,sizeof(sll));
	sll.sll_family = AF_PACKET;
	struct ifreq ifstruct;
	strcpy(ifstruct.ifr_name,bind_interface);
	if (ioctl(sock_fd,SIOCGIFHWADDR,&ifstruct) == 0 && ioctl(sock_fd,SIOCGIFINDEX,&ifstruct) == 0) {
		sll.sll_ifindex = ifstruct.ifr_ifindex;
		sll.sll_protocol = htons(ETH_P_ALL);
		printf("local mac_addr: ");
		print_mac_addr(ifstruct.ifr_addr.sa_data);
	}
	else {
		perror("io error");
		exit(1);
	}
	if (bind(sock_fd,(struct sockaddr *)&sll,sizeof(sll)) == -1) {
		perror("bind error");
		printf("Are you root?\n");
		exit(1);
	}
	const int buf_sz = 65536;
	unsigned char buf[buf_sz];
	ssize_t sz;
	while ((sz = recv(sock_fd,buf,buf_sz,0)) > 0) {
		printf("%d:",sz);
		for (int i=0;i<sz;i++) printf("%02x,",buf[i]);
		printf("\n");
		recv_eth(buf,sz);
	}
	//TODO: pack/unpack IP packet and IP fragment

	return 0;
}
