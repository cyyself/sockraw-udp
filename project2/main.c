#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include "cksum.c"



char* bind_interface = "docker0";//you can change it, such as eth0

struct in_addr myip;
unsigned char mymac[6];
const unsigned char bcast_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
unsigned short mtu = 1500;//you can even try 28

const unsigned short more_frag_mask= 0x2000;
const unsigned short frag_offset_mask = 0x1fff;
const unsigned char proto_udp = 17;
const int buf_sz = 65536;
#define max_frag_size 65536//actually supoort to 9000 Bytes jumbo frame is enough

int sock_fd;

void sigint_handler(sig_t s){
	close(sock_fd);
	exit(1); 
}

void print_mac_addr(unsigned char *mac) {
	for (int i=0;i<6;i++) printf("%02x%c",(unsigned char)mac[i],i==5?'\n':' ');
}

char get_header_hash(struct iphdr l3_header) {
	const char hash_base = 2333;
	char src_ip_hash = 
		((l3_header.saddr >>  0) & 0xff) ^
		((l3_header.saddr >>  8) & 0xff) ^ 
		((l3_header.saddr >> 16) & 0xff) ^ 
		((l3_header.saddr >> 24) & 0xff);
	char dst_ip_hash = 
		((l3_header.daddr >>  0) & 0xff) ^
		((l3_header.daddr >>  8) & 0xff) ^ 
		((l3_header.daddr >> 16) & 0xff) ^ 
		((l3_header.daddr >> 24) & 0xff);
	char id_hash = (l3_header.id >> 8) ^ (l3_header.id & 0xff);
	return hash_base ^ src_ip_hash ^ dst_ip_hash ^ id_hash;
}

void print_hex(unsigned char *payload,unsigned short len) {
	printf("%d:{",len);
	for (int i=0;i<len;i++) printf("%02x,",payload[i]);
	printf("}\n");
}
int verify_cksum(struct iphdr l3_header) {
	unsigned short cksum = l3_header.check;
	l3_header.check = 0;
	if (in_cksum(&l3_header,sizeof(l3_header)) == cksum) return 0;
	else return 1;
}
void recv_udp(unsigned char *payload,unsigned short len) {
	struct udphdr l4_header;
	memcpy(&l4_header,payload,sizeof(l4_header));
	if (ntohs(l4_header.len) == len) {
		printf("recv_udp src=%d dst=%d\n",ntohs(l4_header.source),ntohs(l4_header.dest));
		for (int i=8;i<len;i++) printf("%c",payload[i]);
		printf("\n");
	}
	else {
		printf("bad udp size\n");
	}
}
void recv_ipv4(unsigned char *packet,unsigned short len) {
	struct iphdr l3_header;
	memcpy(&l3_header,packet,sizeof(l3_header));
	struct in_addr saddr, daddr;
	memcpy(&saddr,&l3_header.saddr,sizeof(saddr));
	memcpy(&daddr,&l3_header.daddr,sizeof(saddr));
	char *src_ip_s = inet_ntoa(saddr);
	printf("src ip=%s, ",src_ip_s);
	char *dst_ip_s = inet_ntoa(daddr);
	printf("dst ip=%s,",dst_ip_s);
	if (len != ntohs(l3_header.tot_len)) {
		printf("Packet size error\n");
		return;
	} 
	if (verify_cksum(l3_header)) {
		printf("header cksum error\n");
		return;
	}
	unsigned short more_frag = ntohs(l3_header.frag_off) & more_frag_mask;
	unsigned short frag_offset = (ntohs(l3_header.frag_off) & frag_offset_mask) << 3;
	unsigned char *payload = packet + (l3_header.ihl << 2);
	unsigned short payloadlen = ntohs(l3_header.tot_len) - (l3_header.ihl << 2);
	printf("payloadlen=%d,frag_offset=%d,more_frag=%s\n",payloadlen,frag_offset,more_frag?"YES":"NO");
	if (more_frag || frag_offset) {
		static char frag_mem[1<<8][max_frag_size];//hash id to 8 bit
		static unsigned short frag_len[1<<8];
		static unsigned short frag_totlen[1<<8];
		unsigned char header_hash = get_header_hash(l3_header);
		if (payloadlen + frag_offset >= max_frag_size) {//check if this packet will result in buffer overflow
			printf("bad packet\n");
			return;
		}
		frag_len[header_hash] += payloadlen;
		memcpy(&frag_mem[header_hash][frag_offset],payload,payloadlen);
		if (frag_totlen[header_hash] && frag_offset > frag_totlen[header_hash]) {
			frag_totlen[header_hash] = 0;
			printf("drop frag\n");
		}
		if (!more_frag) frag_totlen[header_hash] = frag_offset + payloadlen;
		if (frag_len && frag_len[header_hash] == frag_totlen[header_hash]) {
			printf("reassemble packet success\n");
			if (l3_header.protocol == proto_udp) {
				recv_udp(frag_mem[header_hash],frag_totlen[header_hash]);
			}
			frag_totlen[header_hash] = 0;
			frag_len[header_hash] = 0;
		}
	}
	else {
		if (l3_header.protocol == proto_udp) {
			recv_udp(payload,payloadlen);
		}
	}
}


void recv_eth(unsigned char *frame,unsigned short len) {
	struct ethhdr l2_header;
	memcpy(&l2_header,frame,sizeof(l2_header));
	/*
	printf("mac dst: ");
	print_mac_addr(l2_header.h_dest);
	printf("mac src: ");
	print_mac_addr(l2_header.h_source);
	*/
	switch (ntohs(l2_header.h_proto)) {
		case ETH_P_IP:
			printf("IPv4\n");
			recv_ipv4(frame+sizeof(l2_header),len-sizeof(l2_header));
			break;
		default:
			//printf("unknow protocol %04x\n",ntohs(l2_header.h_proto));
			break;
	}
}
int lowbit_clear(int x,int len) {
	return x >> len << len;
}
void send_eth(unsigned char *dst,unsigned short proto,unsigned char *payload,unsigned int payloadlen) {
	char buf[buf_sz];
	struct ethhdr l2_header;
	memcpy(&l2_header.h_dest,dst,6);
	memcpy(&l2_header.h_source,mymac,6);
	l2_header.h_proto = proto;
	memcpy(buf,&l2_header,sizeof(l2_header));
	memcpy(buf+14,payload,payloadlen);
	send(sock_fd,buf,payloadlen+14,0);
}
void send_ip(struct in_addr dst_ip,unsigned char protocol,unsigned char *payload,unsigned short len) {
	char buf[buf_sz];
	struct iphdr l3_header;
	l3_header.version = 4;
	l3_header.ihl = 5;
	l3_header.tos = 0;
	l3_header.tot_len = htons(len + (l3_header.ihl << 2));
	l3_header.id = rand() & 0xffff;
	l3_header.frag_off = 0;
	l3_header.ttl = 64;
	l3_header.protocol = protocol;
	l3_header.check = 0;
	l3_header.saddr = myip.s_addr;
	l3_header.daddr = dst_ip.s_addr;
	if (len > mtu - (l3_header.ihl << 2)) {
		//do_fragment
		int each_sz = lowbit_clear(mtu - (l3_header.ihl << 2),3);
		//try to send in reverse order to check frag is ok
		for (int i=len-(len%each_sz==0?each_sz:len%each_sz);i>=0;i-=each_sz) {
		//for (int i=0;i<len;i+=each_sz) {
			unsigned char more_frag = i + each_sz < len;
			l3_header.tot_len = htons(20 + (more_frag ? each_sz : len - i));
			l3_header.frag_off = htons((i >> 3) | (more_frag?more_frag_mask:0));
			l3_header.check = 0;
			l3_header.check = in_cksum(&l3_header,sizeof(l3_header));
			memcpy(buf,&l3_header,sizeof(l3_header));
			memcpy(buf+20,payload+i,(more_frag ? each_sz : len - i));
			send_eth(bcast_mac,htons(ETH_P_IP),buf,ntohs(l3_header.tot_len));
			//no arp, broadcast every packet
		}
	}
	else {
		l3_header.check = in_cksum(&l3_header,sizeof(l3_header));
		memcpy(buf,&l3_header,sizeof(l3_header));
		memcpy(buf+20,payload,len);
		send_eth(bcast_mac,htons(ETH_P_IP),buf,len+20);
		//no arp, broadcast every packet
	}
}
void send_ip_a(char* dst_ip,unsigned char protocol,unsigned char *payload,unsigned short len) {
	struct in_addr dst_ip_n;
	inet_aton(dst_ip,&dst_ip_n);
	send_ip(dst_ip_n,protocol,payload,len);
}
void send_udp(char* dst_ip,unsigned short src_port,unsigned short dst_port,char *payload,unsigned short len) {
	char buf[buf_sz];
	struct udphdr l4_header;
	l4_header.source = htons(src_port);
	l4_header.dest = htons(dst_port);
	l4_header.check = 0;
	l4_header.len = htons(len + 8);
	memcpy(buf,&l4_header,sizeof(l4_header));
	memcpy(buf+8,payload,len);
	send_ip_a(dst_ip,proto_udp,buf,len+8);
}
char test_udp_payload[3000];
void init_test_udp_payload() {
	memset(test_udp_payload,' ',sizeof(test_udp_payload));
	char *begin = "----- Test BEGIN -----\nHi, I'm a udp payload of size 3000.\n";
	memcpy(test_udp_payload,begin,strlen(begin));
	char *end = "\n----- Test END -----\n";
	memcpy(test_udp_payload+3000-strlen(end),end,strlen(end));
}
int main(int argc,char *argv[]) {
	//use -l to bind for specific interface
	for (int i=0;i<argc;i++) {
		if (strcmp(argv[i],"-l") == 0) {
			if (i + 1 < argc) {
				bind_interface = argv[i+1];
			}
		}
	}
	//init random seed (for random packet id)
	srand(time(NULL));
	//init sighandler to avoid unuseable fd after close
	signal(SIGINT,(__sighandler_t)sigint_handler);
	//init socket
	sock_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_ALL));
	struct sockaddr_ll sll;
	memset(&sll,0,sizeof(sll));
	sll.sll_family = AF_PACKET;
	struct ifreq ifstruct;
	strcpy(ifstruct.ifr_name,bind_interface);
	//get ip addr for this interface
	ifstruct.ifr_addr.sa_family = AF_INET;
	if (ioctl(sock_fd,SIOCGIFADDR,&ifstruct) == 0) {
		memcpy(&myip,&(((struct sockaddr_in *)&ifstruct.ifr_addr)->sin_addr),sizeof(myip));
		printf("local ip: %s\n",inet_ntoa(myip));
	}
	else {
		perror("can't get ip address");
		exit(1);
	}
	//get mac addr for this interface
	if (ioctl(sock_fd,SIOCGIFHWADDR,&ifstruct) == 0) {
		memcpy(mymac,&ifstruct.ifr_addr.sa_data,sizeof(mymac));
		printf("mac addr: ");
		print_mac_addr(mymac);
		/*
			use different mac_addr is ok, 
			but some virtual machines will
			filter mac address by default,
			so the frame will be drop.

			For Hyper-V, you should open 
			"MAC Address Spoofing".
		*/
	}
	//get interface index
	if (ioctl(sock_fd,SIOCGIFINDEX,&ifstruct) == 0) {
		sll.sll_ifindex = ifstruct.ifr_ifindex;
		sll.sll_protocol = htons(ETH_P_ALL);
	}
	else {
		perror("can't get interface index");
		exit(1);
	}
	//bind raw socket
	if (bind(sock_fd,(struct sockaddr *)&sll,sizeof(sll)) == -1) {
		perror("bind error! Are you root?\n");
		exit(1);
	}
	//send test
	init_test_udp_payload();
	send_udp("172.17.0.2",2333,2333,test_udp_payload,3000);//you can change it
	//please see tcpdump or wireshark
	//test udp application on remote host: socat - udp-listen:2333,fork
	unsigned char buf[buf_sz];
	ssize_t sz;
	while ((sz = recv(sock_fd,buf,buf_sz,0)) > 0) {
		recv_eth(buf,sz);
	}
	return 0;
}
