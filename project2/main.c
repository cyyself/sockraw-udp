#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>

const char* bind_interface = "ens33";

int main() {
	int sock_fd = socket(PF_PACKET,SOCK_RAW,htons(ETH_P_IP));
	struct sockaddr_ll sll;
	memset(&sll,0,sizeof(sll));
	sll.sll_family = AF_PACKET;
	struct ifreq ifstruct;
	strcpy(ifstruct.ifr_name,bind_interface);
	ioctl(sock_fd,SIOCGIFINDEX,&ifstruct);
	sll.sll_ifindex = ifstruct.ifr_ifindex;
	sll.sll_protocol = htons(ETH_P_ALL);
	int fd;
	if(bind(sock_fd,(struct sockaddr *) &sll,sizeof(sll)) == -1) {
		perror("bind error");
		printf("This program need running on root user\n");
		exit(1);
	}
	const int buf_sz = 65536;
	char buf[buf_sz];
	ssize_t sz;
	while ((sz = recv(sock_fd,buf,buf_sz,0)) > 0) {
		printf("%d:",sz);
		for (int i=0;i<sz;i++) printf("%02x",buf[i]);
		printf("\n");
	}
	//TODO: pack/unpack IP packet and IP fragment
	return 0;
}
