#include <stdio.h>
#include <string.h>
//typedef unsigned char mac_addr[6];
unsigned char my_mac[6] = {0x3b,0xaf,0x21,0x9e,0x5f,0x85};
unsigned int crc32(unsigned char *data,int len) {
	unsigned int crc = 0xFFFFFFFF;
	for (int i=0;i<len;i++) {
		crc = crc ^ data[i];
		for (int j=7;j>=0;j--) {
			crc = (crc >> 1) ^ (0xEDB88320 & (-(crc & 1)));
		}
	}
	return ~crc;
}
unsigned char buf[65536];
int mac_eq(unsigned char x[6],unsigned char y[6]) {
	for (int i=0;i<6;i++) if (x[i] != y[i]) return 0;
	return 1;
}
void output_mac(unsigned char x[6]) {
	for (int i=0;i<6;i++) {
		printf("%02x",x[i]);
		if (i != 5) printf(":");
	}
}
void welcome() {
	printf("[INFO] Receiver Start, mac_addr=");
	output_mac(my_mac);
	printf("\n");
}
int main() {
	FILE *in = fopen("1.bin","r");
	welcome();
	unsigned short frame_len;
	int seq = 0;
	while (fread(&frame_len,sizeof(frame_len),1,in)) {
		if (frame_len == 0) break;
		seq ++;
		//dst 6bytes、src 6 bytes、ether type 2 bytes、payload 46-1500 bytes、fcs 4 bytes
		fread(buf,sizeof(char),frame_len,in);
		if (frame_len < 64 || frame_len > 1518) {
			printf("[ERROR] eth_frame %d size %u error.\n",seq,frame_len);
			continue;
		}
		unsigned int crc32_result = crc32(buf,frame_len-4);
		unsigned char crc32_result_c[4];
		memcpy(crc32_result_c,&crc32_result,sizeof(crc32_result));
		if (
			crc32_result_c[3] != buf[frame_len-1] ||
			crc32_result_c[2] != buf[frame_len-2] ||
			crc32_result_c[1] != buf[frame_len-3] ||
			crc32_result_c[0] != buf[frame_len-4] 
			) {
			printf("[ERROR] eth_frame %d crc32 check failed.\n",seq);
			continue;
		}
		unsigned char dst_mac[6];
		memcpy(&dst_mac,&buf,6);
		unsigned char src_mac[6];
		memcpy(&src_mac,&buf[6],6);
		unsigned short protocol_type;
		memcpy(&protocol_type,&buf[12],2);
		unsigned char *payload = &buf[14];
		if (!mac_eq(dst_mac,my_mac)) {
			printf("[WARNING] eth_frame %d dst_mac=",seq);
			output_mac(dst_mac);
			printf(", expected ");
			output_mac(my_mac);
			printf(", so dropped.\n");
			continue;
		}
		printf("[INFO] eth_frame %d size %d ok.\n",seq,frame_len);
	}
	fclose(in);
	return 0;
}