#include <net/if.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <pcap.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

struct arp_packet
{
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	uint16_t ether_type; /* IP? ARP? RARP? etc */
	uint16_t ar_hrd;		/* Format of hardware address.  */
	uint16_t ar_pro;		/* Format of protocol address.  */
 	u_char ar_hln;		/* Length of hardware address.  */
  	u_char ar_pln;		/* Length of protocol address.  */
 	uint16_t ar_op;		/* ARP opcode (command).  */
	u_char __ar_sha[ETH_ALEN];	/* Sender hardware address.  */
	u_char __ar_sip[4];		/* Sender IP address.  */
	u_char __ar_tha[ETH_ALEN];	/* Target hardware address.  */
	u_char __ar_tip[4];		/* Target IP address.  */
};
