#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include "pcap.h"
#include "time.h"

FILE* out;

/* 4 bytes IP address */
typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct mac_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac_address;

typedef struct mac_type
{
	u_char byte1;
	u_char byte2;
}mac_type;

typedef struct mac_header
{
	mac_address daddr;
	mac_address saddr;
	mac_type type;
}mac_header;

/* IPv4 header */
typedef struct ip_header
{
	u_char	ver_ihl;		// Version (4 bits) + Internet header length (4 bits)
	u_char	tos;			// Type of service 
	u_short tlen;			// Total length 
	u_short identification; // Identification
	u_short flags_fo;		// Flags (3 bits) + Fragment offset (13 bits)
	u_char	ttl;			// Time to live
	u_char	proto;			// Protocol
	u_short crc;			// Header checksum
	ip_address	saddr;		// Source address
	ip_address	daddr;		// Destination address
	u_int	op_pad;			// Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header
{
	u_short sport;			// Source port
	u_short dport;			// Destination port
	u_short len;			// Datagram length
	u_short crc;			// Checksum
}udp_header;

/* prototype of the packet handler */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);


int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "ip and udp";
	struct bpf_program fcode;

	out = fopen("C://Downloads//task3.csv", "w");
	fprintf(out, "时间,源 MAC,源 IP,目标 MAC,目标 IP,登录名,口令,成功与否\n");

	/* Open the capture file */
	if ((adhandle = pcap_open_offline("C://Downloads//ftp.pcap",			// name of the device
		errbuf					// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the file.\n");
		return -1;
	}

	/* read and dispatch packets until EOF is reached */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	pcap_close(adhandle);
	fclose(out);
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[25];
	ip_header* ih;
	mac_header* mh;
	udp_header* uh;
	u_int ip_len;
	time_t local_tv_sec;
	char* data;
	char string[500];
	int i = 0;

	/*
	 * unused parameter
	 */
	(VOID)(param);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);

	/* print timestamp and length of the packet */
	fprintf(out, "%s,", timestr);

	/* retireve the position of the ip header */
	ih = (ip_header*)(pkt_data +
		14); //length of ethernet header

	mh = (mac_header*)(pkt_data);

	data = (char*)(pkt_data + 54);

	/* retireve the position of the udp header */
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header*)((u_char*)ih + ip_len);

	fprintf(out, "%x:%x:%x:%x:%x:%x,",
		mh->saddr.byte1,
		mh->saddr.byte2,
		mh->saddr.byte3,
		mh->saddr.byte4,
		mh->saddr.byte5,
		mh->saddr.byte6);

	/* print ip addresses and udp ports */
	fprintf(out, "%d.%d.%d.%d,",
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4);

	fprintf(out, "%x:%x:%x:%x:%x:%x,",
		mh->daddr.byte1,
		mh->daddr.byte2,
		mh->daddr.byte3,
		mh->daddr.byte4,
		mh->daddr.byte5,
		mh->daddr.byte6);

	fprintf(out, "%d.%d.%d.%d,",
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4);
	
	if (*data == 'U' && *(++data) == 'S' && *(++data) == 'E' && *(++data) == 'R') {
		while (*(++data) != 0x0d)  string[i++] = *data;
		string[i] = '\0';
		fprintf(out,"%s,/,/\n", string);
		return;
	}

	data = (char*)(pkt_data + 54);
	if (*data == 'P' && *(++data) == 'A' && *(++data) == 'S' && *(++data) == 'S') {
		while (*(++data) != 0x0d)  string[i++] = *data;
		string[i] = '\0';
		fprintf(out, "/,%s,/\n", string);
		return;
	}

	data = (char*)(pkt_data + 54);
	if (*data == '5' && *(++data) == '3' ) {
		fprintf(out, "/,/,FAILED\n");
		return;
	}

	data = (char*)(pkt_data + 54);
	if (*data == '2' && *(++data) == '3') {
		fprintf(out, "/,/,SUCCEED\n");
		return;
	}
	fprintf(out, "/,/,/\n");
}
