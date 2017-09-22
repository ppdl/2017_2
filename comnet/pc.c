#include <pcap.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define SNAP_LEN 1518
#define SIZE_ETHERNET 14
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src,ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;
struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
		#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	static int count = 1;
	static int innercount = 0;

	const struct sniff_ethernet *ethernet;
	const struct sniff_ip *ip;
	const struct sniff_tcp *tcp;
	const char *payload;

	int size_ip;
	int size_tcp;
	int size_payload;

	ethernet = (struct sniff_ethernet*)(packet);

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if(size_ip < 20)
	{
		printf("	* Invalid IP header length: %u bytes\n", size_ip);
		return;
	}

	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
	size_tcp = TH_OFF(tcp)*4;
	if(size_tcp < 20)
	{
		//printf("	 * Invalid TCP header length: %u bytes\n", size_tcp);
		return;
	}

	
	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);
	if(size_payload <= 0) return;

	/* First word in the payload */
	char hc[10];
	for(int i=0; i<10; i++)
	{
		if(*(payload + i) == ' ')
		{
			hc[i] = '\0';
			break;
		}
		hc[i] = *(payload + i);
	}

	/* To find "HTTP" string at the front of the payload,
	 * seperate first 4 letter. */
	char http[5];
	strncpy(http, payload, 4);
	http[4] = '\0';

	/* Request */
	if(!strcmp(hc, "GET") || !strcmp(hc, "POST") || !strcmp(hc, "OPTIONS") || !strcmp(hc, "HEAD")

			|| !strcmp(hc, "PUT") || !strcmp(hc, "DELETE") || !strcmp(hc, "CONNECT") || !strcmp(hc, "TRACE"))
	{
		printf("%d %s:%d %s:%d HTTP Request\n", count, inet_ntoa(ip->ip_src), ntohs(tcp->th_sport),
			inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));

		/* set the end point of the http header */
		char *endpoint = strstr(payload, "\r\n\r\n");
		
		innercount = 0;


		/* print all characters in the header */
		while(payload != endpoint+4)
		{
		//	if(!(isprint(*payload) || *payload == '\r' || *payload == '\n')) break;
			printf("%c", *payload);
			payload++;
			innercount++;
			//if(innercount > 10000) break;
		}
		
		if(payload == endpoint+4) count++;
	}
	/* Response */
	else if(!strcmp(http, "HTTP"))
	{
		bool is_image_included = false;
		int http_hsize = 0;

		if(strstr(payload, "image/png") != NULL|| strstr(payload, "image/jpeg") != NULL || strstr(payload, "image/gif") != NULL
				|| strstr(payload, "image/jpg") != NULL || strstr(payload, "image/bmp") != NULL) is_image_included = true;
		printf("%d %s:%d %s:%d HTTP Response\n", count, inet_ntoa(ip->ip_src), ntohs(tcp->th_sport),
			inet_ntoa(ip->ip_dst), ntohs(tcp->th_dport));

		/* set the end point of the http header */
		char *endpoint = strstr(payload, "\r\n\r\n");
		/* print all characters in the header */


		innercount = 0;


		if(endpoint != NULL)
		{
			while(payload != endpoint+4)
			{
				//if(!(isprint(*payload) || *payload == '\r' || *payload == '\n')) break;
				if(*payload >= 0 && *payload <128)
					printf("%c", *payload);
				payload++;
				http_hsize++;
				innercount++;
				//if(innercount > 10000) break;
			}
		}

		if(payload == endpoint+4) count++;
		if(is_image_included)
		{
			printf("Image included\n");
			FILE *out;
			char *img;
			int i=0;
			printf("payload size: %d, httpheader size: %d\n", size_payload, http_hsize);
			img = (char*)calloc(size_payload-http_hsize, sizeof(char));
			printf("calloced size: %d\n", size_payload-http_hsize);
			for(int i=0; i<size_payload-http_hsize; i++)
			{
				img[i] = *payload;
				printf("%x ", *payload);
				if(i%16 == 1) printf("\n");
				if(i>100) break;
			}
			out = fopen("output.jpeg", "wb");
			printf("IMAGE SAVING...\n");
			fwrite(img, sizeof(char), sizeof(img)/sizeof(char), out);
			fclose(out);
			free(img);
			
		}
	}

	return;
}


int main(int argc, char **argv)
{
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;

	char filter_exp[] = "ip";
	struct bpf_program fp;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	int num_packets = -1;	/* number of packets to capture */

	if(argc == 2)
	{
		dev = argv[1];
	}
	else if(argc > 2)
	{
		fprintf(stderr, " error: unrecognized command-line options\n\n");
		exit(EXIT_FAILURE);
	}
	else
	{
		dev = pcap_lookupdev(errbuf);
		if(dev == NULL)
		{
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}

	if(pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
	{
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		net = 0;
		mask = 0;
	}
	printf("Device: %s\n", dev);
	printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", filter_exp);

	handle = pcap_open_live(dev, SNAP_LEN, 0, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	}
	if(pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "%s is not an Etherenet\n", dev);
		exit(EXIT_FAILURE);
	}
	if(pcap_compile(handle, &fp, "tcp port 80", 0, net) == -1)
	{
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}
	if(pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	pcap_loop(handle, num_packets, got_packet, NULL);

	pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");
	return 0;
}

