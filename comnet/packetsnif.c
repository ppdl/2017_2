#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <arpa/inet.h>

#define BUFSIZE 16*1024
#define ETHER_HL 14		//length of Ethernet header
//position offset
#define IP_VER_IHL 0
#define IP_PTYPE 9		
#define IP_S_IP 12
#define IP_D_IP 16
#define TCP_S_PORT 0
#define TCP_D_PORT 2
#define TCP_THL 12

int count = 0;

void myfunc(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct in_addr src_ip, dst_ip;
	u_short src_port, dst_port;
	u_char ip_vhl, tcp_thl;
	unsigned int size_ip, size_tcp;

	u_char ptype;
	char src[50];
	char dst[50];

	// get size of IP header
	ip_vhl = *((u_char*)(packet + ETHER_HL + IP_VER_IHL));
	size_ip = (int)(ip_vhl & 0x0f) * 4;
	// get source and destination IP address
	src_ip = *((struct in_addr*)(packet + ETHER_HL + IP_S_IP));
	dst_ip = *((struct in_addr*)(packet + ETHER_HL + IP_D_IP));
	strcpy(src, inet_ntoa(src_ip));
	strcpy(dst, inet_ntoa(dst_ip));
	// get 4th layer protocol type
	ptype = *((u_char*)(packet + ETHER_HL + IP_PTYPE));
	// get size of TCP header
	tcp_thl = *((u_char*)(packet + ETHER_HL + size_ip + TCP_THL));
	size_tcp = (int)((tcp_thl & 0xf0) >> 4) * 4;
	// get source and destination port number
	src_port = *((u_short*)(packet + ETHER_HL + size_ip + TCP_S_PORT));
	dst_port = *((u_short*)(packet + ETHER_HL + size_ip + TCP_D_PORT));
	src_port = ((src_port & 0x00ff) << 8) |((src_port & 0xff00) >> 8);
	dst_port = ((dst_port & 0x00ff) << 8) |((dst_port & 0xff00) >> 8);
	
	// http packet 
	char *data = (char *)(packet + ETHER_HL + size_ip + size_tcp);	

	// too small packet. so return. 
	if(header->len < ETHER_HL + size_ip + size_tcp + 16)
		return;
	//Http analize
	int seperate;// 0-->no header, 1-->response, 2-->request, 3-->POST
	// request
	if(*data =='O'&&*(data+1)=='P'&&*(data+2)=='T'&&*(data+3)=='I'&&*(data+4)=='O'&&*(data+5)=='N'&&*(data+6)=='S'&&*(data+7)==' '&&*(data+8)=='/') seperate = 2;
	else if(*data =='G'&&*(data+1)=='E'&&*(data+2)=='T'&&*(data+3)==' '&&*(data+4)=='/') seperate = 2;
	else if(*data =='H'&&*(data+1)=='E'&&*(data+2)=='A'&&*(data+3)=='D'&&*(data+4)==' '&&*(data+5)=='/') seperate = 2;
	else if(*data =='P'&&*(data+1)=='O'&&*(data+2)=='S'&&*(data+3)=='T'&&*(data+4)==' '&&*(data+5)=='/') seperate = 3; // post method
	else if(*data =='P'&&*(data+1)=='U'&&*(data+2)=='T'&&*(data+3)==' '&&*(data+4)=='/') seperate = 2;
	else if(*data =='D'&&*(data+1)=='E'&&*(data+2)=='L'&&*(data+3)=='E'&&*(data+4)=='T'&&*(data+5)=='E'&&*(data+6)==' '&&*(data+7)=='/') seperate = 2;
	else if(*data =='T'&&*(data+1)=='R'&&*(data+2)=='A'&&*(data+3)=='C'&&*(data+4)=='E'&&*(data+5)==' '&&*(data+6)=='/') seperate = 2;
	else if(*data =='C'&&*(data+1)=='O'&&*(data+2)=='N'&&*(data+3)=='N'&&*(data+4)=='E'&&*(data+5)=='C'&&*(data+6)=='T'&&*(data+7)==' '&&*(data+8)=='/') seperate = 2;
	else if(*data =='P'&&*(data+1)=='A'&&*(data+2)=='T'&&*(data+3)=='C'&&*(data+4)=='H'&&*(data+5)==' '&&*(data+6)=='/') seperate = 2;
	// response
	else if(*data =='H'&&*(data+1)=='T'&&*(data+2)=='T'&&*(data+3)=='P'&&*(data+4)=='/'&&*(data+5)=='1'&&*(data+6)=='.') seperate = 1;
	// no
	else return;

	// print basic information
	printf("%d ",++count);
	printf("%s:%hu %s:%hu HTTP ", src,src_port, dst,dst_port);
	if(seperate==1) printf("Response\n");
	else printf("Request\n");
	
	// print http header 
	char pp='T',p='T';
	for(data=(char*)(packet+ETHER_HL+size_ip+size_tcp);!(*data=='\r'&&pp=='\r'&&p=='\n');data++)
	{
		printf("%c",*data);
		pp = p;
		p = *data;
	}
	
	// POST
	if(seperate == 3){
		data +=2;
		char path[100];
		sprintf(path,"post/%d.txt",count);
		FILE *fout = fopen(path,"w");
		for(;data != (char*)(packet+header->len);data++)
			fprintf(fout,"%c",*data);
		fclose(fout);
	}

//	printf("\ntotal len:%d Ether:14 IP:%d TCP:%d",header->len,size_ip,size_tcp);
	printf("\n\n");
}

int main(int argc, char *argv[]) {
 	pcap_if_t *alldev;
	char *dev=NULL;    
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle;
	struct bpf_program fp;
	char filter_exp[]="port 80";// only http protocol
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;

    // get network device
/*	pcap_findalldevs(&alldev,errbuf);
	for(;alldev != NULL;alldev = alldev->next){
		if((alldev->addresses != NULL)&&((alldev->flags & PCAP_IF_LOOPBACK)==0))
		{
			dev = alldev->name;
			break;
		}
	}
*/
    dev = pcap_lookupdev(errbuf);
    if(dev == NULL)
    {
        printf("Couldn't find default device: %s\n",errbuf);
        return -1;
    }
	printf("dev: %s\n",dev);
	
	// Find the properties for the device 
	if(pcap_lookupnet(dev,&net,&mask,errbuf)==-1){
		printf("Can't get netmask for device %s\n",dev);
		net=0;
		mask=0;
	}

	// Open the session in promiscuous mode
	handle = pcap_open_live(dev, BUFSIZE, 1,1000,errbuf);
	if(handle == NULL){
		printf("Coudln't open device %s: %s\n",dev,errbuf);
		return -1;
	}
	
	// Compile and apply the filter
	if(pcap_compile(handle,&fp,filter_exp,0,net)==-1){
		printf("Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
		return -1;
	}
	if(pcap_setfilter(handle,&fp)==-1) {
		printf("Couldn't install filter %s: %s\n", filter_exp,pcap_geterr(handle));
		return -1;
	}
	
	// sniffing
	pcap_loop(handle,-1,myfunc,NULL);	

	return 0;
}
