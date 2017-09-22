#include <stdio.h>
#include <pcap.h>

int main(int argc, char **argv)
{
	/*
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	
	// setting the device
	dev = pcap_lookupdev(errbuf);

	if(dev == NULL)
	{
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
	}
	printf("Device: %s\n", dev);
	*/

	pcap_t *handle;
	char *dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char filter_exp[] = "port 80";
	bpf_u_int32 mask;
	bpf_u_int32 net;
	struct pcap_pkthdr header;
	const u_char *packet;

	dev = pcap_lookupdev(errbuf);
	if(pcap_lookupnet(dev, &net,&mask, errbuf) == -1)
	{
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	// opening the device for sniffing
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL)
	{
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}
	
	// check type of link-layer header,
	// and later it will be used for processing the packet contents
	/*
	if(pcap_datalink(handle) != DLT_EN10MB)
	{
		fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported\n", dev);
		return(2);
	}
	*/

	// compile the filter and apply the filter
	if(pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
	{
		fprintf(stderr,"Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}
	if(pcap_setfilter(handle, &fp) == -1)
	{
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	}

	packet = pcap_next(handle, &header);

	printf("Jacked a packet with length of [%d]\n", header.len);
	pcap_close(handle);
	return(0);
}
