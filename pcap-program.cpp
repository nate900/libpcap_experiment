

#include <stdio.h>
#include <pcap.h>
int main(int argc, char *argv[])
{
	//1. start by getting a device interface to read packets from
	// two ways to do this. One way is to accept arguments from the command line from the user.
	// the other way is to use the findalldevs(*pcap_if_t, *char) module to return all devices that are on this system
	// the latter is the way we are going to do this.
	char *dev, errbuf[PCAP_ERRBUF_SIZE]; // define a string to hold the device name and error buffer string of a constant size

	// the purpose of the errbuf variable string is to pass it into libpcap modules. If something goes wrong in the modules, then the errbuf string will be populated with an error message

	pcap_if_t *all_devs; // declare a pcap_if_t variable to store all devices. The returned list is a list of type pcap_if_t but contains strings and are referenced all_devs->name

	if(pcap_findalldevs(&all_devs, errbuf) == -1){ // this will return all devices on this computer
		printf("This did not work, abort");
		return(-1);
	}
	
	// get the properties of our device

	bpf_u_int32 mask;
	bpf_u_int32 net;

	
	if(pcap_lookupnet(dev, &net, &mask, errbuf)){
		fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
		return(2);
	}


	// pcap_if_t *next_dev = all_devs; // iterate over this array of pcap_if_t and print all the devices that were returned
	// while(next_dev != NULL){
	// 	printf("Device: %s\n",next_dev->name);
	// 	next_dev = next_dev->next;
	// }

	//2. open the device for sniffing
	// pcap_t *pcap_open_live(char *device, int snaplen, int promisc, int to_ms, char *ebuf)
	/*
		returns a potiner of type pcap_t. The arguments are as follows: char *device is a string that represents the device we are sniffing
		int snaplen is the maximum number of bytes to be captured by pcap.
		int promisc is an integer that you pass into the function to specify whether you are sniffing in promiscuous or non-promiscuous mode
		int to_ms is the read timeout in milliseconds.
		char *ebuf is a string that will write any errors, just like in the above code we pass in "errbuf."
	*/

	// open session in promiscuous mode
	pcap_t *handle;

	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return(2);
	}

	// grab a packet
	struct pcap_pkthdr header;
	
	const u_char *packet;

	packet = pcap_next(handle, &header);

	printf("Jacked a packet with length of [%d]\n", header.len);

	// close the session

	/* cleanup */
	//pcap_freecode(&fp);
	pcap_close(handle);

	printf("\nCapture complete.\n");
/*
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return(2);
	}
*/
	return(0);
}
