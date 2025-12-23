#include <stdio.h>
#include <pcap.h>

#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

void handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
    struct ether_header* ethHeader = (struct ether_header*) packet;
    uint16_t frameType = ntohs(ethHeader->ether_type);
    switch(frameType){
        case ETHERTYPE_IP:
            printf("IP packet\n");
            break;
        case ETHERTYPE_ARP:
            printf("ARP packet\n");
            break;
        case ETHERTYPE_REVARP:
            printf("Reverse ARP packet\n");
            break;
        default:
            printf("Unknown packet\n");
            break;
    }

    printf("\tHeader length: %d\n", header->len);
    printf("\tDestination: %2X:%02X:%02X:%02X:%02X:%02X\n", ethHeader->ether_dhost[0], ethHeader->ether_dhost[1], ethHeader->ether_dhost[2],
                                                            ethHeader->ether_dhost[3], ethHeader->ether_dhost[4], ethHeader->ether_dhost[5]);
    printf("\tSource: %02X:%02X:%02X:%02X:%02X:%02X\n", ethHeader->ether_shost[0], ethHeader->ether_shost[1], ethHeader->ether_shost[2],
                                                            ethHeader->ether_shost[3], ethHeader->ether_shost[4], ethHeader->ether_shost[5]);
}

int main(){
    char* device;
    char error_buff[PCAP_ERRBUF_SIZE];

    device = pcap_lookupdev(error_buff);
    if(!device) return 1;
    printf("Using network device: %s\n", device);

    pcap_t* handle;
    handle = pcap_open_live(device, BUFSIZ, 0, 10000, error_buff);

    if(!handle) {
        printf("Error: %s\n", error_buff);
        return 1;
    }

    pcap_loop(handle, 0, handler, NULL);
}
