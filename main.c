#include <stdio.h>
#include <pcap.h>

#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

char* device; //, *defaultGW;
uint32_t gateway_net;

void getDG(uint32_t* res){
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return; // NULL;
    char line[256]; //char* res = NULL;

    fgets(line, sizeof(line), f);
    while(fgets(line, sizeof(line), f)){
        char interface[32]; unsigned long destination, gateway;

        if(sscanf(line, "%31s %lx %lx", interface, &destination, &gateway) != 3) continue;
        
        if(strcmp(device, interface) == 0 && destination == 0){ //!(strcmp(device, interface) || destination)){
            *res = htonl(gateway);
            //res = malloc(INET_ADDRSTRLEN);
            // struct in_addr dg;
            // dg.s_addr = htonl(gateway); //gateway;
            // strncpy(res, inet_ntoa(dg), INET_ADDRSTRLEN);
            // res[INET_ADDRSTRLEN-1] = '\0';
            //inet_ntop(AF_INET, &dg, res, INET_ADDRSTRLEN);
            break;
        }
    }

    fclose(f);
    //return res;
}

void handler(u_char* args, const struct pcap_pkthdr* header, const u_char* packet){
    struct ether_header* ethHeader = (struct ether_header*) packet;
    uint16_t frameType = ntohs(ethHeader->ether_type);
    switch(frameType){
        case ETHERTYPE_IP:
            printf("IP packet\n");
            break;
        case ETHERTYPE_ARP:
            printf("ARP packet\n");
            if (header->len < sizeof(struct ether_header) + 28) return;

            const u_char* arpHeader = packet + sizeof(struct ether_header);

            uint16_t* hardwareType = arpHeader;
            uint16_t* protoType = arpHeader + 2;
            uint16_t* lengths = arpHeader + 4;
            uint16_t* op = arpHeader + 6;

            if (ntohs(*hardwareType) != ARPHRD_ETHER || ntohs(*protoType) != ETHERTYPE_IP) return;

            uint8_t* senderMAC = arpHeader + 8;
            uint8_t* senderIP = arpHeader + 14;
            uint8_t* targetMAC = arpHeader + 18;
            uint8_t* targetIP = arpHeader + 24;

            struct in_addr arp_sender_addr;
            memcpy(&arp_sender_addr.s_addr, senderIP, 4);

            if (arp_sender_addr.s_addr == gateway_net){
                printf("[ALERT][ARP] Gateway MAC address is changed");
            }

            printf("\tOperation: %s\n", ((ntohs(*op) == ARPOP_REQUEST) ? "request" : "reply"));
            printf("\tSender hardware address: %2X:%02X:%02X:%02X:%02X:%02X\n", senderMAC[0], senderMAC[1], senderMAC[2],
                                                            senderMAC[3], senderMAC[4], senderMAC[5]);
            printf("\tTarget hardware address: %02X:%02X:%02X:%02X:%02X:%02X\n", targetMAC[0], targetMAC[1], targetMAC[2],
                                                            targetMAC[3], targetMAC[4], targetMAC[5]);
            printf("\tSender protocol address: %d.%d.%d.%d\n", senderIP[0], senderIP[1], senderIP[2], senderIP[3]);
            printf("\tTarget protocol address: %d.%d.%d.%d\n", targetIP[0], targetIP[1], targetIP[2], targetIP[3]);
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
    // char* device;
    char error_buff[PCAP_ERRBUF_SIZE];
    // defaultGW = malloc(INET_ADDRSTRLEN);

    device = pcap_lookupdev(error_buff);
    if(!device) return 1;
    printf("Using network device: %s\n", device);

    getDG(&gateway_net);
    // printf("Default gateway: %s\n", defaultGW);

    pcap_t* handle;
    handle = pcap_open_live(device, BUFSIZ, 0, 10000, error_buff);

    if(!handle) {
        printf("Error: %s\n", error_buff);
        return 1;
    }

    pcap_loop(handle, 0, handler, NULL);
}
