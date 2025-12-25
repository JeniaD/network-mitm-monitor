#include <stdio.h>
#include <pcap.h>

#include <time.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <stdlib.h>
#include <string.h>

#include <arpa/inet.h>

char* device; //, *defaultGW;
uint32_t gateway_net = NULL;
uint8_t gateway_mac[6];
uint8_t gatewayTTL = 0;
int gwKnown = 0;

void getDG(uint32_t* res){
    FILE *f = fopen("/proc/net/route", "r");
    if (!f) return; // NULL;
    char line[256]; //char* res = NULL;

    fgets(line, sizeof(line), f);
    while(fgets(line, sizeof(line), f)){
        char interface[32]; unsigned long destination, gateway;

        if(sscanf(line, "%31s %lx %lx", interface, &destination, &gateway) != 3) continue;
        
        if(strcmp(device, interface) == 0 && destination == 0){ //!(strcmp(device, interface) || destination)){
            *res = gateway; //htonl(gateway);
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
            // Check DHCP and DNS packets here
            printf("IP packet\n");
            const u_char* ipHeader = packet + sizeof(struct ether_header);

            uint8_t version = ipHeader[0] >> 4;
            uint8_t ihl = (ipHeader[0] & 0x0F) * 4;

            if (version != 4) return; // ignore IPv6
            if (header->len < sizeof(struct ether_header) + ihl + 8) return;

            uint8_t* ttl = ipHeader + 8;
            uint8_t* sourceIP = ipHeader + 12;
            uint32_t gateway_net_be = htonl(gateway_net); // quick fix
            if(gwKnown && !memcmp(ethHeader->ether_shost, gateway_mac, 6) && !memcmp(sourceIP, &gateway_net_be, 4)) {
                if(gatewayTTL <= 0) gatewayTTL = *ttl;
                else if(*ttl != gatewayTTL){//memcmp(ttl, &gatewayTTL, 1)){
                    gatewayTTL = *ttl;
                    printf("[ALERT] TTL value from gateway changed");
                }
            }

            // should check here if its IPv4
            // and continue to DNS and DHCP
            
            if (ipHeader[9] != IPPROTO_UDP) return;
            const uint8_t *udp = ipHeader + ihl;

            uint16_t src_port = ntohs(*(uint16_t*)udp);
            uint16_t dst_port = ntohs(*(uint16_t*)(udp + 2));

            if(gwKnown){
                // DNS
                if (src_port == 53)
                    if (memcmp(ethHeader->ether_shost, gateway_mac, 6) != 0){
                        printf("[ALERT][DNS] Rogue DNS detected\n");
                        printf("Gateway MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                            gateway_mac[0], gateway_mac[1], gateway_mac[2],
                            gateway_mac[3], gateway_mac[4], gateway_mac[5]);
                        printf("ETH header MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                            ethHeader->ether_shost[0], ethHeader->ether_shost[1], ethHeader->ether_shost[2],
                            ethHeader->ether_shost[3], ethHeader->ether_shost[4], ethHeader->ether_shost[5]);
                    }

                // DHCP
                if ((src_port == 67 && dst_port == 68) || (src_port == 68 && dst_port == 67))
                    if (memcmp(ethHeader->ether_shost, gateway_mac, 6) != 0)
                        printf("[ALERT][DHCP] Rogue DHCP detected\n");
            }

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

            if (memcmp(senderMAC, ethHeader->ether_shost, 6) != 0) {
                printf("[ALERT] ARP/Ethernet MAC mismatch\n");
            }

            if (arp_sender_addr.s_addr == gateway_net){
                printf("[ARP] Received gateway MAC address\n");
                if(!gwKnown){
                    memcpy(gateway_mac, ethHeader->ether_shost, 6);
                    // gateway_mac = *(uint_t*)ethHeader->ether_shost;
                    gwKnown = 1;
                }
                else if(memcmp(gateway_mac, ethHeader->ether_shost, 6)) {
                    printf("[ALERT] Gateway MAC address changed");

                    printf("Old MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                        gateway_mac[0], gateway_mac[1], gateway_mac[2],
                        gateway_mac[3], gateway_mac[4], gateway_mac[5]);

                    printf("New MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                        ethHeader->ether_shost[0], ethHeader->ether_shost[1],
                        ethHeader->ether_shost[2], ethHeader->ether_shost[3],
                        ethHeader->ether_shost[4], ethHeader->ether_shost[5]);  

                    memcpy(gateway_mac, ethHeader->ether_shost, 6);
                    // gateway_mac = *(uint64_t*)ethHeader->ether_shost;
                }
            }

            printf("\tOperation: %s\n", ((ntohs(*op) == ARPOP_REQUEST) ? "request" : "reply"));
            printf("\tSender hardware address: %02X:%02X:%02X:%02X:%02X:%02X\n", senderMAC[0], senderMAC[1], senderMAC[2],
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

    // printf("\tHeader length: %d\n", header->len);
    // printf("\tDestination: %2X:%02X:%02X:%02X:%02X:%02X\n", ethHeader->ether_dhost[0], ethHeader->ether_dhost[1], ethHeader->ether_dhost[2],
    //                                                         ethHeader->ether_dhost[3], ethHeader->ether_dhost[4], ethHeader->ether_dhost[5]);
    // printf("\tSource: %02X:%02X:%02X:%02X:%02X:%02X\n", ethHeader->ether_shost[0], ethHeader->ether_shost[1], ethHeader->ether_shost[2],
    //                                                         ethHeader->ether_shost[3], ethHeader->ether_shost[4], ethHeader->ether_shost[5]);
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
