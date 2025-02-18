#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

#define P_UNKNOWN -1
#define P_TCP 1
#define P_UDP 2

pcap_t* interupt_handler; // Handler for Ctrl+C
FILE* log_file = NULL;

typedef struct {
    int packets_count;       // Total packets received
    int tcp_count;           // Total TCP packets received
    int udp_count;           // Total UDP packets received
    long tcp_bytes;          // Total bytes of TCP packets received
    long udp_bytes;          // Total bytes of UDP packets received
} Statistics;

typedef struct {
    uint32_t src_ip;         // Source IP address
    uint32_t dest_ip;        // Destination IP address
    uint16_t src_port;       // Source port
    uint16_t dest_port;      // Destination port
    uint16_t header_len;     // Header length in bytes
    uint16_t payload_len;    // Payload length in bytes
} PacketInfo;

void print_usage();
void online_capturing(char*, char*);
void offline_capturing(char*, char*);
void write_packet_data(u_char*, const struct pcap_pkthdr*, const u_char*);
void signal_handler(int signal);
int find_packet_type(const u_char*);
int apply_filter(const char*, const PacketInfo*);

int find_packet_type(const u_char *packet) {
    uint16_t ethertype = (packet[12] << 8) | packet[13];

    if (ethertype == 0x0800) { // IPv4
        uint8_t protocol_IPv4 = packet[23];
        if (protocol_IPv4 == 6) return P_TCP;
        if (protocol_IPv4 == 17) return P_UDP;
    } else if (ethertype == 0x86DD) { // IPv6
        uint8_t protocol_IPv6 = packet[20];
        if (protocol_IPv6 == 6) return P_TCP;
        if (protocol_IPv6 == 17) return P_UDP;
    }
    return P_UNKNOWN;
}

int apply_filter(const char *filter, const PacketInfo *info) {
    if (!filter) return 1; // No filter, accept all packets.

    // Check for port filtering
    if (strstr(filter, "port")) {
        int port = atoi(filter + strlen("port "));
        if (info->src_port == port || info->dest_port == port) {
            return 1;
        }
    }

    // Check for source IP filtering
    if (strstr(filter, "src ip")) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(info->src_ip), ip_str, INET_ADDRSTRLEN);
        if (strcmp(ip_str, filter + strlen("src ip ")) == 0) {
            return 1;
        }
    }

    // Check for destination IP filtering
    if (strstr(filter, "dst ip")) {
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &(info->dest_ip), ip_str, INET_ADDRSTRLEN);
        if (strcmp(ip_str, filter + strlen("dst ip ")) == 0) {
            return 1;
        }
    }

    return 0; // No match.
}

void write_packet_data(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    Statistics *stats = (Statistics *)args;
    PacketInfo info;
    memset(&info, 0, sizeof(PacketInfo));

    stats->packets_count++;

    int ptype = find_packet_type(packet);
    if (ptype != P_TCP && ptype != P_UDP) return; // Skip non-TCP/UDP packets.

    info.src_port = (packet[34] << 8) | packet[35];
    info.dest_port = (packet[36] << 8) | packet[37];
    info.src_ip = (packet[26] << 24) | (packet[27] << 16) | (packet[28] << 8) | packet[29];
    info.dest_ip = (packet[30] << 24) | (packet[31] << 16) | (packet[32] << 8) | packet[33];
    info.header_len = (packet[24] << 8) | packet[25];

    if (!apply_filter(NULL, &info)) return; // Apply filter if specified.

        if (ptype == P_TCP) {
        stats->tcp_count++;
        stats->tcp_bytes += header->len;
    } else if (ptype == P_UDP) {
        stats->udp_count++;
        stats->udp_bytes += header->len;
    }


    fprintf(log_file, "Packet:\n");
    fprintf(log_file, "Src IP: %u.%u.%u.%u, Src Port: %d\n",
            (info.src_ip >> 24) & 0xFF, (info.src_ip >> 16) & 0xFF, (info.src_ip >> 8) & 0xFF, info.src_ip & 0xFF, info.src_port);
    fprintf(log_file, "Dst IP: %u.%u.%u.%u, Dst Port: %d\n",
            (info.dest_ip >> 24) & 0xFF, (info.dest_ip >> 16) & 0xFF, (info.dest_ip >> 8) & 0xFF, info.dest_ip & 0xFF, info.dest_port);
    fprintf(log_file, "Protocol: %s, Header Length: %d\n", (ptype == P_TCP ? "TCP" : "UDP"), info.header_len);
    fprintf(log_file, "\n");
}

void online_capturing(char *interface, char *filter) {
    pcap_t *online_handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    Statistics stats = {0};

    online_handler = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
    if (!online_handler) {
        fprintf(stderr, "Error opening interface %s: %s\n", interface, errbuf);
        return;
    }

    log_file = fopen("log.txt", "w");
    if (!log_file) {
        fprintf(stderr, "Error opening log file.\n");
        pcap_close(online_handler);
        return;
    }

    interupt_handler = online_handler;
    signal(SIGINT, signal_handler);

    int packet_capture = pcap_loop(online_handler, 0, write_packet_data, (u_char*) &stats );
    if(packet_capture<0 && packet_capture!=-2){
        fprintf(stderr, "Error capturing packets\n");
    }


    fprintf(stderr, "Capture complete.\n");
    fprintf(stderr, "Statistics:\n");
    fprintf(stderr, "Total Packets: %d\n", stats.packets_count);
    fprintf(stderr, "TCP Packets: %d, TCP Bytes: %ld\n", stats.tcp_count, stats.tcp_bytes);
    fprintf(stderr, "UDP Packets: %d, UDP Bytes: %ld\n", stats.udp_count, stats.udp_bytes);

    fclose(log_file);
    pcap_close(online_handler);
}

void offline_capturing(char *file_name, char *filter) {
    pcap_t *offline_handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    Statistics stats = {0};

    offline_handler = pcap_open_offline(file_name, errbuf);
    if (!offline_handler) {
        fprintf(stderr, "Error opening file %s: %s\n", file_name, errbuf);
        return;
    }

    interupt_handler = offline_handler;
    signal(SIGINT, signal_handler);

    int packet_capture = pcap_loop(offline_handler, 0, write_packet_data, (u_char*) &stats );
    if(packet_capture<0 && packet_capture!=-2){
        fprintf(stderr, "Error capturing packets\n");
    }


    fprintf(stderr, "Capture complete.\n");
    fprintf(stderr, "Statistics:\n");
    fprintf(stderr, "Total Packets: %d\n", stats.packets_count);
    fprintf(stderr, "TCP Packets: %d, TCP Bytes: %ld\n", stats.tcp_count, stats.tcp_bytes);
    fprintf(stderr, "UDP Packets: %d, UDP Bytes: %ld\n", stats.udp_count, stats.udp_bytes);

    pcap_close(offline_handler);
}

void signal_handler(int signal) {
    pcap_breakloop(interupt_handler);
}

void print_usage() {
    printf("Options:\n");
    printf("  -i <interface>  Capture live packets from interface.\n");
    printf("  -r <file>       Read packets from a pcap file.\n");
    printf("  -f <filter>     Apply a manual filter expression.\n");
    printf("  -h              Display this help message.\n");
}

int main(int argc, char *argv[])
{
    char* interface= NULL;
    char* file_name= NULL;
    char* filter_expression= NULL;
    int opt;
    while ((opt = getopt(argc, argv, "i:r:f:h")) != -1) {
        switch (opt) {
            case 'i':
                interface = optarg;
                break;
            case 'r':
                file_name = optarg;
                break;
            case 'f':
                filter_expression = optarg;
                break;
            case 'h':
                print_usage();
                return 0;
            default:
                printf("Invalid option\n");
                print_usage();
                return 1;
        }
    }

    Statistics *stats = malloc(sizeof(Statistics));

    if(!interface && !file_name){
        printf("You have to specify an interface or a file_name\n");
        print_usage();
        return -1;
    }

    if(interface && file_name){
        printf("You can't specify both an interface and a file_name\n");
        print_usage();
        return 1;
    }

    if(interface){

        printf("Capturing packets on specified interface (%s)\n",interface);

        if(filter_expression){
            printf("Using the specified filter (%s)\n",filter_expression);
        }
        online_capturing(interface,filter_expression);
        
    }

    if(file_name){
        printf("Capturing packets on specified file (%s)\n",file_name);
        if(filter_expression){
            printf("Using the specified filter (%s)\n",filter_expression);
        }
        offline_capturing(file_name,filter_expression);
    }
    return 0;
}



