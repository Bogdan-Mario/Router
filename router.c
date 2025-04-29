#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "queue.h"
#include "lib.h"
#include "protocols.h"

/* Network protocol identifiers */
#define ETH_IPV4 0x0800
#define ETH_ARP  0x0806
#define IP_ICMP  1

/* ARP operation codes */
#define ARP_QUERY  1
#define ARP_RESPONSE 2

/* Hardware and protocol specifications */
#define HW_ETHERNET 1
#define MAC_BYTES 6
#define IPV4_BYTES 4

/* ICMP message types */
#define ICMP_ECHO_RESPONSE 0
#define ICMP_ECHO_CALL 8
#define ICMP_TTL_EXPIRED 11
#define ICMP_NET_UNREACHABLE 3

/* Default network values */
#define DEFAULT_HOP_LIMIT 64
#define MAX_PENDING_PKTS 9999
#define INIT_ARP_CAPACITY 999999
#define INIT_RT_CAPACITY 100000

/* Network tables */
struct route_table_entry *route_table;
int route_count;
struct arp_table_entry *arp_cache;
int arp_count;
queue pending_queue;

/* Binary routing structure */
typedef struct route_node {
    struct route_table_entry *rt_entry;
    struct route_node *next[2];
} route_node;

/* Packet awaiting ARP resolution */
typedef struct deferred_pkt {
    uint32_t target_ip;
    int if_index;
    char *pkt_data;
    size_t pkt_len;
} deferred_pkt;

/* Protocol type identification */
int get_protocol_type(uint16_t eth_type) {
    if (eth_type == ETH_IPV4) return 0;
    if (eth_type == ETH_ARP) return 1;
    return -1;
}

/* ARP packet configuration */
void config_arp(struct arp_hdr *arp_pkt, int op, 
               uint32_t src_ip, uint32_t dst_ip,
               int if_idx, uint8_t *dst_mac) {
    arp_pkt->hw_type = htons(HW_ETHERNET);
    arp_pkt->proto_type = htons(ETH_IPV4);
    arp_pkt->hw_len = MAC_BYTES;
    arp_pkt->proto_len = IPV4_BYTES;
    arp_pkt->opcode = htons(op);
    get_interface_mac(if_idx, arp_pkt->shwa);
    memcpy(arp_pkt->thwa, dst_mac, MAC_BYTES);
    arp_pkt->sprotoa = src_ip;
    arp_pkt->tprotoa = dst_ip;
}

/* Ethernet frame setup */
void setup_eth_frame(struct ether_hdr *eth, uint8_t *dst_mac, int if_idx) {
    memcpy(eth->ethr_dhost, dst_mac, MAC_BYTES);
    get_interface_mac(if_idx, eth->ethr_shost);
    eth->ethr_type = htons(ETH_ARP);
}

/* Handle ARP queries */
void respond_to_arp_query(uint32_t query_ip, int if_idx) {
    uint8_t pkt[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)];
    uint8_t broadcast[MAC_BYTES] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    uint8_t blank_mac[MAC_BYTES] = {0};
    
    struct ether_hdr *eth = (struct ether_hdr *)pkt;
    struct arp_hdr *arp = (struct arp_hdr *)(pkt + sizeof(struct ether_hdr));
    
    setup_eth_frame(eth, broadcast, if_idx);
    config_arp(arp, ARP_QUERY, inet_addr(get_interface_ip(if_idx)), 
              query_ip, if_idx, blank_mac);
    
    send_to_link(sizeof(pkt), (char *)pkt, if_idx);
}

/* Process ARP responses */
void handle_arp_response(struct arp_hdr *arp_pkt, struct ether_hdr *eth, int if_idx) {
    /* Update ARP cache */
    int found = 0;
    for (int i = 0; i < arp_count; i++) {
        if (arp_cache[i].ip == arp_pkt->sprotoa) {
            memcpy(arp_cache[i].mac, arp_pkt->shwa, MAC_BYTES);
            found = 1;
            break;
        }
    }
    
    if (!found) {
        arp_cache[arp_count].ip = arp_pkt->sprotoa;
        memcpy(arp_cache[arp_count].mac, arp_pkt->shwa, MAC_BYTES);
        arp_count++;
    }
    
    /* Process waiting packets */
    deferred_pkt *temp_store[MAX_PENDING_PKTS];
    int temp_size = 0;
    
    while (!queue_empty(pending_queue)) {
        deferred_pkt *dpkt = queue_deq(pending_queue);
        if (dpkt->target_ip == arp_pkt->sprotoa) {
            struct ether_hdr *eth_pkt = (struct ether_hdr *)dpkt->pkt_data;
            memcpy(eth_pkt->ethr_dhost, arp_pkt->shwa, MAC_BYTES);
            send_to_link(dpkt->pkt_len, dpkt->pkt_data, dpkt->if_index);
            free(dpkt->pkt_data);
            free(dpkt);
        } else {
            temp_store[temp_size++] = dpkt;
        }
    }
    
    for (int i = 0; i < temp_size; i++) {
        queue_enq(pending_queue, temp_store[i]);
    }
}

/* Build routing structure */
void build_route_tree(route_node *root) {
    for (int i = 0; i < route_count; i++) {
        uint32_t net_prefix = htonl(route_table[i].prefix);
        uint32_t net_mask = htonl(route_table[i].mask);
        route_node *current = root;
        
        for (int bit = 31; bit >= 0; bit--) {
            if (net_mask & (1 << bit)) {
                int direction = (net_prefix >> bit) & 1;
                
                if (!current->next[direction]) {
                    current->next[direction] = calloc(1, sizeof(route_node));
                }
                current = current->next[direction];
            } else {
                break;
            }
        }
        current->rt_entry = &route_table[i];
    }
}

/* Find optimal route */
struct route_table_entry *find_best_route(route_node *root, uint32_t ip) {
    struct route_table_entry *match = NULL;
    route_node *current = root;
    
    for (int bit = 31; bit >= 0; bit--) {
        int direction = (ip >> bit) & 1;
        
        if (current->next[direction]) {
            current = current->next[direction];
            if (current->rt_entry) match = current->rt_entry;
        } else {
            break;
        }
    }
    return match;
}

/* Generate ICMP message */
void create_icmp_response(uint32_t dst_ip, char *pkt_buf, 
                         int if_idx, uint8_t type, uint8_t code) {
    struct ether_hdr *eth = (struct ether_hdr *)pkt_buf;
    struct ip_hdr *ip = (struct ip_hdr *)(pkt_buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp = (struct icmp_hdr *)(pkt_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    
    memcpy((uint8_t *)icmp + sizeof(struct icmp_hdr), ip, sizeof(struct ip_hdr) + 8);
    
    icmp->mtype = type;
    icmp->mcode = code;
    icmp->check = checksum((uint16_t *)icmp, sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
    
    ip->tot_len = htons(sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + 8);
    ip->ttl = DEFAULT_HOP_LIMIT;
    ip->proto = IP_ICMP;
    ip->checksum = checksum((uint16_t *)ip, sizeof(struct ip_hdr));
    ip->source_addr = inet_addr(get_interface_ip(if_idx));
    ip->dest_addr = dst_ip;
    
    send_to_link(sizeof(struct ether_hdr) + ntohs(ip->tot_len), pkt_buf, if_idx);
}

int main(int argc, char *argv[]) {
    char pkt_buf[MAX_PACKET_LEN];
    
    /* Initialize network */
    init(argv + 2, argc - 2);
    
    /* Load routing table */
    route_table = calloc(INIT_RT_CAPACITY, sizeof(struct route_table_entry));
    route_count = read_rtable(argv[1], route_table);
    
    /* Initialize ARP components */
    arp_cache = calloc(INIT_ARP_CAPACITY, sizeof(struct arp_table_entry));
    arp_count = 0;
    pending_queue = create_queue();
    
    /* Build routing structure */
    route_node *rt_root = calloc(1, sizeof(route_node));
    build_route_tree(rt_root);
    
    /* Main processing loop */
    while (1) {
        int if_idx;
        size_t pkt_size;
        
        if_idx = recv_from_any_link(pkt_buf, &pkt_size);
        DIE(if_idx < 0, "Packet receive error");
        
        struct ether_hdr *eth = (struct ether_hdr *)pkt_buf;
        int proto = get_protocol_type(ntohs(eth->ethr_type));
        
        if (proto == -1) continue;
        
        if (proto == 0) {  /* IPv4 processing */
            struct ip_hdr *ip = (struct ip_hdr *)(pkt_buf + sizeof(struct ether_hdr));
            
            /* Validate checksum */
            uint16_t orig_chksum = ip->checksum;
            ip->checksum = 0;
            if (orig_chksum != htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)))) {
                continue;
            }
            
            /* Check for ICMP echo */
            struct icmp_hdr *icmp = (struct icmp_hdr *)(pkt_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
            if (icmp->mtype == ICMP_ECHO_CALL && icmp->mcode == 0 && 
                ip->dest_addr == inet_addr(get_interface_ip(if_idx))) {
                create_icmp_response(ip->source_addr, pkt_buf, if_idx, ICMP_ECHO_RESPONSE, 0);
                continue;
            }
            
            /* Check TTL */
            if (ip->ttl <= 1) {
                create_icmp_response(ip->source_addr, pkt_buf, if_idx, ICMP_TTL_EXPIRED, 0);
                continue;
            }
            
            /* Find best route */
            struct route_table_entry *rt_entry = find_best_route(rt_root, htonl(ip->dest_addr));
            if (!rt_entry) {
                create_icmp_response(ip->source_addr, pkt_buf, if_idx, ICMP_NET_UNREACHABLE, 0);
                continue;
            }
            
            /* Update packet */
            ip->ttl--;
            ip->checksum = 0;
            ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));
            
            /* Find MAC address */
            uint8_t *mac = NULL;
            for (int i = 0; i < arp_count; i++) {
                if (arp_cache[i].ip == rt_entry->next_hop) {
                    mac = arp_cache[i].mac;
                    break;
                }
            }
            
            if (mac) {
                memcpy(eth->ethr_dhost, mac, MAC_BYTES);
                get_interface_mac(rt_entry->interface, eth->ethr_shost);
                send_to_link(pkt_size, pkt_buf, rt_entry->interface);
            } else {
                // Store packet for later transmission
                struct deferred_pkt *deferred = (struct deferred_pkt*)malloc(sizeof(struct deferred_pkt));
                if (!deferred) {
                    fprintf(stderr, "Memory allocation failed\n");
                    return 0;
                }
            
                deferred->pkt_data = (char*)malloc(pkt_size);
                if (!deferred->pkt_data) {
                    free(deferred);
                    fprintf(stderr, "Memory allocation failed\n");
                    return 0;
                }
                memcpy(deferred->pkt_data, pkt_buf, pkt_size);
            
                deferred->pkt_len = pkt_size;
                deferred->target_ip = rt_entry->next_hop;
                deferred->if_index = rt_entry->interface;
            
                queue_enq(pending_queue, deferred);
            
                // Initiate ARP resolution
                respond_to_arp_query(rt_entry->next_hop, rt_entry->interface);
            }
        } 
        else if (proto == 1) {  /* ARP processing */
            struct arp_hdr *arp = (struct arp_hdr *)(pkt_buf + sizeof(struct ether_hdr));
            if (ntohs(arp->opcode) == ARP_QUERY) {
                uint8_t reply[sizeof(struct ether_hdr) + sizeof(struct arp_hdr)];
                struct ether_hdr *eth_reply = (struct ether_hdr *)reply;
                struct arp_hdr *arp_reply = (struct arp_hdr *)(reply + sizeof(struct ether_hdr));
                
                setup_eth_frame(eth_reply, eth->ethr_shost, if_idx);
                config_arp(arp_reply, ARP_RESPONSE, arp->tprotoa, arp->sprotoa, if_idx, eth->ethr_shost);
                send_to_link(sizeof(reply), (char *)reply, if_idx);
            } 
            else if (ntohs(arp->opcode) == ARP_RESPONSE) {
                handle_arp_response(arp, eth, if_idx);
            }
        }
    }
    
    return 0;
}