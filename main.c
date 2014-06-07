/*
This is a very troublesome homework...

A pcap file structure for tcp transaction is something like this:
[pcap_file_header]
    for each packet
        [pcap_packet] --this contains packet len info
        [ip_header]----usually of size 20 or more
        [tcp_header]--usually of size 20 or more
        [packet] ---len stored in pcap packet header
*/
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <sys/stat.h>
#include <dirent.h>
#include "hashtbl.h"


// the type code of the pcap_packet in an ETHERNET header
#define ETHER_TYPE_IP4 0x0800
#define ETHER_TYPE_IP6 0x86DD
// the offset value of the pcap_packet (in byte number)
#define ETHER_OFFSET_IP 14
// protocol code
#define PROTOCOL_IP4 AF_INET
#define PROTOCOL_IP6 AF_INET6
#define PROTOCOL_TCP 0x06
#define PROTOCOL_UDP 0x11
// constant
#ifndef __FILE__
#define __FILE__ "main"
#endif /* __FILE__ */
#define TRUE 1
#define FALSE 0
#define HASH_SIZE 100
#define PCAP_DIR "pcaps"
#define RSSB_DIR "reassembles"
#define HTTP_DIR "https"

// function
#define _IP4(x) ((ip4_hdr *)(x))
#define _IP6(x) ((ip6_hdr *)(x))


typedef int bool;
typedef struct ip ip4_hdr;
typedef struct ip6_hdr ip6_hdr;
typedef struct tcphdr tcp_hdr;
typedef char http_hdr;
typedef struct in_addr ip4_addr;
typedef struct in6_addr ip6_addr;
typedef struct {
    struct pcap_pkthdr header;
    const u_char *packet;
} pcap_item;


void error(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);
    printf("\n");
    exit(EXIT_FAILURE);
}

char *mystrdup(int argc, const char *str1, ...) {
    va_list strs;
    va_start(strs, str1);
    char *ss = strdup(str1);
    int len = strlen(ss);

    for (int i = 0; i < argc - 1; i++) {
        const char *s = va_arg(strs, const char *);
        len += strlen(s);
        // 1 for '\0'
        if (!(ss = realloc(ss, len + 1)))
            error("alloc memory for `mystrdup` function failed");
        ss[len] = '\0';
        strcat(ss, s);
    }

    va_end(strs);
    return ss;
}

size_t hexprint(void *ptr, size_t length) {
    size_t byte_counter = 0;
    char *byte_ptr = (char *)ptr;

    while (length--) {
        printf("%02X", *byte_ptr);
        byte_ptr++;

        if (++byte_counter) {
            if (byte_counter % 16 == 0) {
                printf("\n");
            } else if (byte_counter % 2 == 0) {
                printf(" ");
            }
        }
    }

    printf("\n");
    return byte_counter;
}

pcap_t *get_handle(char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (!(handle = pcap_open_offline(filename, errbuf)))
        error("Couldn't open pcap file %s: %s", filename, errbuf);
    return handle;
}

bool is_pcap_file(const char *filename) {
    const char *sub = strrchr(filename, '.');
    if (sub == NULL)
        return FALSE;
    if (strcmp(sub, ".pcap"))
        return FALSE;
    return TRUE;
}

bool is_ip4(int protocol) {
    return protocol == PROTOCOL_IP4;
}

bool is_ip6(int protocol) {
    return protocol == PROTOCOL_IP6;
}

bool is_ip(int protocol) {
    return is_ip4(protocol) || is_ip6(protocol);
}

bool is_tcp(int ip_protocol, void *ip_packet) {
    if (is_ip4(ip_protocol))
        return _IP4(ip_packet)->ip_p == PROTOCOL_TCP;
    // TODO
    else if (is_ip6(ip_protocol))
        return 0;
    return FALSE;
}

int get_ether_type(const u_char *pcap_packet) {
    return ((int)(pcap_packet[12]) << 8) | (int)pcap_packet[13];
}

int get_ip_protocol(const u_char *pcap_packet) {
    switch (get_ether_type(pcap_packet)) {
        case ETHER_TYPE_IP4: return PROTOCOL_IP4;
        case ETHER_TYPE_IP6: return PROTOCOL_IP6;
        default: return -1;
    }
}

void *get_ip_header(int protocol, const u_char *pcap_packet) {
    //skip past the Ethernet II header
    if (is_ip4(protocol))
        return (void *)(pcap_packet + ETHER_OFFSET_IP);
    // TODO
    else if (is_ip6(protocol))
        return 0;
    return NULL;
}

tcp_hdr *get_tcp_header(int protocol, void *ip_packet) {
    if (is_ip4(protocol))
        return (tcp_hdr *)((char *)(ip_packet) + _IP4(ip_packet)->ip_hl * 4);
    // TODO
    else
        return 0;
    return NULL;
}

const char *get_tcp_data(tcp_hdr *tcp_packet) {
    return (const char *)((char *)(tcp_packet) + tcp_packet->th_off * 4);
}

size_t get_tcp_data_length(int protocol, void *ip_packet) {
    size_t ip_len;
    size_t ip_header_len;
    size_t tcp_header_len;

    if (is_ip4(protocol)) {
        ip_header_len = _IP4(ip_packet)->ip_hl * 4;
        ip_len = ntohs(_IP4(ip_packet)->ip_len);
        // `th_off` specifies the size of the TCP header in 32-bit words
        tcp_header_len = get_tcp_header(PROTOCOL_IP4, ip_packet)->th_off * 4;
    } else {
        // TODO
    }

    return ip_len - (ip_header_len + tcp_header_len);
}

const char *get_ip_port_pair(int protocol, void *ip_packet) {
    int addr_len;
    void *ip_src;
    void *ip_dst;

    if (is_ip4(protocol)) {
        addr_len = INET_ADDRSTRLEN;
        ip_src = &_IP4(ip_packet)->ip_src;
        ip_dst = &_IP4(ip_packet)->ip_dst;
    } else {
        addr_len = INET6_ADDRSTRLEN;
        // TODO
    }

    char buf_src[INET6_ADDRSTRLEN];
    char buf_dst[INET6_ADDRSTRLEN];
    inet_ntop(protocol, ip_src, buf_src, addr_len);
    inet_ntop(protocol, ip_dst, buf_dst, addr_len);

    tcp_hdr *tcp_packet = get_tcp_header(protocol, ip_packet);
    int port_src = ntohs(tcp_packet->th_sport);
    int port_dst = ntohs(tcp_packet->th_dport);

    // max port number in string takes 5 bytes
    char *str = malloc((addr_len + 5) * 2 + 5);
    sprintf(str, "%s.%d--%s.%d", buf_src, port_src, buf_dst, port_dst);

    return (const char *)str;
}

// single pattern
HASHTBL *get_hash_table() {
    static HASHTBL *hashtbl;
    if(hashtbl == NULL) {
        hashtbl = hashtbl_create(HASH_SIZE, NULL);
        if(hashtbl == NULL)
            error("ERROR: hashtbl_create() failed");
    }
    return hashtbl;
}

void free_hash_data(void *ptr) {
    pcap_item *pcap = (pcap_item *)ptr;
    free((void *)pcap->packet);
    free((void *)pcap);
}

const char *hash_ip_pair(int protocol, const u_char *pcap_packet, struct pcap_pkthdr *pcap_header) {
    void *ip_packet = get_ip_header(protocol, pcap_packet);
    const char *key = get_ip_port_pair(protocol, ip_packet);
    size_t pcap_len = pcap_header->caplen;

    u_char *tmp_packet = malloc(pcap_len);
    memcpy(tmp_packet, pcap_packet, pcap_len);

    pcap_item *pcap = malloc(sizeof(pcap_item));
    pcap->header = *pcap_header;
    pcap->packet = tmp_packet;
    if (-1 == hashtbl_insert(get_hash_table(), key, (void *)pcap))
        error("ERROR: insert to hash table failed");

    return key;
}

int cmp_pcap_packet(pcap_item *p1, pcap_item *p2) {
    int protocol1;
    int protocol2;
    const u_char *pck1 = p1->packet;
    const u_char *pck2 = p2->packet;

    protocol1 = get_ip_protocol(pck1);
    tcp_hdr *t1 = get_tcp_header(protocol1, get_ip_header(protocol1, pck1));
    protocol2 = get_ip_protocol(pck2);
    tcp_hdr *t2 = get_tcp_header(protocol2, get_ip_header(protocol2, pck2));

    // TODO: use `t1->th_flags` to drop wrong pcap_packet
    // TH_FIN TH_SYN TH_RST TH_PUSH TH_ACK TH_URG TH_ECE TH_CWR
    int diff_seq = ntohl(t1->th_seq) - ntohl(t2->th_seq);
    int diff_ack = ntohl(t1->th_ack) - ntohl(t2->th_ack);
    if (diff_seq)
        return diff_seq;
    else
        return diff_ack;
}

struct hashnode_s *sort_pcap_packets(struct hashnode_s *list) {
    struct hashnode_s *p, *q, *e, *tail;
    int insize, nmerges, psize, qsize, i;

    if (!list)
        return NULL;

    insize = 1;
    while (1) {
        p = list;
        list = NULL;
        tail = NULL;
        /* count number of merges we do in this pass */
        nmerges = 0;

        while (p) {
            /* there exists a merge to be done */
            nmerges++;
            /* step `insize' places along from p */
            q = p;
            psize = 0;
            for (i = 0; i < insize; i++) {
                psize++;
                if (!(q = q->next))
                    break;
            }

            /* if q hasn't fallen off end, we have two lists to merge */
            qsize = insize;

            /* now we have two lists; merge them */
            while (psize > 0 || (qsize > 0 && q)) {
                /* decide whether next element of merge comes from p or q */
                if (psize == 0) {
                    /* p is empty; e must come from q. */
                    e = q; q = q->next; qsize--;
                } else if (qsize == 0 || !q) {
                    /* q is empty; e must come from p. */
                    e = p; p = p->next; psize--;
                } else if (cmp_pcap_packet((pcap_item *)p->data, (pcap_item *)q->data) <= 0) {
                    /* First element of p is lower (or same);
                     * e must come from p. */
                    e = p; p = p->next; psize--;
                } else {
                    /* First element of q is lower; e must come from q. */
                    e = q; q = q->next; qsize--;
                }

                /* add the next element to the merged list */
                if (tail)
                    tail->next = e;
                else
                    list = e;

                tail = e;
            }

            /* now p has stepped `insize' places along, and q has too */
            p = q;
        }

        tail->next = NULL;

        /* If we have done only one merge, we're finished. */
        if (nmerges <= 1)   /* allow for nmerges==0, the empty list case */
            return list;
        /* Otherwise repeat, merging lists twice the size */
        insize *= 2;
    }
}

void write_pcap_packets(pcap_t *handle, struct hashnode_s *node) {
    const char *filename = mystrdup(3, PCAP_DIR "/", node->key, ".pcap");

    pcap_dumper_t *pd;
    if (!(pd = pcap_dump_open(handle, filename)))
        error("opening savefile '%s' failed for writing\n", filename);

    while (node) {
        pcap_item *pcap = (pcap_item *)node->data;
        struct pcap_pkthdr *pHeader = &pcap->header;
        const u_char *packet = pcap->packet;
        pcap_dump((u_char *)pd, pHeader, packet);
        node = node->next;
    }

    pcap_dump_close(pd);
    free((void *)filename);
}

void write_pcap_to_files(pcap_t *handle) {
    HASHTBL *hashtbl = get_hash_table();
    struct hashnode_s *node;
    for (int i = 0; i < HASH_SIZE; i++) {
        if (!hashtbl->nodes[i])
            continue;
        hashtbl->nodes[i] = sort_pcap_packets(hashtbl->nodes[i]);
        write_pcap_packets(handle, hashtbl->nodes[i]);
        hashtbl_remove(hashtbl, hashtbl->nodes[i]->key, free_hash_data);
    }
    hashtbl_destroy(hashtbl);
}

size_t write_tcp_data_to_file(FILE *fp, const u_char *pcap_packet) {
    int protocol = get_ip_protocol(pcap_packet);
    void *ip_packet = get_ip_header(protocol, pcap_packet);
    tcp_hdr *tcp_packet = get_tcp_header(protocol, ip_packet);

    size_t data_len = get_tcp_data_length(protocol, ip_packet);
    const char *data_ptr = get_tcp_data(tcp_packet);

    if (data_len && data_len != fwrite(data_ptr, 1, data_len, fp))
        error("write wrong size of tcp data to file\n");
    return data_len;
}

void reassemble_pcap_from_files() {
    DIR *dir;
    struct dirent *ent;
    if (!(dir = opendir(PCAP_DIR)))
        error("open directory '" PCAP_DIR "' failed\n");

    while ((ent = readdir(dir)) != NULL) {
        const u_char *pcap_packet;
        struct pcap_pkthdr header;

        char *filename = ent->d_name;
        if (!is_pcap_file(filename))
            continue;
        filename = mystrdup(3, RSSB_DIR "/", filename, ".txt");

        char *pcap_filename = mystrdup(2, PCAP_DIR "/", ent->d_name);
        pcap_t *handle = get_handle(pcap_filename);
        FILE *fp = fopen(filename, "wb");
        while (NULL != (pcap_packet = pcap_next(handle, &header)))
            write_tcp_data_to_file(fp, pcap_packet);

        fclose(fp);
        pcap_close(handle);
        free(pcap_filename);
    }
    closedir(dir);
}


int main(int argc, char **argv) {
    const u_char *pcap_packet;
    struct pcap_pkthdr header;
    pcap_t *handle;

    if (argc < 2)
        error("usage: %s [file]", argv[0]);
    else {
        mkdir(PCAP_DIR, 0754);
        mkdir(RSSB_DIR, 0754);
        mkdir(HTTP_DIR, 0754);
        handle = get_handle(argv[1]);
    }

    while (NULL != (pcap_packet = pcap_next(handle, &header))) {
        int protocol = get_ip_protocol(pcap_packet);
        if (!is_ip(protocol))
            continue;

        void *ip_packet = get_ip_header(protocol, pcap_packet);
        if (is_tcp(protocol, ip_packet)) {
            hash_ip_pair(protocol, pcap_packet, &header);
        } else {
            // TODO
            continue;
        }
    }

    write_pcap_to_files(handle);
    reassemble_pcap_from_files();

    pcap_close(handle);
    return 0;
}
