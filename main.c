/*
 * This is a very troublesome homework...
 *
 * A pcap file structure for tcp transaction is something like this:
 *     [pcap_file_header]
 *     for each packet
 *         [pcap_packet]  this contains packet len info
 *         [ip_header]    usually of size 20 or more
 *         [tcp_header]   usually of size 20 or more
 *         [tcp_data]     len stored in ip header
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <dirent.h>
#include "hashtbl.h"
#include "main.h"

// my custom function
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

char *pathcat(char *dir, char *filename) {
    return mystrdup(3, dir, PATH_DELIMITER, filename);
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

bool is_little_endian() {
   unsigned int i = 1;
   char *c = (char*)&i;
   return *c;
}

// judge function
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

bool is_tcp(void *ip_packet) {
    int protocol = get_ip_protocol(ip_packet);
    if (is_ip4(protocol))
        return _IP4(ip_packet)->ip_p == PROTOCOL_TCP;
    // TODO
    else if (is_ip6(protocol))
        return 0;
    return FALSE;
}

// packet infomation
int get_ether_type(const u_char *pcap_packet) {
    return ((int)(pcap_packet[12]) << 8) | (int)pcap_packet[13];
}

/*
 * @protocol: IPv4 or IPv6
 */
void *get_ip_header(const u_char *pcap_packet) {
    int offset;
    switch (get_ether_type(pcap_packet)) {
        case ETHER_TYPE_8021Q: offset = ETHER_OFFSET_8021Q;break;
        case ETHER_TYPE_IP4: offset = ETHER_OFFSET_IP4;break;
        case ETHER_TYPE_IP6: offset = ETHER_OFFSET_IP6;break;
        default: return NULL;
    }
    //skip past the Ethernet II header
    return (void *)(pcap_packet + offset);
}

int get_ip_protocol(void *ip_packet) {
    char version = *((char *)ip_packet);
    if (is_little_endian())
        version = (version & 0xF0) >> 4;
    else
        version &= 0x0F;

    return 4 == version ? PROTOCOL_IP4 : PROTOCOL_IP6;
}

/*
 * @ip_packet: beginning memory address of IP packet, same with IP header
 */
tcp_hdr *get_tcp_header(void *ip_packet) {
    int protocol = get_ip_protocol(ip_packet);
    if (is_ip4(protocol))
        return (tcp_hdr *)((char *)(ip_packet) + _IP4(ip_packet)->ip_hl * 4);
    // TODO
    else
        return 0;
    return NULL;
}

/*
 * return beginning memory address of tcp data
 */
const char *get_tcp_data(tcp_hdr *tcp_packet) {
    return (const char *)((char *)(tcp_packet) + tcp_packet->th_off * 4);
}

size_t get_tcp_data_length(void *ip_packet) {
    size_t ip_len;
    size_t ip_header_len;
    size_t tcp_header_len;
    int protocol = get_ip_protocol(ip_packet);

    if (is_ip4(protocol)) {
        ip_header_len = _IP4(ip_packet)->ip_hl * 4;
        ip_len = ntohs(_IP4(ip_packet)->ip_len);
        // `th_off` specifies the size of the TCP header in 32-bit words
    } else {
        // TODO
    }
    tcp_header_len = get_tcp_header(ip_packet)->th_off * 4;

    return ip_len - (ip_header_len + tcp_header_len);
}

/*
 * return something like "192.168.137.1.80--192.168.137.233.8888"
 */
const char *get_ip_port_pair(void *ip_packet) {
    int addr_len;
    void *ip_src;
    void *ip_dst;
    int protocol = get_ip_protocol(ip_packet);

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

    tcp_hdr *tcp_packet = get_tcp_header(ip_packet);
    int port_src = ntohs(tcp_packet->th_sport);
    int port_dst = ntohs(tcp_packet->th_dport);

    // max port number in string takes 5 bytes
    char *str = malloc((addr_len + 5) * 2 + 5);
    sprintf(str, "%s.%d--%s.%d", buf_src, port_src, buf_dst, port_dst);

    return (const char *)str;
}

pcap_t *get_pcap_handle(char *filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    if (!(handle = pcap_open_offline(filename, errbuf)))
        error("Couldn't open pcap file %s: %s", filename, errbuf);
    return handle;
}

/*
 * a pcap item contains a pcap header and a pointer of beignning of packet
 */
pcap_item *create_pcap_item(const u_char *pcap_packet, struct pcap_pkthdr *pcap_header) {
    size_t pcap_len = pcap_header->caplen;
    u_char *tmp_packet = malloc(pcap_len);
    memcpy(tmp_packet, pcap_packet, pcap_len);

    pcap_item *pcap = malloc(sizeof(pcap_item));
    pcap->header = *pcap_header;
    pcap->packet = tmp_packet;

    return pcap;
}

// hash operation
/*
 * return a single instance of hash table
 */
HASHTBL *get_hash_table() {
    static HASHTBL *hashtbl;
    if(hashtbl == NULL) {
        hashtbl = hashtbl_create(HASH_SIZE, NULL);
        if(hashtbl == NULL)
            error("ERROR: hashtbl_create() failed");
    }
    return hashtbl;
}

/*
 * don't destory hash table until finished all your work!
 */
void destory_hash_table() {
    hashtbl_destroy(get_hash_table());
}

void free_hash_node(void *ptr) {
    pcap_item *pcap = (pcap_item *)ptr;
    free((void *)pcap->packet);
    free((void *)pcap);
}

void remove_hash_nodes(const char *key) {
    HASHTBL *hashtbl = get_hash_table();
    hashtbl_remove(hashtbl, key, free_hash_node);
}

/*
 * use (source ip:port, destination ip:port) as key, hash pcap_item
 */
const char *insert_hash_node(const u_char *pcap_packet, struct pcap_pkthdr *pcap_header) {
    void *ip_packet = get_ip_header(pcap_packet);
    const char *key = get_ip_port_pair(ip_packet);
    pcap_item *pcap = create_pcap_item(pcap_packet, pcap_header);

    if (-1 == hashtbl_insert(get_hash_table(), key, (void *)pcap))
        error("ERROR: insert to hash table failed");

    return key;
}

int cmp_pcap_packet(pcap_item *p1, pcap_item *p2) {
    const u_char *pck1 = p1->packet;
    const u_char *pck2 = p2->packet;
    tcp_hdr *t1 = get_tcp_header(get_ip_header(pck1));
    tcp_hdr *t2 = get_tcp_header(get_ip_header(pck2));

    int diff_seq = ntohl(t1->th_seq) - ntohl(t2->th_seq);
    int diff_ack = ntohl(t1->th_ack) - ntohl(t2->th_ack);

    return diff_seq ? diff_seq : diff_ack;
}

/*
 * sort pcap packets storging in hash table
 */
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

// file operation
/*
 * write pcap packet to pcap file
 */
void write_pcap_to_file(pcap_t *handle, struct hashnode_s *node) {
    const char *filename = pathcat(PCAP_DIR, mystrdup(2, node->key, ".pcap"));

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

void write_pcaps_to_files(pcap_t *handle) {
    HASHTBL *hashtbl = get_hash_table();

    for (int i = 0; i < HASH_SIZE; i++) {
        if (!hashtbl->nodes[i])
            continue;
        hashtbl->nodes[i] = sort_pcap_packets(hashtbl->nodes[i]);
        write_pcap_to_file(handle, hashtbl->nodes[i]);
        remove_hash_nodes(hashtbl->nodes[i]->key);
    }
}

/*
 * write tcp data (maybe contains HTTP request and response) to txt file
 */
size_t write_tcp_data_to_file(FILE *fp, const u_char *pcap_packet) {
    void *ip_packet = get_ip_header(pcap_packet);
    int protocol = get_ip_protocol(ip_packet);
    tcp_hdr *tcp_packet = get_tcp_header(ip_packet);
    size_t data_len = get_tcp_data_length(ip_packet);
    const char *data_ptr = get_tcp_data(tcp_packet);

    if (data_len && data_len != fwrite(data_ptr, 1, data_len, fp))
        error("write wrong size of tcp data to file\n");
    return data_len;
}

void write_http_pairs_to_files() {
    DIR *dir;
    struct dirent *ent;
    if (!(dir = opendir(PCAP_DIR)))
        error("open directory '" PCAP_DIR "' failed\n");

    while ((ent = readdir(dir)) != NULL) {
        char *filename = ent->d_name;
        if (!is_pcap_file(filename))
            continue;
        filename = pathcat(REQS_DIR, mystrdup(2, filename, ".txt"));

        const u_char *pcap_packet;
        struct pcap_pkthdr header;
        char *pcap_filename = pathcat(PCAP_DIR, ent->d_name);

        pcap_t *handle = get_pcap_handle(pcap_filename);
        FILE *fp = fopen(filename, "wb");
        while (NULL != (pcap_packet = pcap_next(handle, &header)))
            write_tcp_data_to_file(fp, pcap_packet);

        fclose(fp);
        pcap_close(handle);
        free(pcap_filename);
    }
    closedir(dir);
}


void init_environment(int argc, char **argv) {
    if (argc < 2)
        error("usage: %s [file]", argv[0]);
    mkdir(PCAP_DIR, 0754);
    mkdir(REQS_DIR, 0754);
    mkdir(HTTP_DIR, 0754);
}

int main(int argc, char **argv) {
    const u_char *pcap_packet;
    struct pcap_pkthdr header;
    pcap_t *handle;

    init_environment(argc, argv);
    handle = get_pcap_handle(argv[1]);

    while (NULL != (pcap_packet = pcap_next(handle, &header))) {
        void *ip_packet = get_ip_header(pcap_packet);
        // skip if neither IPv4 nor IPv6
        if (NULL == ip_packet)
            continue;
        // TODO: deal with UDP
        if (is_tcp(ip_packet)) {
            insert_hash_node(pcap_packet, &header);
        }
    }

    write_pcaps_to_files(handle);
    write_http_pairs_to_files();

    destory_hash_table();
    pcap_close(handle);
    return 0;
}
