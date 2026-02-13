#include <linux/bpf.h>
#include <linux/if.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

#include <stdbool.h>
#include <stdint.h>
#include <netinet/in.h>

#include "bpf_shared.h"
#include <netlog_shared.h>

#define DEBUG 1

#define IP_ETH_OFFSET_SRC (offsetof(struct iphdr, saddr))
#define IP_ETH_OFFSET_DST (offsetof(struct iphdr, daddr))
#define IP_PROTOCOL_OFFSET (offsetof(struct iphdr, protocol))

#define IPV4_DPORT_OFFSET (sizeof(struct iphdr) + offsetof(struct tcphdr, dest))
#define IPV4_SPORT_OFFSET (sizeof(struct iphdr) + offsetof(struct tcphdr, source))

#define IPV6_OFFSET_SRC         (offsetof(struct ipv6hdr, saddr))
#define IPV6_OFFSET_DST         (offsetof(struct ipv6hdr, daddr))

#define IPV6_DPORT_OFF          (sizeof(struct ipv6hdr) + offsetof(struct tcphdr, dest))
#define IPV6_SPORT_OFF          (sizeof(struct ipv6hdr) + offsetof(struct tcphdr, source))
#define IPV6_PROTOCOL_OFFSET    6

static int (*bpf_skb_load_bytes)(struct __sk_buff *skb, int off, void *to, int len) = (void *)BPF_FUNC_skb_load_bytes;
static uint32_t (*bpf_get_socket_uid)(struct __sk_buff *skb) = (void *)BPF_FUNC_get_socket_uid;

DEFINE_BPF_RINGBUF_EXT(insecure_ports_ringbuf, socket_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
DEFINE_BPF_RINGBUF_EXT(abnormal_pkts_ringbuf, socket_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
DEFINE_BPF_RINGBUF_EXT(localnw_pkts_ringbuf, socket_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
DEFINE_BPF_RINGBUF_EXT(bypassVpn_pkts_ringbuf, socket_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
DEFINE_BPF_RINGBUF_EXT(sock_listen_probe_ringbuf, inet_listen_data_t, 4096, AID_ROOT, AID_SYSTEM, 0660, "", "", PRIVATE,
                       BPFLOADER_MIN_VER, BPFLOADER_MAX_VER, LOAD_ON_ENG, LOAD_ON_USER, LOAD_ON_USERDEBUG);
DEFINE_BPF_MAP_GRW(socket_data_map, PERCPU_ARRAY, uint32_t, socket_data_t, 1, AID_SYSTEM);
DEFINE_BPF_MAP_GRW(socket_listen_map, PERCPU_ARRAY, uint32_t, inet_listen_data_t, 1, AID_SYSTEM);

static inline __always_inline void extract_and_write_event_data(struct __sk_buff *skb, uint32_t packet_type)
{
    uint32_t zero = 0;
     // TODO - use bpf_ringbuf_reserve() instead and remove socket_data_map
    socket_data_t *output = bpf_socket_data_map_lookup_elem(&zero);
    if (output == NULL)
        return;

    output->event_type = packet_type;
    output->uid = bpf_get_socket_uid(skb);
    output->timestamp = bpf_ktime_get_boot_ns();
    output->ifindex = skb->ifindex;

    if (skb->protocol == htons(ETH_P_IP))
    {
        bpf_skb_load_bytes(skb, IP_ETH_OFFSET_SRC, &output->src_ip, sizeof(output->src_ip));
        bpf_skb_load_bytes(skb, IP_ETH_OFFSET_DST, &output->dest_ip, sizeof(output->dest_ip));
        output->src_port = load_half(skb, IPV4_SPORT_OFFSET);
        output->dest_port = load_half(skb, IPV4_DPORT_OFFSET);
        bpf_skb_load_bytes(skb, IP_PROTOCOL_OFFSET, &output->protocol, 1);
        output->family = AF_INET;
    }
    else if (skb->protocol == htons(ETH_P_IPV6))
    {
        bpf_skb_load_bytes(skb, IPV6_OFFSET_SRC , &output->src_ip6, sizeof(output->src_ip6));
        bpf_skb_load_bytes(skb, IPV6_OFFSET_DST, &output->dest_ip6, sizeof(output->dest_ip6));
        output->src_port = load_half(skb, IPV6_SPORT_OFF);
        output->dest_port = load_half(skb, IPV6_DPORT_OFF);
        bpf_skb_load_bytes(skb, IPV6_PROTOCOL_OFFSET, &output->protocol, 1);
        output->family = AF_INET6;
    }
    
    switch (packet_type) {
        case EVENT_TYPE_INSECURE_PORTS:
            bpf_insecure_ports_ringbuf_output(output);
            break;
        case EVENT_TYPE_ABNORMAL_PACKETS:
            bpf_abnormal_pkts_ringbuf_output(output);
            break;
        case EVENT_TYPE_LOCALNW_PACKETS:
            bpf_localnw_pkts_ringbuf_output(output);
            break;
        case EVENT_TYPE_BYPASS_VPN:
            bpf_bypassVpn_pkts_ringbuf_output(output);
            break;
        default:
            break;
    }
}

DEFINE_BPF_PROG("skfilter/insecureports/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_insecureports_prog)
(struct __sk_buff *skb)
{
    extract_and_write_event_data(skb, EVENT_TYPE_INSECURE_PORTS);
    return 1;
}

DEFINE_BPF_PROG("skfilter/abnormalpackets/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_abnormalpackets_prog)
(struct __sk_buff *skb)
{
    extract_and_write_event_data(skb, EVENT_TYPE_ABNORMAL_PACKETS);
    return 1;
}

DEFINE_BPF_PROG("skfilter/localnwpackets/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_localnwpackets_prog)
(struct __sk_buff *skb)
{
    extract_and_write_event_data(skb, EVENT_TYPE_LOCALNW_PACKETS);
    return 1;
}

DEFINE_BPF_PROG("skfilter/bypassvpnpackets/xtbpf", AID_ROOT, AID_NET_ADMIN, xt_bpf_bypassvpnpackets_prog)
(struct __sk_buff *skb)
{
    extract_and_write_event_data(skb, EVENT_TYPE_BYPASS_VPN);
    return 1;
}

DEFINE_BPF_PROG("tracepoint/sock/inet_sock_set_state", AID_ROOT, AID_SYSTEM, inet_sock_set_state)
(struct inet_sock_state_args *args) {
    uint32_t zero = 0;
    inet_listen_data_t *data = bpf_socket_listen_map_lookup_elem(&zero);

    if(!data) {
        return 0;
    }

    if (args->newstate == TCP_STATE_LISTEN) {
        data->uid = (bpf_get_current_uid_gid() >> 32);
        data->family = args->family;
        data->timestamp = bpf_ktime_get_boot_ns();
        data->sport = args->sport;
        data->dport = args->dport;

        if (args->family == AF_INET) {
            __builtin_memcpy(&data->saddr, args->saddr, sizeof(data->saddr));
            __builtin_memcpy(&data->daddr, args->daddr, sizeof(data->daddr));
        } else { 
            __builtin_memcpy(&data->saddr_v6, args->saddr_v6, sizeof(data->saddr_v6));
            __builtin_memcpy(&data->daddr_v6, args->daddr_v6, sizeof(data->daddr_v6));
        }

#if DEBUG
    bpf_printk("[ztd] netlog inet_sock_set_state :: timestamp =   %lu", data->timestamp);
    bpf_printk("[ztd] netlog inet_sock_set_state :: family    =   %d", data->family);
    bpf_printk("[ztd] netlog inet_sock_set_state :: uid       =   %d", data->uid);
    bpf_printk("[ztd] netlog inet_sock_set_state :: sport     =   %u", data->sport);
#endif
        bpf_sock_listen_probe_ringbuf_output(data);
    }
    return 1;
}

LICENSE("GPL");
