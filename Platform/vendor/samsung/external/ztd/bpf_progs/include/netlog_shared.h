#pragma once

#include <sys/types.h>

#define PROG_INSECURE_PORTS     "insecureports"
#define PROG_ABNORMAL_PACKETS   "abnormalpackets"
#define PROG_LOCALNW_PACKETS    "localnwpackets"
#define PROG_BYPASSVPN_PACKETS  "bypassvpnpackets"

#define TP_SOCK_LISTEN_PROG "/sys/fs/bpf/prog_netlog_tracepoint_sock_inet_sock_set_state"
#define XT_BPF_NETLOG(NAME) "/sys/fs/bpf/prog_netlog_skfilter_" NAME "_xtbpf"

#define XT_BPF_INSECUREPORTS_PROG_PATH XT_BPF_NETLOG(PROG_INSECURE_PORTS)
#define XT_BPF_ABNORMALPACKETS_PROG_PATH XT_BPF_NETLOG(PROG_ABNORMAL_PACKETS)
#define XT_BPF_LOCALNWPACKETS_PROG_PATH XT_BPF_NETLOG(PROG_LOCALNW_PACKETS)
#define XT_BPF_BYPASSVPNPACKETS_PROG_PATH XT_BPF_NETLOG(PROG_BYPASSVPN_PACKETS)

#define INSECURE_PORTS_RINGBUF_PATH     "/sys/fs/bpf/map_netlog_insecure_ports_ringbuf"
#define ABNORMAL_PKT_RINGBUF_PATH       "/sys/fs/bpf/map_netlog_abnormal_pkts_ringbuf"
#define LOCAL_NW_RINGBUF_PATH           "/sys/fs/bpf/map_netlog_localnw_pkts_ringbuf"
#define BYPASSVPN_RINGBUF_PATH          "/sys/fs/bpf/map_netlog_bypassVpn_pkts_ringbuf"
#define SOCK_LISTEN_PROBE_RINGBUF_PATH  "/sys/fs/bpf/map_netlog_sock_listen_probe_ringbuf"
#define SOCKET_DATA_MAP_PATH            "/sys/fs/bpf/map_netlog_socket_data_map"

#define EVENT_TYPE_INSECURE_PORTS   1
#define EVENT_TYPE_ABNORMAL_PACKETS 2
#define EVENT_TYPE_LOCALNW_PACKETS  3
#define EVENT_TYPE_BYPASS_VPN       4

#ifndef AF_INET
#define AF_INET    2
#endif

#define TCP_STATE_LISTEN    10

typedef struct socket_data
{
    uint32_t event_type;
    uint64_t timestamp;
    uint32_t uid;
    uint32_t ifindex;
    uint16_t family;
    uint8_t protocol;
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t src_ip;
    uint32_t dest_ip;
    uint8_t src_ip6[16];
    uint8_t dest_ip6[16];
} socket_data_t;

typedef struct inet_listen_data {
    uint64_t timestamp;
    uint32_t family; // Needed to copy v4 or v6 address in JNI layer
    uint32_t ifindex;
    uint32_t uid;
    uint16_t sport;
    uint16_t dport;
    uint8_t saddr[4];
    uint8_t daddr[4];
    uint8_t saddr_v6[16];
    uint8_t daddr_v6[16];
} inet_listen_data_t;


struct inet_sock_state_args {
    uint64_t common;
    const void* skaddr;
    int oldstate;
    int newstate;
    uint16_t sport;
    uint16_t dport;
    uint16_t family;
    uint16_t protocol;
    uint8_t saddr[4];
    uint8_t daddr[4];
    uint8_t saddr_v6[16];
    uint8_t daddr_v6[16];
};