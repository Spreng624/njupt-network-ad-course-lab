/*
 * sniff-detector.c
 *
 * 局域网嗅探检测器
 *
 * 检测能力：
 *   1. Promiscuous Mode 检测（主动探测）
 *      发送目标 MAC = FF:FF:FF:FF:FF:FE（错的广播）的 ARP 请求：
 *        正常网卡：看到目标 MAC 不是自己/广播 → 驱动层丢弃 → 不响应
 *        promiscuous 网卡：接收所有帧 → 处理并可能响应 ARP → 暴露
 *
 *   2. ARP 欺骗检测（被动监听）
 *      2a. IP→MAC 翻转：同一个 IP 出现不同 MAC（经典 arpspoof 特征）
 *      2b. 一对多：同一个 MAC 声称拥有多个 IP（网关欺骗的典型特征）
 *          正常主机一个 MAC 只对应 1~2 个 IP；
 *          攻击者一个 MAC 会声称拥有网关、靶机等多个 IP。
 *
 * 编译：
 *   gcc -O2 -o sniff-detector sniff-detector.c -lpcap
 *
 * 用法：
 *   ./sniff-detector -i eth0                # 全功能
 *   ./sniff-detector -i eth0 -p             # 仅 Promiscuous 检测
 *   ./sniff-detector -i eth0 -a             # 仅 ARP 欺骗检测
 *   ./sniff-detector -i eth0 -t 10.10.50.0/24  # 只探测指定网段
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if_arp.h>
#include <pcap.h>

/* ================= 常量 ================= */
#define ARP_HDR_LEN   28   /* ETHER_HDR_LEN 由 <net/ethernet.h> 提供 */
#define ARP_PKT_LEN   (ETHER_HDR_LEN + ARP_HDR_LEN)
#define PROBE_DST_MAC {0xff, 0xff, 0xff, 0xff, 0xff, 0xfe}  /* 错广播 MAC */

#define MAX_IP_ENTRIES   2048   /* IP -> MAC 表 */
#define MAX_MAC_ENTRIES  1024   /* MAC -> IP 反查表 */
#define MAC_CLAIM_THRESHOLD 3   /* 一个 MAC 声称超过 N 个 IP 就告警 */

/* ================= 数据结构 ================= */
struct arp_entry {
    uint32_t ip;
    uint8_t  mac[6];
    time_t   first;
    time_t   last;
    int      flips;      /* 该 IP 换过几次 MAC */
};

struct mac_entry {
    uint8_t  mac[6];
    uint32_t ips[16];    /* 该 MAC 声称过的 IP */
    int      n_ips;
    time_t   last;
    int      alerted;
};

struct detector_ctx {
    char     iface[32];
    uint8_t  my_mac[6];
    uint32_t my_ip;
    uint32_t my_subnet;   /* 网络字节序 */

    struct arp_entry ip_tab[MAX_IP_ENTRIES];
    int ip_n;

    struct mac_entry mac_tab[MAX_MAC_ENTRIES];
    int mac_n;

    int promisc_only;
    int arp_only;
    int verbose;

    pcap_t  *pcap;
    int      raw_sock;
};

/* ================= 工具 ================= */
/* 注意：mac_str 用两个轮换缓冲区，
   这样一次 printf("...was %s now %s", mac_str(a), mac_str(b)) 才正确。
   （用单个 static buffer 会让两个参数指向同一块内存，输出 "was X now X"）*/
static const char *mac_str(const uint8_t *m) {
    static char bufs[2][32];
    static int idx = 0;
    idx ^= 1;
    char *b = bufs[idx];
    snprintf(b, 32, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return b;
}

static const char *ip_str(uint32_t ip_net) {
    struct in_addr a = { .s_addr = ip_net };
    static char buf[32];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

static void log_msg(const char *level, const char *fmt, ...) {
    time_t t = time(NULL);
    struct tm tm;
    char ts[16];
    localtime_r(&t, &tm);
    strftime(ts, sizeof(ts), "%H:%M:%S", &tm);
    fprintf(stderr, "[%s] [%s] ", ts, level);
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fprintf(stderr, "\n");
}

#define INFO(fmt, ...)  log_msg("INFO",  fmt, ##__VA_ARGS__)
#define WARN(fmt, ...)  log_msg("WARN",  fmt, ##__VA_ARGS__)
#define ALERT(fmt, ...) log_msg("ALERT", fmt, ##__VA_ARGS__)

/* ================= 接口信息 ================= */
static int get_if_info(const char *ifname, uint8_t *mac, uint32_t *ip) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) return -1;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    memset(ifr.ifr_name, 0, IFNAMSIZ);
    strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);

    if (ioctl(s, SIOCGIFHWADDR, &ifr) != 0) { close(s); return -1; }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, 6);

    if (ioctl(s, SIOCGIFADDR, &ifr) != 0) { close(s); return -1; }
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;
    *ip = sin->sin_addr.s_addr;

    close(s);
    return 0;
}

/* ================= 构造 / 解析 ARP ================= */
static int build_arp_probe(uint8_t *pkt, const uint8_t *my_mac, uint32_t target_ip) {
    static const uint8_t probe_dst[6] = PROBE_DST_MAC;
    memset(pkt, 0, ARP_PKT_LEN);

    memcpy(pkt, probe_dst, 6);          /* dst MAC = FF:FF:FF:FF:FF:FE */
    memcpy(pkt + 6, my_mac, 6);
    uint16_t etype = htons(0x0806);
    memcpy(pkt + 12, &etype, 2);

    uint16_t htype = htons(1), ptype = htons(0x0800), op = htons(1);
    memcpy(pkt + ETHER_HDR_LEN + 0, &htype, 2);
    memcpy(pkt + ETHER_HDR_LEN + 2, &ptype, 2);
    pkt[ETHER_HDR_LEN + 4] = 6;
    pkt[ETHER_HDR_LEN + 5] = 4;
    memcpy(pkt + ETHER_HDR_LEN + 6, &op, 2);

    memcpy(pkt + ETHER_HDR_LEN + 8,  my_mac, 6);    /* sender MAC */
    memcpy(pkt + ETHER_HDR_LEN + 14, &target_ip, 4);/* sender IP  */
    memcpy(pkt + ETHER_HDR_LEN + 24, &target_ip, 4);/* target IP  */
    return ARP_PKT_LEN;
}

static void parse_arp(const uint8_t *pkt, int len,
                      uint16_t *op, uint8_t *sha, uint8_t *tha,
                      uint32_t *spa, uint32_t *tpa) {
    if (len < ETHER_HDR_LEN + ARP_HDR_LEN) {
        *op = 0; memset(sha, 0, 6); memset(tha, 0, 6); *spa = 0; *tpa = 0;
        return;
    }
    const uint8_t *a = pkt + ETHER_HDR_LEN;
    *op = ntohs(*(uint16_t *)(a + 6));
    memcpy(sha, a + 8, 6);
    memcpy(tha, a + 18, 6);
    memcpy(spa, a + 14, 4);
    memcpy(tpa, a + 24, 4);
}

/* ================= IP 表 ================= */
static struct arp_entry *ip_lookup(struct detector_ctx *c, uint32_t ip) {
    for (int i = 0; i < c->ip_n; i++)
        if (c->ip_tab[i].ip == ip) return &c->ip_tab[i];
    return NULL;
}

static void ip_update(struct detector_ctx *c, uint32_t ip, const uint8_t *mac) {
    struct arp_entry *e = ip_lookup(c, ip);
    if (e) {
        if (memcmp(e->mac, mac, 6) != 0) {
            e->flips++;
            WARN("ARP 翻转: %s 原为 %s，现为 %s  ← 疑似 ARP 欺骗",
                 ip_str(ip), mac_str(e->mac), mac_str(mac));
            memcpy(e->mac, mac, 6);
        }
        e->last = time(NULL);
        return;
    }
    if (c->ip_n >= MAX_IP_ENTRIES) return;
    e = &c->ip_tab[c->ip_n++];
    e->ip = ip;
    memcpy(e->mac, mac, 6);
    e->first = e->last = time(NULL);
    e->flips = 0;
    if (c->verbose)
        INFO("学习: %s is at %s", ip_str(ip), mac_str(mac));
}

/* ================= MAC 反查表（一对多检测） ================= */
static struct mac_entry *mac_lookup(struct detector_ctx *c, const uint8_t *mac) {
    for (int i = 0; i < c->mac_n; i++)
        if (memcmp(c->mac_tab[i].mac, mac, 6) == 0) return &c->mac_tab[i];
    return NULL;
}

static void mac_update(struct detector_ctx *c, const uint8_t *mac, uint32_t ip) {
    struct mac_entry *m = mac_lookup(c, mac);
    if (!m) {
        if (c->mac_n >= MAX_MAC_ENTRIES) return;
        m = &c->mac_tab[c->mac_n++];
        memcpy(m->mac, mac, 6);
        m->n_ips = 0;
        m->alerted = 0;
    }
    m->last = time(NULL);

    /* 该 IP 是否已记录 */
    for (int i = 0; i < m->n_ips; i++)
        if (m->ips[i] == ip) return;

    if (m->n_ips < 16) m->ips[m->n_ips++] = ip;

    /* 一个 MAC 声称拥有多个 IP → 典型的欺骗特征 */
    if (m->n_ips >= MAC_CLAIM_THRESHOLD && !m->alerted) {
        m->alerted = 1;
        char ips[256] = {0};
        for (int i = 0; i < m->n_ips; i++) {
            strncat(ips, ip_str(m->ips[i]), sizeof(ips) - strlen(ips) - 2);
            if (i < m->n_ips - 1) strncat(ips, ", ", sizeof(ips) - strlen(ips) - 2);
        }
        ALERT("一对多告警: MAC %s 声称拥有 %d 个 IP [%s]  ← 疑似 ARP 欺骗",
              mac_str(mac), m->n_ips, ips);
    } else if (c->verbose) {
        INFO("MAC %s 现在声称拥有 %s (共 %d 个 IP)",
             mac_str(mac), ip_str(ip), m->n_ips);
    }
}

/* ================= ARP 包处理 ================= */
static void handle_arp(struct detector_ctx *c, const uint8_t *pkt, int len) {
    uint16_t op; uint8_t sha[6], tha[6]; uint32_t spa, tpa;
    parse_arp(pkt, len, &op, sha, tha, &spa, &tpa);
    if (op != 1 && op != 2) return;         /* 只关心 request/reply */
    if (spa == 0) return;

    ip_update(c, spa, sha);
    mac_update(c, sha, spa);
}

/* ================= pcap 回调 ================= */
static void pcap_cb(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct detector_ctx *c = (struct detector_ctx *)user;
    if (h->caplen < ETHER_HDR_LEN + ARP_HDR_LEN) return;

    uint16_t et = ntohs(*(uint16_t *)(bytes + 12));
    if (et != 0x0806) return;

    uint16_t op; uint8_t sha[6], tha[6]; uint32_t spa, tpa;
    parse_arp(bytes, h->caplen, &op, sha, tha, &spa, &tpa);

    /* 收到 ARP Reply 说明对方响应了探测（我们发的请求目标 MAC 是错的） */
    if (op == 2 && !c->arp_only) {
        ALERT("混杂模式候选: %s 响应了错误目标 MAC 的探测包 (MAC=%s)",
              ip_str(spa), mac_str(sha));
    }

    if (!c->promisc_only)
        handle_arp(c, bytes, h->caplen);
}

/* ================= 主循环 ================= */
static volatile sig_atomic_t g_run = 1;
static pcap_t *g_pcap = NULL;

static void on_sig(int s) {
    (void)s;
    g_run = 0;
    /* 唤醒阻塞中的 pcap_next_ex，使 Ctrl+C 能立即退出。 */
    if (g_pcap != NULL) pcap_breakloop(g_pcap);
}

static void usage(const char *p) {
    fprintf(stderr,
        "用法: %s -i <接口> [-p|-a] [-t <网段>] [-q]\n"
        "  -i <接口>    监听/发送接口（默认 eth0）\n"
        "  -p           仅做 Promiscuous 模式检测\n"
        "  -a           仅做 ARP 欺骗检测\n"
        "  -t <网段>    探测网段，如 10.10.50.0/24（默认按接口 /24 推断）\n"
        "  -q           安静模式（不打印 learning 日志）\n",
        p);
}

int main(int argc, char **argv) {
    struct detector_ctx c;
    memset(&c, 0, sizeof(c));
    strncpy(c.iface, "eth0", sizeof(c.iface) - 1);
    c.verbose = 1;

    int opt;
    while ((opt = getopt(argc, argv, "i:pat:qh")) != -1) {
        switch (opt) {
            case 'i': strncpy(c.iface, optarg, sizeof(c.iface) - 1); break;
            case 'p': c.promisc_only = 1; break;
            case 'a': c.arp_only = 1; break;
            case 't': (void)optarg; break;   /* 预留：自定义探测网段 */
            case 'q': c.verbose = 0; break;
            case 'h': default: usage(argv[0]); return 2;
        }
    }

    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);

    if (get_if_info(c.iface, c.my_mac, &c.my_ip) < 0) {
        fprintf(stderr, "取不到 %s 的信息: %s\n", c.iface, strerror(errno));
        return 1;
    }
    c.my_subnet = c.my_ip & htonl(0xffffff00);

    INFO("sniff-detector 启动  接口=%s 本机=%s MAC=%s",
         c.iface, ip_str(c.my_ip), mac_str(c.my_mac));

    /* 打开 pcap，只收 ARP */
    char err[PCAP_ERRBUF_SIZE];
    c.pcap = pcap_open_live(c.iface, 65535, 1, 200, err);
    if (!c.pcap) {
        fprintf(stderr, "pcap_open_live(%s): %s\n", c.iface, err);
        return 1;
    }
    g_pcap = c.pcap;
    struct bpf_program bp;
    if (pcap_compile(c.pcap, &bp, "arp", 1, PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(c.pcap, &bp) < 0) {
        fprintf(stderr, "BPF 过滤器设置失败\n");
        return 1;
    }

    /* raw socket 发探测包 */
    c.raw_sock = socket(AF_PACKET, SOCK_RAW, htons(0x0806));
    if (c.raw_sock < 0) {
        fprintf(stderr, "需要 CAP_NET_RAW 权限: %s\n", strerror(errno));
        return 1;
    }
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(0x0806);
    sll.sll_ifindex = if_nametoindex(c.iface);
    if (bind(c.raw_sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        fprintf(stderr, "bind: %s\n", strerror(errno));
        return 1;
    }

    time_t last_probe = 0;
    int probed = 0;

    if (!c.arp_only) {
        INFO("将探测 %s.0/24 中响应错误目标 MAC 的主机（混杂模式检测）",
             ip_str(c.my_subnet));
    }
    if (!c.promisc_only) {
        INFO("正在监听 ARP 变化（ARP 欺骗检测）... Ctrl-C 停止");
    }

    while (g_run) {
        time_t now = time(NULL);

        /* 每 30 秒发一轮探测 */
        if (!c.arp_only && now - last_probe >= 30) {
            for (int i = 1; i < 255; i++) {
                uint32_t target = c.my_subnet | htonl(i);
                uint8_t pkt[ARP_PKT_LEN];
                int plen = build_arp_probe(pkt, c.my_mac, target);
                send(c.raw_sock, pkt, plen, 0);
                usleep(1500);
                probed++;
            }
            INFO("已探测 %d 个地址，等待响应 ...", probed);
            last_probe = now;
        }

        /* 收包 */
        struct pcap_pkthdr *h;
        const u_char *bytes;
        int rc;
        while ((rc = pcap_next_ex(c.pcap, &h, &bytes)) > 0)
            pcap_cb((u_char *)&c, h, bytes);
        if (rc < 0) break;

        usleep(50000);
    }

    pcap_close(c.pcap);
    g_pcap = NULL;
    close(c.raw_sock);
    INFO("退出");
    return 0;
}
