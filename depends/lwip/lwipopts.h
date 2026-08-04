/*=============================================================================
Copyright (c) 2024-2026 Stas Skokov

Distributed under the MIT License (https://opensource.org/licenses/MIT)
=============================================================================*/

/*
 * FPTN lwIP configuration (PR-LW1).
 *
 * NO_SYS raw-callback stack for the FlowProxy data plane: one Asio strand
 * owns all stack access, so no locks, sockets, or netconn layers.
 * Sizing is deliberately bounded for the Network Extension memory budget.
 */

#ifndef FPTN_LWIP_LWIPOPTS_H
#define FPTN_LWIP_LWIPOPTS_H

/* Platform / execution model */
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_TCPIP_CORE_LOCKING 0
#define LWIP_NETCONN 0
#define LWIP_SOCKET 0
#define LWIP_NETIF_API 0

/* Protocols */
#define LWIP_IPV4 1
#define LWIP_IPV6 1
#define LWIP_TCP 1
#define LWIP_UDP 1
#define LWIP_ICMP 1
#define LWIP_RAW 0
#define LWIP_DNS 0
#define LWIP_DHCP 0
#define LWIP_IPV6_DHCP6 0
#define LWIP_AUTOIP 0
#define LWIP_ACD 0
#define LWIP_IGMP 0
#define LWIP_IPV6_MLD 0
#define LWIP_ARP 0
#define LWIP_ETHERNET 0
#define LWIP_ALTCP 0
#define LWIP_STATS 0
#define LWIP_HAVE_LOOPIF 0
#define LWIP_NETIF_HOSTNAME 0
#define LWIP_NETIF_STATUS_CALLBACK 0
#define LWIP_NETIF_LINK_CALLBACK 0

/* Alignment */
#define MEM_ALIGNMENT 8

/* BSD system headers (via Boost.Asio) define TCP_MSS as a socket option
 * and provide htons/ntohs/htonl/ntohl; avoid macro collisions. */
#ifdef TCP_MSS
#undef TCP_MSS
#endif
#define LWIP_DONT_PROVIDE_BYTEORDER_FUNCTIONS 1

/* Memory: bounded pools; ingress borrows caller buffers via custom pbufs,
 * so the pool mainly serves stack-internal and egress allocations. */
#define MEM_SIZE (256 * 1024)
#define MEMP_NUM_PBUF 512
#define PBUF_POOL_SIZE 256
#define MEMP_NUM_TCP_PCB 128
#define MEMP_NUM_TCP_PCB_LISTEN 4
#define MEMP_NUM_TCP_SEG 512
#define MEMP_NUM_UDP_PCB 64
#define MEMP_NUM_SYS_TIMEOUT 64
#define MEMP_NUM_FRAG_PBUF 32

/* TCP: MTU 1400 at the NEPacketTunnelFlow boundary -> MSS 1360 (IPv6-safe). */
#define TCP_MSS 1360
#define TCP_WND (32 * TCP_MSS)
#define TCP_SND_BUF (32 * TCP_MSS)
#define TCP_SND_QUEUELEN ((4 * (TCP_SND_BUF) + (TCP_MSS - 1)) / (TCP_MSS))
#define LWIP_TCP_KEEPALIVE 1

/* IPv6 */
#define LWIP_ND6 1
#define LWIP_IPV6_SEND_ROUTER_SOLICIT 0

/* Platform hooks (LWIP_RAND, assert/diag) live in arch/cc.h;
 * sys_now()/fptn_lwip_rand() are implemented in fptn_lwip_port.c. */

#endif /* FPTN_LWIP_LWIPOPTS_H */
