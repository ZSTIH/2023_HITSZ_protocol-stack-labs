#include <string.h>
#include <stdio.h>
#include "net.h"
#include "arp.h"
#include "ethernet.h"
/**
 * @brief 初始的arp包
 * 
 */
static const arp_pkt_t arp_init_pkt = {
    .hw_type16 = constswap16(ARP_HW_ETHER),
    .pro_type16 = constswap16(NET_PROTOCOL_IP),
    .hw_len = NET_MAC_LEN,
    .pro_len = NET_IP_LEN,
    .sender_ip = NET_IF_IP,
    .sender_mac = NET_IF_MAC,
    .target_mac = {0}};

/**
 * @brief arp地址转换表，<ip,mac>的容器
 * 
 */
map_t arp_table;

/**
 * @brief arp buffer，<ip,buf_t>的容器
 * 
 */
map_t arp_buf;

/**
 * @brief 打印一条arp表项
 * 
 * @param ip 表项的ip地址
 * @param mac 表项的mac地址
 * @param timestamp 表项的更新时间
 */
void arp_entry_print(void *ip, void *mac, time_t *timestamp)
{
    printf("%s | %s | %s\n", iptos(ip), mactos(mac), timetos(*timestamp));
}

/**
 * @brief 打印整个arp表
 * 
 */
void arp_print()
{
    printf("===ARP TABLE BEGIN===\n");
    map_foreach(&arp_table, arp_entry_print);
    printf("===ARP TABLE  END ===\n");
}

/**
 * @brief 发送一个arp请求
 * 
 * @param target_ip 想要知道的目标的ip地址
 */
void arp_req(uint8_t *target_ip)
{
    // TO-DO
    // Step1: 对 txbuf 进行初始化
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // Step2: 填写 ARP 报头
    arp_pkt_t *pkt = (arp_pkt_t *) txbuf.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));

    // Step3: 修改 ARP 报头的操作类型为 ARP_REQUEST，并修改目的 IP 地址为 target_ip
    pkt->opcode16 = swap16(ARP_REQUEST);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);

    // Step4: 调用 ethernet_out 函数将 ARP 报文发送出去
    ethernet_out(&txbuf, ether_broadcast_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 发送一个arp响应
 * 
 * @param target_ip 目标ip地址
 * @param target_mac 目标mac地址
 */
void arp_resp(uint8_t *target_ip, uint8_t *target_mac)
{
    // TO-DO
    // Step1: 初始化 txbuf
    buf_init(&txbuf, sizeof(arp_pkt_t));

    // Step2: 填写 ARP 报头
    arp_pkt_t *pkt = (arp_pkt_t *) txbuf.data;
    memcpy(pkt, &arp_init_pkt, sizeof(arp_pkt_t));

    // Step3: 修改 ARP 报头的操作类型为 ARP_REPLY，并修改目的 IP 地址为 target_ip、目的 MAC 地址为 target_mac
    pkt->opcode16 = swap16(ARP_REPLY);
    memcpy(pkt->target_ip, target_ip, NET_IP_LEN);
    memcpy(pkt->target_mac, target_mac, NET_MAC_LEN);

    // Step4: 调用 ethernet_out 函数将 ARP 报文发送出去
    ethernet_out(&txbuf, target_mac, NET_PROTOCOL_ARP);
}

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void arp_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // Step1: 首先判断数据长度，如果数据长度小于 ARP 头部长度，认为数据包不完整，丢弃不处理
    if (buf->len < sizeof(arp_pkt_t))
    {
        return;
    }

    // Step2: 做报头检查，检测 ARP 报头的硬件类型、上层协议类型、MAC 硬件地址长度、IP 协议地址长度、操作类型等是否符合协议规定
    arp_pkt_t *arp_pkt = (arp_pkt_t *) buf->data;
    if (arp_pkt->hw_type16 != swap16(ARP_HW_ETHER)) return;
    if (arp_pkt->pro_type16 != swap16(NET_PROTOCOL_IP)) return;
    if (arp_pkt->hw_len != NET_MAC_LEN) return;
    if (arp_pkt->pro_len != NET_IP_LEN) return;
    if (arp_pkt->opcode16 != swap16(ARP_REQUEST) && arp_pkt->opcode16 != swap16(ARP_REPLY)) return;

    // Step3: 更新 ARP 表项
    map_set(&arp_table, arp_pkt->sender_ip, arp_pkt->sender_mac);

    // Step4: 查看该接收报文的 IP 地址是否有对应的 arp_buf 缓存
    buf_t *buf2 = (buf_t *) map_get(&arp_buf, arp_pkt->sender_ip);
    if (buf2 != NULL)
    {
        // 如果有，说明上一次调用 arp_out 函数发送数据包时，由于没有找到对应的 MAC 地址故先发送了 ARP request 报文
        // 此时收到了该request的应答报文，因此需要将缓存的数据包发送给以太网层，再将这个缓存的数据包删除掉
        ethernet_out(buf2, arp_pkt->sender_mac, NET_PROTOCOL_IP);
        map_delete(&arp_buf, arp_pkt->sender_ip);
    }
    else
    {
        // 如果没有，还需要判断接收到的报文是否为 ARP_REQUEST 请求报文，并且该请求报文的 target_ip 是本机的 IP
        if (arp_pkt->opcode16 == swap16(ARP_REQUEST) && memcmp(arp_pkt->target_ip, net_if_ip, NET_IP_LEN) == 0)
        {
            // 如果是，回应一个 ARP 响应报文
            arp_resp(arp_pkt->sender_ip, arp_pkt->sender_mac);
        }
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void arp_out(buf_t *buf, uint8_t *ip)
{
    // TO-DO
    // Step1: 根据 IP 地址来查找 ARP 表
    uint8_t *mac = (uint8_t *) map_get(&arp_table, ip);

    if (mac != NULL)
    {
        // Step2: 如果能找到该 IP 地址对应的 MAC 地址，直接调用 ethernet_out 函数将数据包发送给以太网层
        ethernet_out(buf, mac, NET_PROTOCOL_IP);
    }
    else
    {
        // Step3: 如果没有找到对应的 MAC 地址，先判断 arp_buf 是否已经有包了
        buf_t *buf2 = (buf_t *) map_get(&arp_buf, ip);
        if (buf2 != NULL)
        {
            // 如果有，说明正在等待该 IP 回应 ARP 请求，此时不能再发送 ARP 请求
            return;
        }
        else
        {
            // 如果没有，则将来自 IP 层的数据包缓存到 arp_buf，发送一个请求与目标 IP 地址对应的 MAC 地址的 ARP 请求报文
            map_set(&arp_buf, ip, buf);
            arp_req(ip);
        }
    }
}

/**
 * @brief 初始化arp协议
 * 
 */
void arp_init()
{
    map_init(&arp_table, NET_IP_LEN, NET_MAC_LEN, 0, ARP_TIMEOUT_SEC, NULL);
    map_init(&arp_buf, NET_IP_LEN, sizeof(buf_t), 0, ARP_MIN_INTERVAL, buf_copy);
    net_add_protocol(NET_PROTOCOL_ARP, arp_in);
    arp_req(net_if_ip);
}