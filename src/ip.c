#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac)
{
    // TO-DO
    // Step1: 如果数据包的长度小于 IP 头部长度，丢弃不处理
    if (buf->len < sizeof(ip_hdr_t)) return;

    // Step2: 创建备份，便于发送ICMP协议不可达信息
    buf_t copy;
    buf_copy(&copy, buf, buf->len);

    // Step3: 进行报头检测，检测内容包括版本号是否为 IPv4 、总长度字段是否小于等于收到的包的长度等
    // 如果不符合这些要求，则丢弃不处理
    ip_hdr_t *hdr = (ip_hdr_t *) buf->data;
    if (hdr->version != IP_VERSION_4) return;
    if (swap16(hdr->total_len16) > buf->len) return;

    // Step4: 先把 IP 头部的头部校验和字段用其它变量保存起来，接着将该头部校验和字段置 0
    // 然后调用 checksum16 函数来计算头部校验和。如果不一致，丢弃不处理；如果一致，恢复头部校验和字段为原来的值
    uint16_t hdr_checksum16_backup = hdr->hdr_checksum16;
    hdr->hdr_checksum16 = 0;
    uint16_t hdr_checksum16 = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t));
    if (hdr_checksum16 != hdr_checksum16_backup) return;
    hdr->hdr_checksum16 = hdr_checksum16_backup;

    // Step5: 对比目的 IP 地址是否为本机 IP 地址，如果不是，则丢弃不处理
    if (memcmp(hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0) return;

    // Step6: 如果数据包长度大于 IP 头部的总长度字段，说明该数据包有填充字段，可调用 buf_remove_padding 函数去除填充字段
    if (buf->len > swap16(hdr->total_len16)) buf_remove_padding(buf, buf->len - swap16(hdr->total_len16));

    // Step7: 调用 buf_remove_header 函数去除 IP 报头
    uint8_t protocol = hdr->protocol;
    uint8_t *src_ip = hdr->src_ip;
    buf_remove_header(buf, hdr->hdr_len * 4);

    // Step8: 调用 net_in 函数向上层传递数据包
    // 如果是不能识别的协议类型，则调用 icmp_unreachable 函数返回ICMP协议不可达信息。
    int flag = net_in(buf, protocol, src_ip);
    if (flag == -1)
        icmp_unreachable(&copy, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
}

/**
 * @brief 处理一个要发送的ip分片
 * 
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id, uint16_t offset, int mf)
{
    // TO-DO
    // Step1: 调用 buf_add_header 增加IP数据报头部缓存空间
    buf_add_header(buf, sizeof(ip_hdr_t));

    // Step2: 填写 IP 数据报头部字段
    ip_hdr_t *hdr = (ip_hdr_t *) buf->data;
    hdr->version = IP_VERSION_4;
    hdr->hdr_len = sizeof(ip_hdr_t) / 4;
    hdr->tos = 0;
    hdr->total_len16 = swap16(buf->len);
    hdr->id16 = swap16(id);
    hdr->flags_fragment16 = swap16((mf ? IP_MORE_FRAGMENT : 0) | offset);
    hdr->ttl = 64;
    hdr->protocol = protocol;
    memcpy(hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(hdr->dst_ip, ip, NET_IP_LEN);

    // Step3: 先把IP头部的首部校验和字段填0，再调用checksum16函数计算校验和
    // 然后把计算出来的校验和填入首部校验和字段
    hdr->hdr_checksum16 = 0;
    uint16_t new_checksum = checksum16((uint16_t *)hdr, sizeof(ip_hdr_t));
    hdr->hdr_checksum16 = new_checksum;

    // Step4: 调用 arp_out 函数将封装后的IP头部和数据发送出去
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 * 
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol)
{
    // TO-DO
    // Step1: 求出IP协议最大负载包长（1500字节，即MTU大小，减去IP首部长度）
    int max_load_length = 1500 - sizeof(ip_hdr_t);

    // Step2: 如果数据包长度超过IP协议的最大负载包长，则需要分片发送
    int i;
    static int id = 0;
    for (i = 0; (i + 1) * max_load_length < buf->len; i++)
    {
        buf_t ip_buf;
        buf_init(&ip_buf, max_load_length);
        memcpy(ip_buf.data, buf->data + i * max_load_length, max_load_length);
        ip_fragment_out(&ip_buf, ip, protocol, id, i * (max_load_length >> 3), 1);
    }

    // Step3: 对于没有超过IP协议最大负载包长的数据包，或者分片后的最后的一个分片小于或等于IP协议最大负载包长的数据包，统一再进行一次发送
    // 由于两种情况下都是发送最后一个分片，因此需要设置MF为0
    buf_t ip_buf;
    buf_init(&ip_buf, buf->len - i * max_load_length);
    memcpy(ip_buf.data, buf->data + i * max_load_length, buf->len - i * max_load_length);
    ip_fragment_out(&ip_buf, ip, protocol, id, i * (max_load_length >> 3), 0);

    id++;
}

/**
 * @brief 初始化ip协议
 * 
 */
void ip_init()
{
    net_add_protocol(NET_PROTOCOL_IP, ip_in);
}