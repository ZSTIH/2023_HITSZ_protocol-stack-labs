#include "ethernet.h"
#include "utils.h"
#include "driver.h"
#include "arp.h"
#include "ip.h"
/**
 * @brief 处理一个收到的数据包
 * 
 * @param buf 要处理的数据包
 */
void ethernet_in(buf_t *buf)
{
    // TO-DO
    // Step1: 判断数据长度，若数据小于以太网头部长度，则认为数据包不完整，丢弃不处理
    if (buf->len < sizeof(ether_hdr_t))
    {
        return;
    }

    // Step2: 解析以太网包头，获得协议类型、源 MAC 地址，再移除以太网包头
    ether_hdr_t *hdr = (ether_hdr_t *) buf->data;
    net_protocol_t protocol = swap16(hdr->protocol16);
    uint8_t *src = hdr->src;
    buf_remove_header(buf, sizeof(ether_hdr_t));

    // Step3: 向上层传递数据包
    net_in(buf, protocol, src);
}
/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的数据包
 * @param mac 目标MAC地址
 * @param protocol 上层协议
 */
void ethernet_out(buf_t *buf, const uint8_t *mac, net_protocol_t protocol)
{
    // TO-DO
    // Step1: 判断数据长度，如果不足46则显示填充0
    if (buf->len < 46)
    {
        size_t len_padding = 46 - buf->len;
        buf_add_padding(buf, len_padding);
    }

    // Step2: 添加以太网包头
    buf_add_header(buf, sizeof(ether_hdr_t));
    ether_hdr_t *hdr = (ether_hdr_t *) buf->data;

    // Step3: 填写目的 MAC 地址
    memcpy(hdr->dst, mac, NET_MAC_LEN);

    // Step4: 填写源 MAC 地址
    memcpy(hdr->src, net_if_mac, NET_MAC_LEN);

    // Step5: 填写协议类型 protocol
    hdr->protocol16 = swap16(protocol);

    // Step6: 将添加了以太网包头的数据帧发送到驱动层
    driver_send(buf);
}
/**
 * @brief 初始化以太网协议
 * 
 */
void ethernet_init()
{
    buf_init(&rxbuf, ETHERNET_MAX_TRANSPORT_UNIT + sizeof(ether_hdr_t));
}

/**
 * @brief 一次以太网轮询
 * 
 */
void ethernet_poll()
{
    if (driver_recv(&rxbuf) > 0)
        ethernet_in(&rxbuf);
}
