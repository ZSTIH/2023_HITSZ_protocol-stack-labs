#include "udp.h"
#include "ip.h"
#include "icmp.h"

/**
 * @brief udp处理程序表
 * 
 */
map_t udp_table;

/**
 * @brief udp伪校验和计算
 * 
 * @param buf 要计算的包
 * @param src_ip 源ip地址
 * @param dst_ip 目的ip地址
 * @return uint16_t 伪校验和
 */
static uint16_t udp_checksum(buf_t *buf, uint8_t *src_ip, uint8_t *dst_ip)
{
    // TO-DO
    // Step1: 调用buf_add_header函数增加UDP伪头部
    // 由于计算长度时不包含伪头部和任何填充的数据，因此需要预先暂存原有长度
    uint16_t len_backup = swap16(buf->len);
    udp_hdr_t *hdr = (udp_hdr_t *) buf->data;
    buf_add_header(buf, sizeof(udp_peso_hdr_t));

    // Step2: 将被UDP伪头部覆盖的IP头部拷贝出来，暂存IP头部，以免被覆盖
    udp_peso_hdr_t phdr_backup;
    memcpy(&phdr_backup, buf->data, sizeof(udp_peso_hdr_t));

    // Step3: 填写UDP伪头部的12字节字段
    udp_peso_hdr_t *phdr = (udp_peso_hdr_t *) buf->data;
    memcpy(phdr->src_ip, src_ip, NET_IP_LEN);
    memcpy(phdr->dst_ip, dst_ip, NET_IP_LEN);
    phdr->placeholder = 0;
    phdr->protocol = NET_PROTOCOL_UDP;
    phdr->total_len16 = len_backup;

    // Step4: 计算UDP校验和
    hdr->checksum16 = 0;
    hdr->checksum16 = checksum16((uint16_t *) buf->data, buf->len);

    // Step5: 再将 Step2 中暂存的IP头部拷贝回来
    memcpy(buf->data, &phdr_backup, sizeof(udp_peso_hdr_t));

    // Step6: 调用buf_remove_header函数去掉UDP伪头部
    buf_remove_header(buf, sizeof(udp_peso_hdr_t));

    return hdr->checksum16;
}

/**
 * @brief 处理一个收到的udp数据包
 * 
 * @param buf 要处理的包
 * @param src_ip 源ip地址
 */
void udp_in(buf_t *buf, uint8_t *src_ip)
{
    // TO-DO
    // Step1: 首先做包检查，检测该数据报的长度是否小于UDP首部长度，
    // 或者接收到的包长度小于UDP首部长度字段给出的长度，如果是，则丢弃不处理
    if (buf->len < sizeof(udp_hdr_t)) return;

    // Step2: 接着重新计算校验和，先把首部的校验和字段保存起来，
    // 然后把该字段填充0，调用udp_checksum函数计算出校验和，
    // 如果该值与接收到的UDP数据报的校验和不一致，则丢弃不处理
    udp_hdr_t *hdr = (udp_hdr_t *) buf->data;
    uint16_t checksum_backup = hdr->checksum16;
    hdr->checksum16 = 0;
    uint16_t checksum = udp_checksum(buf, src_ip, net_if_ip);
    if (checksum != checksum_backup) return;
    hdr->checksum16 = checksum;

    // Step3: 调用map_get函数查询udp_table是否有该目的端口号对应的处理函数（回调函数）
    uint16_t dst_port = swap16(hdr->dst_port16);
    udp_handler_t *handler = map_get(&udp_table, &dst_port);
    if (handler == NULL)
    {
        // Step4: 如果没有找到，则调用buf_add_header函数增加IPv4数据报头部，
        // 再调用icmp_unreachable函数发送一个端口不可达的ICMP差错报文
        buf_add_header(buf, sizeof(ip_hdr_t));
        icmp_unreachable(buf, net_if_ip, ICMP_CODE_PORT_UNREACH);
    }
    else
    {
        // Step5: 如果能找到，则去掉UDP报头，调用处理函数来做相应处理
        buf_remove_header(buf, sizeof(udp_hdr_t));
        (* handler)(buf->data, buf->len, src_ip, swap16(hdr->src_port16));
    }
}

/**
 * @brief 处理一个要发送的数据包
 * 
 * @param buf 要处理的包
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_out(buf_t *buf, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    // TO-DO
    // Step1: 首先调用buf_add_header函数添加UDP报头
    buf_add_header(buf, sizeof(udp_hdr_t));

    // Step2: 接着，填充UDP首部字段
    udp_hdr_t *hdr = (udp_hdr_t *) buf->data;
    hdr->src_port16 = swap16(src_port);
    hdr->dst_port16 = swap16(dst_port);
    hdr->total_len16 = swap16(buf->len);

    // Step3: 计算校验和
    hdr->checksum16 = 0;
    hdr->checksum16 = udp_checksum(buf, net_if_ip, dst_ip);

    // Step4: 调用ip_out()函数发送UDP数据报
    ip_out(buf, dst_ip, NET_PROTOCOL_UDP);
}

/**
 * @brief 初始化udp协议
 * 
 */
void udp_init()
{
    map_init(&udp_table, sizeof(uint16_t), sizeof(udp_handler_t), 0, 0, NULL);
    net_add_protocol(NET_PROTOCOL_UDP, udp_in);
}

/**
 * @brief 打开一个udp端口并注册处理程序
 * 
 * @param port 端口号
 * @param handler 处理程序
 * @return int 成功为0，失败为-1
 */
int udp_open(uint16_t port, udp_handler_t handler)
{
    return map_set(&udp_table, &port, &handler);
}

/**
 * @brief 关闭一个udp端口
 * 
 * @param port 端口号
 */
void udp_close(uint16_t port)
{
    map_delete(&udp_table, &port);
}

/**
 * @brief 发送一个udp包
 * 
 * @param data 要发送的数据
 * @param len 数据长度
 * @param src_port 源端口号
 * @param dst_ip 目的ip地址
 * @param dst_port 目的端口号
 */
void udp_send(uint8_t *data, uint16_t len, uint16_t src_port, uint8_t *dst_ip, uint16_t dst_port)
{
    buf_init(&txbuf, len);
    memcpy(txbuf.data, data, len);
    udp_out(&txbuf, src_port, dst_ip, dst_port);
}