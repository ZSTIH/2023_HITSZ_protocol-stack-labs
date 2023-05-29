#ifndef TCP_H
#define TCP_H

#include "net.h"

#pragma pack(1)

typedef struct tcp_flags {
    uint8_t fin : 1;    // 释放连接
    uint8_t syn : 1;    // 连接/接受连接
    uint8_t rst : 1;    // 出错, 重新连接
    uint8_t psh : 1;    // Push function. 不需要等待缓冲区满就转发给应用层
    uint8_t ack : 1;    // 确认字段有效
    uint8_t urg : 1;    // 紧急
    uint8_t ece : 1;    // ECN-Echo 
    uint8_t cwr : 1;    // congestion window reduced 
} tcp_flags_t;

static const tcp_flags_t tcp_flags_null = {};
static const tcp_flags_t tcp_flags_ack = { .ack = 1 };
static const tcp_flags_t tcp_flags_ack_syn = { .ack = 1 ,.syn = 1 };
static const tcp_flags_t tcp_flags_ack_fin = { .ack = 1, .fin = 1 };
static const tcp_flags_t tcp_flags_ack_rst = { .ack = 1 ,.rst = 1 };

typedef struct tcp_hdr {
    uint16_t src_port16;
    uint16_t dst_port16;
    uint32_t seq_number32;
    uint32_t ack_number32;
    uint8_t reserved : 4;   // 置零
    uint8_t data_offset : 4;// 这个头有多少个32位字长, 后面的是数据
    tcp_flags_t flags;
    uint16_t window_size16; // 接收窗口大小, 流量控制用
    uint16_t checksum16;    // 校验和
    uint16_t urgent_pointer16;
} tcp_hdr_t;

typedef struct tcp_peso_hdr {
    uint8_t src_ip[4];    // 源IP地址
    uint8_t dst_ip[4];    // 目的IP地址
    uint8_t placeholder;  // 必须置0,用于填充对齐
    uint8_t protocol;     // 协议号
    uint16_t total_len16; // 整个数据包的长度
} tcp_peso_hdr_t;

#pragma pack()


typedef enum tcp_state {
    // 不使用状态 TCP_CLOSED,
    TCP_LISTEN = 0, /* 初始化的状态，没有分配缓存。处于这个状态时 tcp_connect_t 其他字段全是无效的
                        其他状态rx_buf、tx_buf都在堆上动态分配了缓存，因此释放时要调用释放函数。
                    */
    TCP_SYN_SEND,
    TCP_SYN_RCVD,
    TCP_ESTABLISHED,
    TCP_CLOSE_WAIT,
    TCP_LAST_ACK,
    TCP_FIN_WAIT_1,
    TCP_FIN_WAIT_2,
    TCP_CLOSING,
    TCP_TIME_WAIT,
} tcp_state_t;

typedef struct tcp_key {
    uint8_t ip[NET_IP_LEN];
    uint16_t src_port;
    uint16_t dst_port;
} tcp_key_t;

typedef struct tcp_connect {
    tcp_state_t state;
    uint16_t local_port, remote_port;
    uint8_t ip[NET_IP_LEN];
    uint32_t unack_seq, next_seq; // tx_buf中前[next_seq - unack_seq]字节已经发送，unack_seq未确认的起始序号，next_seq下一发送序号
    uint32_t ack;
    uint16_t remote_mss;
    uint16_t remote_win;
    void* handler;
    buf_t* rx_buf; // 接收缓存
    buf_t* tx_buf; // 发送缓存
} tcp_connect_t;

static const tcp_connect_t CONNECT_LISTEN = {
    .state = TCP_LISTEN,
};

typedef enum connect_state {
    // 刚刚建立连接
    TCP_CONN_CONNECTED,
    // 收到数据
    TCP_CONN_DATA_RECV,
    // 关闭连接
    TCP_CONN_CLOSED,
} connect_state_t;

typedef void (*tcp_handler_t)(tcp_connect_t* conect, connect_state_t state);

void tcp_init();
int tcp_open(uint16_t port, tcp_handler_t handler);
void tcp_close(uint16_t port);
void tcp_connect_close(tcp_connect_t* connect);
size_t tcp_connect_write(tcp_connect_t* connect, const uint8_t* data, size_t len);
size_t tcp_connect_read(tcp_connect_t* connect, uint8_t* data, size_t len);
void tcp_in(buf_t* buf, uint8_t* src_ip);

#endif
