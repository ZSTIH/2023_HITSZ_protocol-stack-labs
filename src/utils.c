#include "utils.h"
#include <stdio.h>
#include <string.h>
/**
 * @brief ip转字符串
 * 
 * @param ip ip地址
 * @return char* 生成的字符串
 */
char *iptos(uint8_t *ip)
{
    static char output[3 * 4 + 3 + 1];
    sprintf(output, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    return output;
}

/**
 * @brief mac转字符串
 * 
 * @param mac mac地址
 * @return char* 生成的字符串
 */
char *mactos(uint8_t *mac)
{
    static char output[2 * 6 + 5 + 1];
    sprintf(output, "%02X-%02X-%02X-%02X-%02X-%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return output;
}

/**
 * @brief 时间戳转字符串
 * 
 * @param timestamp 时间戳
 * @return char* 生成的字符串
 */
char *timetos(time_t timestamp)
{
    static char output[20];
    struct tm *utc_time = gmtime(&timestamp);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-overflow"
    sprintf(output, "%04d-%02d-%02d %02d:%02d:%02d", utc_time->tm_year + 1900, utc_time->tm_mon + 1, utc_time->tm_mday, utc_time->tm_hour, utc_time->tm_min, utc_time->tm_sec);
    return output;
#pragma GCC diagnostic pop
}

/**
 * @brief ip前缀匹配
 * 
 * @param ipa 第一个ip
 * @param ipb 第二个ip
 * @return uint8_t 两个ip相同的前缀长度
 */
uint8_t ip_prefix_match(uint8_t *ipa, uint8_t *ipb)
{
    uint8_t count = 0;
    for (size_t i = 0; i < 4; i++)
    {
        uint8_t flag = ipa[i] ^ ipb[i];
        for (size_t j = 0; j < 8; j++)
        {
            if (flag & (1 << 7))
                return count;
            else
                count++, flag <<= 1;
        }
    }
    return count;
}

/**
 * @brief 计算16位校验和
 * 
 * @param buf 要计算的数据包
 * @param len 要计算的长度
 * @return uint16_t 校验和
 */
uint16_t checksum16(uint16_t *data, size_t len)
{
    // TO-DO
    uint32_t sum = 0;
    // Step1: 把 data 看出是每两个字节组成一个数，不断累加；若最后剩下一个字节的值，也要相加这个值
    // 由于 16 位加法可能会溢出，因此结果 sum 要用 32 位来保存
    for (int i = 0; i < len; i += 2)
    {
        if (i == len - 1)
        {
            // i 为 (len - 1) 说明此时还剩余 8 位没有加，故需要再加上
            sum += *((uint8_t *)data + i);
        }
        else
        {
            sum += data[i / 2];
        }
    }

    // Step2: 判断相加后的结果的高 16 位是否为 0
    // 如果不为 0 ，则将高 16 位和低 16 位相加，依次循环，直至高 16 位为 0 为止
    while ((sum >> 16) != 0)
    {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    // Step3: 将上述和的低 16 位进行取反，得到校验和
    return (~sum) & 0xFFFF;
}