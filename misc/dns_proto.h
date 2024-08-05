//
// Created by zxe on 2024/8/5.
//

#ifndef MY_BADVPN_DNS_PROTO_H
#define MY_BADVPN_DNS_PROTO_H


#include <stdint.h>

#include <misc/debug.h>
#include <misc/byteorder.h>
#include <misc/ipv4_proto.h>
#include <misc/ipv6_proto.h>
#include <misc/read_write_int.h>


B_START_PACKED
struct dns_header_t {
    uint16_t id;
    uint8_t qr_opcode_aa_tc_rd;
    uint8_t ra_z_rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount; // may be >0 for EDNS queries
} B_PACKED;

struct dns_header
{
    unsigned short id; // identification number

    unsigned char rd :1; // recursion desired
    unsigned char tc :1; // truncated message
    unsigned char aa :1; // authoritive answer
    unsigned char opcode :4; // purpose of message
    unsigned char qr :1; // query/response flag

    unsigned char rcode :4; // response code
    unsigned char cd :1; // checking disabled
    unsigned char ad :1; // authenticated data
    unsigned char z :1; // its z! reserved
    unsigned char ra :1; // recursion available

    unsigned short q_count; // number of question entries
    unsigned short ans_count; // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count; // number of resource entries
} B_PACKED;
B_END_PACKED

#define DNS_QR 0x80
#define DNS_TC 0x02
#define DNS_Z  0x70

#endif //MY_BADVPN_DNS_PROTO_H
