/*
* Copyright 2020-2021 Open Networking Foundation
* Copyright 2021-present Princeton University
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*   http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*
*/
#ifndef __PARSER__
#define __PARSER__

#include "define.p4"
#include "header.p4"


//------------------------------------------------------------------------------
// PARSER
//------------------------------------------------------------------------------
parser ParserImpl (packet_in packet,
                   out parsed_headers_t hdr,
                   out local_metadata_t local_meta,
                   out ingress_intrinsic_metadata_t std_meta)
{
    Checksum() ipv4_checksum;
    Checksum() gtp_ipv4_checksum;
    Checksum() tcp_checksum;
    Checksum() gtp_tcp_checksum;
    Checksum() udp_checksum;
    Checksum() gtp_udp_checksum;

    // We assume the first header will always be the Ethernet one, unless the
    // the packet is a packet-out coming from the CPU_PORT.
    // 首选判断该数据包是否从控制面发送而来
    state start {
        // transition select(std_meta.ingress_port) {
        //     CPU_PORT: parse_packet_out;
        //     default: parse_ethernet;
        // }
        packet.extract(std_meta);
        packet.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }
    
    // state parse_packet_out {
    //     packet.extract(hdr.packet_out);
    //     transition parse_ethernet;
    // }

    // 解析 二层包头
    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            EtherType.IPV4: parse_ipv4; // 跳转到IPv4
            default: accept;
        }
    }
    // 解析 Ipv4 
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        ipv4_checksum.add(hdr.ipv4);
        local_meta.checksum_err_ipv4_igprs = ipv4_checksum.verify();
        tcp_checksum.subtract({hdr.ipv4.src_addr});
        udp_checksum.subtract({hdr.ipv4.src_addr});
        //packet.extract(hdr.outer_ipv4_option);
        transition select(hdr.ipv4.proto) { // ip上层协议
            IpProtocol.UDP:  parse_udp; 
            IpProtocol.TCP:  parse_tcp;
            IpProtocol.ICMP: parse_icmp;
            default: accept;
        }
    }

    // Eventualy add VLAN header parsing

    // 解析外层udp
    state parse_udp {
        packet.extract(hdr.udp);
        udp_checksum.subtract({hdr.udp.checksum});
        udp_checksum.subtract({hdr.udp.sport});
        local_meta.checksum_udp_tmp = udp_checksum.get();
        // note: this eventually wont work
        local_meta.l4_sport = hdr.udp.sport; // 将l4_sport赋值为外层udp源端口
        local_meta.l4_dport = hdr.udp.dport; // 将l4_dport赋值为外层udp目的端口
        gtpu_t gtpu = packet.lookahead<gtpu_t>(); // 向前看 gtpu_t 大小的数据，并将该数据返回
        // TODO：设置对gtpu的校验
        transition select(hdr.udp.dport, gtpu.version, gtpu.msgtype) {
            (L4Port.IPV4_IN_UDP, _, _): parse_inner_ipv4; // 如果是ipv4 in UDP，则直接解析ipv4
            // Treat GTP control traffic as payload.
            (L4Port.GTP_GPDU, GTP_V1, GTPUMessageType.GPDU): parse_gtpu; // 如果是GTP协议，解析
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        tcp_checksum.subtract({hdr.tcp.checksum});
        tcp_checksum.subtract({hdr.tcp.sport});
        local_meta.checksum_tcp_tmp = tcp_checksum.get();
        local_meta.l4_sport = hdr.tcp.sport;// 将l4_sport赋值为外层tcp源端口
        local_meta.l4_dport = hdr.tcp.dport;// 将l4_dport赋值为外层udp目的端口
        transition accept;
    }

    state parse_icmp {
        packet.extract(hdr.icmp);
        transition accept;
    }

    // 解析GTP-U
    state parse_gtpu {
        packet.extract(hdr.gtpu); 
        local_meta.teid = hdr.gtpu.teid; //记录tedi
        transition select(hdr.gtpu.ex_flag, hdr.gtpu.seq_flag, hdr.gtpu.npdu_flag) { // 根据gtp协议的option来决定下一步
            (0, 0, 0): parse_inner_ipv4; 
            default: parse_gtpu_options;
        }
    }

    state parse_gtpu_options {
        packet.extract(hdr.gtpu_options);
        bit<8> gtpu_ext_len = packet.lookahead<bit<8>>();
        transition select(hdr.gtpu_options.next_ext, gtpu_ext_len) {
            (GTPU_NEXT_EXT_PSC, GTPU_EXT_PSC_LEN): parse_gtpu_ext_psc;
            default: accept;
        }
    }

    state parse_gtpu_ext_psc {
        packet.extract(hdr.gtpu_ext_psc);
        transition select(hdr.gtpu_ext_psc.next_ext) {
            GTPU_NEXT_EXT_NONE: parse_inner_ipv4; // gtp协议到头，开始解析内部协议
            default: accept;
        }
    }

    //-----------------
    // Inner packet
    //-----------------

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        gtp_ipv4_checksum.add(hdr.inner_ipv4);
        local_meta.checksum_err_gtp_ipv4_igprs = gtp_ipv4_checksum.verify();
        gtp_tcp_checksum.subtract({hdr.inner_ipv4.src_addr});
        gtp_udp_checksum.subtract({hdr.inner_ipv4.src_addr});
        transition select(hdr.inner_ipv4.proto) {
            IpProtocol.UDP:  parse_inner_udp; 
            IpProtocol.TCP:  parse_inner_tcp;
            IpProtocol.ICMP: parse_inner_icmp;
            default: accept;
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        gtp_udp_checksum.subtract({hdr.inner_udp.checksum});
        gtp_udp_checksum.subtract({hdr.inner_udp.sport});
        local_meta.checksum_gtp_udp_tmp = udp_checksum.get();
        local_meta.l4_sport = hdr.inner_udp.sport; //将l4_sport赋值为内层udp源端口
        local_meta.l4_dport = hdr.inner_udp.dport; //将l4_dport赋值为内层udp目的端口
        transition accept;
    }

    state parse_inner_tcp {
        packet.extract(hdr.inner_tcp);
        tcp_checksum.subtract({hdr.inner_tcp.checksum});
        tcp_checksum.subtract({hdr.inner_tcp.sport});
        local_meta.checksum_tcp_tmp = tcp_checksum.get();
        local_meta.l4_sport = hdr.inner_tcp.sport;
        local_meta.l4_dport = hdr.inner_tcp.dport;
        transition accept;
    }

    state parse_inner_icmp {
        packet.extract(hdr.inner_icmp);
        transition accept;
    }
}

//------------------------------------------------------------------------------
// DEPARSER
//------------------------------------------------------------------------------
control DeparserImpl(packet_out packet, inout parsed_headers_t hdr, in local_metadata_t local_meta,
                              in ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md) {
    Checksum() ipv4_checksum;
    Checksum() tcp_checksum;
    Checksum() udp_checksum;

    

    apply {
        if(hdr.outer_ipv4.isValid()) {
            hdr.outer_ipv4.checksum = ipv4_checksum.update(
                {hdr.outer_ipv4.version,
                 hdr.outer_ipv4.ihl,
                 hdr.outer_ipv4.dscp,
                 hdr.outer_ipv4.ecn,
                 hdr.outer_ipv4.total_len,
                 hdr.outer_ipv4.identification,
                 hdr.outer_ipv4.flags,
                 hdr.outer_ipv4.frag_offset,
                 hdr.outer_ipv4.ttl,
                 hdr.outer_ipv4.proto,
                 hdr.outer_ipv4.src_addr,
                 hdr.outer_ipv4.dst_addr});
        }
        if(hdr.ipv4.isValid()){
            hdr.ipv4.checksum = ipv4_checksum.update(
                {hdr.ipv4.version,
                 hdr.ipv4.ihl,
                 hdr.ipv4.dscp,
                 hdr.ipv4.ecn,
                 hdr.ipv4.total_len,
                 hdr.ipv4.identification,
                 hdr.ipv4.flags,
                 hdr.ipv4.frag_offset,
                 hdr.ipv4.ttl,
                 hdr.ipv4.proto,
                 hdr.ipv4.src_addr,
                 hdr.ipv4.dst_addr});
        }
        // if(hdr.tcp.isValid()) {
        //     hdr.tcp.checksum = tcp_checksum.update(data = {
        //         hdr.ipv4.src_addr,
        //         hdr.tcp.sport,
        //         local_meta.checksum_tcp_tmp
        //     });
        // }
        // if(hdr.udp.isValid()) {
        //     hdr.udp.checksum = udp_checksum.update(data = {
        //         hdr.ipv4.src_addr,
        //         hdr.udp.sport,
        //         local_meta.checksum_gtp_udp_tmp
        //     });
        // }

        packet.emit(hdr.packet_in);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.outer_ipv4);
        //packet.emit(hdr.outer_ipv4_option);
        packet.emit(hdr.outer_udp);
        packet.emit(hdr.gtpu);
        packet.emit(hdr.gtpu_options);
        packet.emit(hdr.gtpu_ext_psc);
        packet.emit(hdr.ipv4);
        //packet.emit(hdr.outer_ipv4_option);
        packet.emit(hdr.udp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.icmp);
    }
}


// --------------------
// Tofino Empty Egress
// ---------------------
parser EmptyEgressParser(
        packet_in pkt,
        out empty_header_t hdr,
        out empty_metadata_t eg_md,
        out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

control EmptyEgressDeparser(
        packet_out pkt,
        inout empty_header_t hdr,
        in empty_metadata_t eg_md,
        in egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md) {
    apply {
        pkt.emit(hdr);
    }
}

#endif
