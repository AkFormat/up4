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
#include <core.p4>
#if __TARGET_TOFINO__ == 2
#include <t2na.p4>
#else
#include <tna.p4>
#endif

#include "include/define.p4"
#include "include/header.p4"
#include "include/parser.p4"
//#include "include/checksum.p4"

//------------------------------------------------------------------------------
// ACL BLOCK
//------------------------------------------------------------------------------
control Acl(
    inout parsed_headers_t hdr,
    inout local_metadata_t local_meta,
    //inout ingress_intrinsic_metadata_t std_meta,
    in ingress_intrinsic_metadata_t ig_intr_md,
    in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    // DirectCounter<bit<64>>(CounterType_t.PACKETS_AND_BYTES) aclCounter;// TODO: 什么是 counters; // TODO: 什么是 counters
    action set_port(port_num_t port) {
        //std_meta.egress_spec = port; // 制定该数据包的出口
        ig_intr_tm_md.ucast_egress_port = port;
        
    }

    action punt() {
        set_port(CPU_PORT);
    }

    action clone_to_cpu() {
        // Cloning is achieved by using a v1model-specific primitive. Here we
        // set the type of clone operation (ingress-to-egress pipeline), the
        // clone session ID (the CPU one), and the metadata fields we want to
        // preserve for the cloned packet replica.
        //TODO: clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, { std_meta.ingress_port });
    }

      action drop() {
        ig_intr_dprsr_md.drop_ctl = 1;
    }


    table acls {
        key = {
            ig_intr_md.ingress_port       : ternary @name("inport");
            local_meta.src_iface        : ternary @name("src_iface");
            hdr.ethernet.src_addr       : ternary @name("eth_src");
            hdr.ethernet.dst_addr       : ternary @name("eth_dst");
            hdr.ethernet.ether_type     : ternary @name("eth_type");
            hdr.ipv4.src_addr           : ternary @name("ipv4_src");
            hdr.ipv4.dst_addr           : ternary @name("ipv4_dst");
            hdr.ipv4.proto              : ternary @name("ipv4_proto");
            local_meta.l4_sport         : ternary @name("l4_sport");
            local_meta.l4_dport         : ternary @name("l4_dport");
        }
        actions = {
            set_port;
            punt;
            clone_to_cpu;
            drop;
            NoAction;
        }
        const default_action = NoAction;
        //counters=aclCounter;
        
    }

    apply {
        acls.apply();
    }
}

//------------------------------------------------------------------------------
// ROUTING BLOCK 
//------------------------------------------------------------------------------
control Routing(inout parsed_headers_t    hdr,
                inout local_metadata_t    local_meta,
                //inout ingress_intrinsic_metadata_t std_meta,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md ) {


    //Hash<bit<16>>(HashAlgorithm_t.CRC16) sel_hash;
    //ActionProfile(2048) action_selector_ap;
    // ActionSelector(action_selector_ap, // action profile
    //                sel_hash, // hash extern
    //                SelectorMode_t.FAIR, // Selector algorithm
    //                200, // max group size
    //                100 // max number of groups
    //                ) action_selector;

    action drop() {
        ig_intr_dprsr_md.drop_ctl = 1;
    }

        
    // 选择出去的端口，并填充Mac地址
    action route(mac_addr_t src_mac,
                 mac_addr_t dst_mac,
                 port_num_t egress_port) {
        ig_intr_tm_md.ucast_egress_port = egress_port;
        hdr.ethernet.src_addr = src_mac;
        hdr.ethernet.dst_addr = dst_mac;
    }
    
    
    table routes_v4 {
        key = {
            local_meta.next_hop_ip   : lpm @name("dst_prefix"); 
            // hdr.ipv4.src_addr      : selector;
            // hdr.ipv4.proto         : selector;
            // local_meta.l4_sport    : selector;
            // local_meta.l4_dport    : selector;
        }
        actions = {
            route;
            drop;
            NoAction;
        }
        //@name("hashed_selector")
        //implementation = action_selector; // TODO: action_selector 是什么
        const default_action = NoAction;
        size = MAX_ROUTES;
    }


    apply {
        // Normalize IP address for routing table, and decrement TTL
        // TODO: find a better alternative to this hack
        if (hdr.outer_ipv4.isValid()) {
            local_meta.next_hop_ip = hdr.outer_ipv4.dst_addr;
            hdr.outer_ipv4.ttl = hdr.outer_ipv4.ttl - 1;
            //hdr.outer_ipv4_option.test_data=local_meta.next_hop_ip;
        } else if (hdr.ipv4.isValid()){
            local_meta.next_hop_ip = hdr.ipv4.dst_addr;
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        }
        // if (hdr.ipv4.isValid()) {
        //     local_meta.next_hop_ip = hdr.ipv4.dst_addr;
        //     hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        //     hdr.outer_ipv4_option.test_data=local_meta.next_hop_ip;
        // } else if (hdr.inner_ipv4.isValid()){
        //     local_meta.next_hop_ip = hdr.inner_ipv4.dst_addr;
        //     hdr.inner_ipv4.ttl = hdr.inner_ipv4.ttl - 1;
        // }

        if (hdr.ipv4.ttl == 0) {
            drop();
        }
        else {
            routes_v4.apply();
        }
    }
}


//------------------------------------------------------------------------------
// FAR EXECUTION CONTROL BLOCK, 应用 FAR 规则
//------------------------------------------------------------------------------
control ExecuteFar (inout parsed_headers_t    hdr,
                     inout local_metadata_t    local_meta,
                     // inout ingress_intrinsic_metadata_t std_meta,
                     in ingress_intrinsic_metadata_t ig_intr_md,
                     in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
                     inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
                     inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    action drop() {
        ig_intr_dprsr_md.drop_ctl = 1;
    }

    @hidden
    action _udp_encap(ipv4_addr_t src_addr, ipv4_addr_t dst_addr,
                      L4Port udp_sport, L4Port udp_dport,
                      bit<16> ipv4_total_len,
                      bit<16> udp_len) {
        hdr.outer_ipv4.setValid();
        hdr.outer_ipv4.version = IP_VERSION_4;
        hdr.outer_ipv4.ihl = IPV4_MIN_IHL;
        hdr.outer_ipv4.dscp = 0;
        hdr.outer_ipv4.ecn = 0;
        hdr.outer_ipv4.total_len = ipv4_total_len;
        hdr.outer_ipv4.identification = 0x1513; // TODO: change this to timestamp or some incremental num
        hdr.outer_ipv4.flags = 0;
        hdr.outer_ipv4.frag_offset = 0;
        hdr.outer_ipv4.ttl = DEFAULT_IPV4_TTL;
        hdr.outer_ipv4.proto = IpProtocol.UDP;
        hdr.outer_ipv4.src_addr = src_addr;
        hdr.outer_ipv4.dst_addr = dst_addr;
        hdr.outer_ipv4.checksum = 0; // Updated later

        hdr.outer_udp.setValid();
        hdr.outer_udp.sport = udp_sport;
        hdr.outer_udp.dport = udp_dport;
        hdr.outer_udp.len = udp_len;
        hdr.outer_udp.checksum = 0; // Never updated due to p4 limitations
    }

    @hidden
    action _gtpu_encap(teid_t teid) {
        hdr.gtpu.setValid();
        hdr.gtpu.version = GTP_V1;
        hdr.gtpu.pt = GTP_PROTOCOL_TYPE_GTP;
        hdr.gtpu.spare = 0;
        hdr.gtpu.ex_flag = 0;
        hdr.gtpu.seq_flag = 0;
        hdr.gtpu.npdu_flag = 0;
        hdr.gtpu.msgtype = GTPUMessageType.GPDU;
        hdr.gtpu.msglen = hdr.ipv4.total_len;
        hdr.gtpu.teid = teid;
    }

    @hidden
    action gtpu_only(ipv4_addr_t src_addr, ipv4_addr_t dst_addr,
                      L4Port     udp_sport, teid_t teid) {
        _udp_encap(src_addr, dst_addr, udp_sport, L4Port.GTP_GPDU,
                   hdr.ipv4.total_len + 36, //IPV4_HDR_SIZE + UDP_HDR_SIZE + GTP_HDR_MIN_SIZE = 20 + 8 + 8
                   hdr.ipv4.total_len + 16);//UDP_HDR_SIZE + GTP_HDR_MIN_SIZE
        _gtpu_encap(teid);
    }

    @hidden
    action gtpu_with_psc(ipv4_addr_t src_addr, ipv4_addr_t dst_addr,
                            L4Port     udp_sport, teid_t teid, bit<6> qfi) {
        //
        _udp_encap(src_addr, dst_addr, udp_sport, L4Port.GTP_GPDU,
                   hdr.ipv4.total_len + 44 , //IPV4_HDR_SIZE + UDP_HDR_SIZE + GTP_HDR_MIN_SIZE + GTPU_OPTIONS_HDR_BYTES + GTPU_EXT_PSC_HDR_BYTES = 8
                   hdr.ipv4.total_len + 24); // UDP_HDR_SIZE + GTP_HDR_MIN_SIZE + GTPU_OPTIONS_HDR_BYTES + GTPU_EXT_PSC_HDR_BYTES
        _gtpu_encap(teid);
        hdr.gtpu.msglen = hdr.ipv4.total_len + 8; // Override msglen set by _gtpu_encap,GTPU_OPTIONS_HDR_BYTES + GTPU_EXT_PSC_HDR_BYTES
        hdr.gtpu.ex_flag = 1; // Override value set by _gtpu_encap
        hdr.gtpu_options.setValid();
        hdr.gtpu_options.seq_num   = 0;
        hdr.gtpu_options.n_pdu_num = 0;
        hdr.gtpu_options.next_ext  = GTPU_NEXT_EXT_PSC;
        hdr.gtpu_ext_psc.setValid();
        hdr.gtpu_ext_psc.len      = GTPU_EXT_PSC_LEN;
        hdr.gtpu_ext_psc.type     = GTPU_EXT_PSC_TYPE_DL;
        hdr.gtpu_ext_psc.spare0   = 0;
        hdr.gtpu_ext_psc.ppp      = 0;
        hdr.gtpu_ext_psc.rqi      = 0;
        hdr.gtpu_ext_psc.qfi      = qfi;
        hdr.gtpu_ext_psc.next_ext = GTPU_NEXT_EXT_NONE;
    }

    action do_gtpu_tunnel() {
        gtpu_only(local_meta.far.tunnel_out_src_ipv4_addr,
                   local_meta.far.tunnel_out_dst_ipv4_addr,
                   local_meta.far.tunnel_out_udp_sport,
                   local_meta.far.tunnel_out_teid);
    }

    action do_gtpu_tunnel_with_psc() {
        gtpu_with_psc(local_meta.far.tunnel_out_src_ipv4_addr,
                       local_meta.far.tunnel_out_dst_ipv4_addr,
                       local_meta.far.tunnel_out_udp_sport,
                       local_meta.far.tunnel_out_teid,
                       local_meta.pdr.tunnel_out_qfi);
    }

    action do_forward() {
        // Currently a no-op due to forwarding being logically separated
    }

    action do_buffer() {
        // Send digest. This is equivalent to a PFCP Downlink Data Notification (DDN), used to
        // notify control plane to initiate the paging procedure to locate and wake-up the UE.
        // FIXME: what is the first argument 1 used for?
        // TODO: digest<ddn_digest_t>(1, { local_meta.fseid });
        // The actual buffering cannot be expressed in the logical pipeline.
        drop();
        exit;
    }

    action do_drop() {
        ig_intr_dprsr_md.drop_ctl = 1;
        exit;
    }

    action do_notify_cp() {
        // TODO: clone3(CloneType.I2E, CPU_CLONE_SESSION_ID, { ig_intr_md.ingress_port });
    }

    apply {
        if (local_meta.far.notify_cp) {
            do_notify_cp();
        }
        if (local_meta.bar.needs_buffering) {
            do_buffer();
        }
        if (local_meta.far.needs_tunneling) {
            if (local_meta.far.tunnel_out_type == TunnelType.GTPU) {
              if(local_meta.needs_ext_psc) {
                do_gtpu_tunnel_with_psc();
              } else {
                do_gtpu_tunnel();
              }
            }
        }
        if (local_meta.far.needs_dropping) {
            do_drop();
        } else {
            do_forward();
        }
    }
}


//------------------------------------------------------------------------------
// INGRESS PIPELINE
//------------------------------------------------------------------------------
control PreQosPipe (inout parsed_headers_t    hdr,
                    inout local_metadata_t    local_meta,
                    //inout ingress_intrinsic_metadata_t std_meta,
                    in ingress_intrinsic_metadata_t ig_intr_md,
                    in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
                    inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
                    inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md) {

    action my_station_action(bit<8> tmp){
        
    }

    //DirectCounter<bit<32>>(CounterType_t.PACKETS_AND_BYTES) pre_qos_pdr_counter;
    table my_station {
        key = {
            hdr.ethernet.dst_addr : exact @name("dst_mac"); // 外层Ethernet的mac
        }
        actions = {
            my_station_action;
            NoAction;
        }

        const default_action=NoAction;
        
    }

    // TODO: eventually add the SliceId to let PFCP agent set the slice ID.
    action set_source_iface(InterfaceType src_iface, Direction direction) { // 在local_meta设置接口类型和方向
        // Interface type can be access, core, n6_lan, etc (see InterfaceType enum)
        // If interface is from the control plane, direction can be either up or down
        local_meta.src_iface = src_iface;
        local_meta.direction = direction;
        //hdr.outer_ipv4_option.test_data1 = local_meta.src_iface;
    }
    table source_iface_lookup {
        key = {
            hdr.ipv4.dst_addr : lpm @name("ipv4_dst_prefix"); // 最长匹配，外层ipv4目的地址
            // Eventually should also check VLAN ID here
        }
        actions = {
            set_source_iface;
        }
        const default_action = set_source_iface(InterfaceType.UNKNOWN, Direction.UNKNOWN);
    }


    @hidden
    action gtpu_decap() {
        // 把外层的头部全部设为非法
        hdr.gtpu.setInvalid();
        hdr.gtpu_options.setInvalid();
        hdr.gtpu_ext_psc.setInvalid();
        hdr.outer_ipv4.setInvalid();
        hdr.outer_udp.setInvalid();
    }

    // @hidden
    // action _set_pdr(pdr_id_t          id,
    //                 fseid_t           fseid,
    //                 counter_index_t   ctr_id,
    //                 far_id_t          far_id,
    //                 bit<1>            needs_gtpu_decap
    //                 )
    // {
    //     local_meta.pdr.id           = id;
    //     local_meta.fseid            = fseid;
    //     local_meta.pdr.ctr_idx      = ctr_id;
    //     local_meta.far.id           = far_id;
    //     local_meta.needs_gtpu_decap = (bool)needs_gtpu_decap;
    // }

    action set_pdr_attributes(fseid_t           fseid,
                              far_id_t          far_id,
                              pdr_id_t          pdr_id,
                              bit<1>            needs_gtpu_decap
                             )
    {
        
        local_meta.fseid            = fseid;
        local_meta.pdr.id           = far_id;
        //local_meta.pdr.ctr_idx      = ctr_id;
        local_meta.far.id           = far_id;
        local_meta.needs_gtpu_decap = (bool)needs_gtpu_decap;
        local_meta.needs_ext_psc = false;
    }

    action set_pdr_attributes_qos(
                                       fseid_t           fseid,
                                       pdr_id_t          pdr_id,
                                       far_id_t          far_id,
                                       bit<1>            needs_gtpu_decap,
                                       // Used to push QFI, valid for 5G traffic only
                                       bit<1>            needs_qfi_push,
                                       bit<6>            qfi
                                       )
    {
        local_meta.pdr.id            =  pdr_id;
        local_meta.fseid            = fseid;
        //local_meta.pdr.ctr_idx      = ctr_id;
        local_meta.far.id           = far_id;
        local_meta.needs_ext_psc        = (bool)needs_qfi_push;
        local_meta.pdr.tunnel_out_qfi   = qfi;

    }

    // Contains PDRs for both the Uplink and Downlink Direction
    // One PDR's match conditions are made of PDI and a set of 5-tuple filters (SDFs).
    // The PDR matches if the PDI and any of the SDFs match, but 'filter1 or filter2' cannot be
    // expressed as one table entry in P4, so this table will contain the cross product of every
    // PDR's PDI and its SDFs.
    // Matching on QFI is allowed only for uplink PDRs, while setting a QFI attribute is allowed
    // only for downlink ones.
    table pdrs {
        key = {
            // PDI
            local_meta.src_iface        : exact     @name("src_iface"); // To differentiate uplink and downlink
            hdr.outer_ipv4.dst_addr     : ternary   @name("tunnel_ipv4_dst"); // combines with TEID to make F-TEID
            local_meta.teid             : ternary   @name("teid");
            // one SDF filter from a PDR's filter set
            local_meta.ue_addr          : ternary   @name("ue_addr");
            local_meta.inet_addr        : ternary   @name("inet_addr");
            local_meta.ue_l4_port       : range     @name("ue_l4_port");
            local_meta.inet_l4_port     : range     @name("inet_l4_port");
            hdr.ipv4.proto              : ternary   @name("ip_proto");
            // Match on QFI, valid for 5G traffic only
            hdr.gtpu_ext_psc.isValid()  : ternary  @name("has_qfi");
            hdr.gtpu_ext_psc.qfi        : ternary  @name("qfi");
        }
        actions = {
            set_pdr_attributes;
            set_pdr_attributes_qos;
            NoAction;
        } 
        const default_action = NoAction;
        
    }

    action load_normal_far_attributes(bit<1> needs_dropping,
                                      bit<1> notify_cp) {
        local_meta.far.needs_tunneling = false;
        local_meta.far.needs_dropping    = (bool)needs_dropping;
        local_meta.far.notify_cp = (bool)notify_cp;
    }
    action load_tunnel_far_attributes(bit<1> needs_dropping,
                                    bit<1> notify_cp,
                                    bit<1> needs_buffering,
                                    TunnelType     tunnel_type,
                                    ipv4_addr_t    src_addr,
                                    ipv4_addr_t    dst_addr,
                                    teid_t         teid,
                                    L4Port         sport) {
        local_meta.far.needs_tunneling = true;
        local_meta.far.needs_dropping = (bool)needs_dropping;
        local_meta.far.notify_cp = (bool)notify_cp;
        local_meta.far.tunnel_out_type          = tunnel_type;
        local_meta.far.tunnel_out_src_ipv4_addr = src_addr;
        local_meta.far.tunnel_out_dst_ipv4_addr = dst_addr;
        local_meta.far.tunnel_out_teid          = teid;
        local_meta.far.tunnel_out_udp_sport     = sport;
        local_meta.bar.needs_buffering = (bool)needs_buffering;
    }

    table load_far_attributes {
        key = {
            local_meta.far.id : exact      @name("far_id");
            local_meta.fseid  : exact      @name("session_id");
        }
        actions = {
            load_normal_far_attributes;
            load_tunnel_far_attributes;
        }
    }


    //----------------------------------------
    // INGRESS APPLY BLOCK
    //----------------------------------------
    apply {

        
        if (hdr.packet_out.isValid()) {
            // All packet-outs should be routed like regular packets, without UPF processing.
            // This is used for sending GTP End Marker to base stations, and for other packets
            // originating from the control plane.
            hdr.packet_out.setInvalid();
        } else {
            // Only process if the packet is destined for our MAC addr. We don't handle switching
            // 仅当数据包发往我们的 MAC 地址时才处理
            if (!my_station.apply().hit) {
                return;
            }

            // Interfaces we care about:
            // N3 (from base station) - GTPU - match on outer IP dst
            // N6 (from internet) - no GTPU - match on IP header dst
            // N9 (from another UPF) - GTPU - match on outer IP dst
            // N4-u (from SMF) - GTPU - match on outer IP dst

            // Interface lookup happens before normalization of headers,
            // because the lookup uses the outermost IP header in all cases
            source_iface_lookup.apply(); // 检查数据包从那个网口而来
           


            // Normalize the headers so that the UE's IPv4 header is always hdr.ipv4
            // regardless of if there is encapsulation or not.
            // 矫正
            if (hdr.inner_ipv4.isValid()) { // 如果内部的ipv4是合法的
                hdr.outer_ipv4 = hdr.ipv4; 
                hdr.ipv4 = hdr.inner_ipv4;
                //hdr.outer_ipv4.setValid();
                hdr.inner_ipv4.setInvalid(); // 因为inner_ipv4 已经被赋值为 ipv4，所以报废inner_ipv4
                hdr.outer_udp = hdr.udp; // 默认外4层使用UDP协议？
                //hdr.outer_udp.setValid();
                if (hdr.inner_udp.isValid()) { 
                    hdr.udp = hdr.inner_udp;
                    hdr.inner_udp.setInvalid();
                }
                else {
                    hdr.udp.setInvalid();
                    if (hdr.inner_tcp.isValid()) {
                        hdr.tcp = hdr.inner_tcp;
                        hdr.inner_tcp.setInvalid();
                    }
                    else if (hdr.inner_icmp.isValid()) {
                        hdr.icmp = hdr.inner_icmp;
                        hdr.inner_icmp.setInvalid();
                    }
                }
            }


            // Normalize so the UE address/port appear as the same field regardless of direction
            if (local_meta.direction == Direction.UPLINK) { // 如果流量是由gNB传到UPF
                local_meta.ue_addr = hdr.ipv4.src_addr; // 内层ipv4原地址
                local_meta.inet_addr = hdr.ipv4.dst_addr; // 内层ipv4目的地址
                local_meta.ue_l4_port = local_meta.l4_sport;
                local_meta.inet_l4_port = local_meta.l4_dport;
            }
            else if (local_meta.direction == Direction.DOWNLINK) { // 如果流量是由UPF到UE
                local_meta.ue_addr = hdr.ipv4.dst_addr;
                local_meta.inet_addr = hdr.ipv4.src_addr;
                local_meta.ue_l4_port = local_meta.l4_dport;
                local_meta.inet_l4_port = local_meta.l4_sport;
            }


        // //     // Find a matching PDR and load the relevant attributes.
            pdrs.apply(); // 应用pdr规则
            //hdr.outer_ipv4_option.test_data2 = local_meta.pdr.id;
        // //     // Count packets at a counter index unique to whichever PDR matched.
            
        // //     //pre_qos_pdr_counter.count(local_meta.pdr.ctr_idx); // TODO: 什么是count？
            
        // //     // Perform whatever header removal the matching PDR required.
            if (local_meta.needs_gtpu_decap) { // 是否需要去掉 gtp头部
                gtpu_decap();
            }

        //     // Look up FAR info using the FAR-ID loaded by the PDR table.
            load_far_attributes.apply();
        //     // Execute the loaded FAR
            ExecuteFar.apply(hdr, local_meta, ig_intr_md, ig_intr_prsr_md, ig_intr_dprsr_md, ig_intr_tm_md); // 执行FAR
            //hdr.outer_ipv4_option.test_data3 = hdr.outer_udp.sport;
        }

        // FAR only set the destination IP. FAR只设置ip地址
        // Now we need to choose a destination MAC egress port. 还需要选择egress出口和mac地址
        Routing.apply(hdr, local_meta, ig_intr_md, ig_intr_prsr_md, ig_intr_dprsr_md, ig_intr_tm_md); // 设置mac地址和egress端口

        // Administrative override ACL is standard in network devices
        // Acl.apply(hdr, local_meta, ig_intr_md, ig_intr_prsr_md, ig_intr_dprsr_md, ig_intr_tm_md);
    }
}

control PostQosPipe (inout parsed_headers_t hdr,
                     inout local_metadata_t local_meta,
                     //inout egress_intrinsic_metadata_t std_meta,
                     in ingress_intrinsic_metadata_t ig_intr_md,
                     in ingress_intrinsic_metadata_from_parser_t ig_intr_prsr_md,
                     inout ingress_intrinsic_metadata_for_deparser_t ig_intr_dprsr_md,
                     inout ingress_intrinsic_metadata_for_tm_t ig_intr_tm_md
                     ) {


    //counter(MAX_PDRS, CounterType.packets_and_bytes) post_qos_pdr_counter;

    apply {
        // Count packets that made it through QoS and were not dropped,
        // using the counter index assigned by the PDR that matched in ingress.
       // post_qos_pdr_counter.count(local_meta.pdr.ctr_idx);

        // If this is a packet-in to the controller, e.g., if in ingress we
        // matched on the ACL table with action send/clone_to_cpu...
        if (ig_intr_tm_md.ucast_egress_port == CPU_PORT) {
            // Add packet_in header and set relevant fields, such as the
            // switch ingress port where the packet was received.
            hdr.packet_in.setValid();
            hdr.packet_in.ingress_port = ig_intr_md.ingress_port;
            // Exit the pipeline here.
            exit;
        }
    }
}


//------------------------------------------------------------------------------
// EMPTY EGRESS PIPELINE
//------------------------------------------------------------------------------

control EmptyEgress(
        inout empty_header_t hdr,
        inout empty_metadata_t eg_md,
        in egress_intrinsic_metadata_t eg_intr_md,
        in egress_intrinsic_metadata_from_parser_t eg_intr_md_from_prsr,
        inout egress_intrinsic_metadata_for_deparser_t ig_intr_dprs_md,
        inout egress_intrinsic_metadata_for_output_port_t eg_intr_oport_md) {
    apply {}
}



Pipeline(
    ParserImpl(), // 解析报文
    //VerifyChecksumImpl(),
    PreQosPipe(),
    //PostQosPipe(),
    //ComputeChecksumImpl(),
    DeparserImpl(),
    EmptyEgressParser(),
    EmptyEgress(),
    EmptyEgressDeparser()
) pipe;

Switch(pipe) main;
