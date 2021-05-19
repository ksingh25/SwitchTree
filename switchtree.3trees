/* -*- P4_16 -*- */
/********************************************************************************
*
* Copyright (c) 2019 Kamal Singh
* All rights reserved.
*
*********************************************************************************/

#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;

#define MAX_REGISTER_ENTRIES 8192
#define BLOOM_FILTER_BIT_WIDTH 32
#define PACKET_THRESHOLD 1000
#define FLOW_TIMEOUT 15000000 //15 seconds
#define CLASS_NOT_SET 10000// A big number

#define STATE_INT 1
#define STATE_FIN 2
#define STATE_REQ 3
#define STATE_CON 4
#define STATE_ACC 5
#define STATE_CLO 6
#define STATE_EST 7

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}


struct metadata {
    bit<64> feature1;
    bit<64> feature2;
    bit<64> feature3;
    bit<64> feature4;
    bit<64> feature5;
    bit<64> feature6;
    bit<64> feature7;
    bit<64> feature8;
    bit<64> feature9;
    bit<64> feature10;
    bit<64> feature11;
    bit<64> feature12;
    bit<64> feature13;

    bit<16> prevFeature;
    bit<16> isTrue;

    bit<16> class;
    bit<16> class2;
    bit<16> class3;

    bit<16> node_id;

    bit<1> direction;
    bit<32> register_index;
    bit<32> register_index_2;
    bit<32> register_index_inverse;
    bit<32> register_index_inverse_2;

    //bloom filter indexes
    bit<1> register_cell_one;
    bit<1> register_cell_two;
    bit<32> register_position_one;
    bit<32> register_position_two;
 
    bit<8> sttl;
    bit<8> dttl;
    bit<32> srcip;
    bit<16> srcport;
    bit<16> dstport;
    bit<16> hdr_srcport;
    bit<16> hdr_dstport;
     
    bit<32> dpkts;
    bit<32> spkts;
    bit<32> sbytes;
    bit<32> dbytes;
    bit<16> ct_srv_dst;
    bit<48> tcprtt;
    bit<48> syn_time;
    bit<48> time_last_pkt;
    bit<48> time_first_pkt;
  
    bit<48> dur;
    bit<1> is_first;
    bit<1> is_empty;
    bit<1> is_hash_collision;
    bit<1> first_ack;

    bit<8> state;
    bit<8> ct_state_ttl;
    bit<1> malware;
    bit<1> marked_malware;
	
}

struct headers {
    ethernet_t  ethernet;
    ipv4_t      ipv4;
    tcp_t       tcp;
    udp_t	udp;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

   //TODO parse different types of packets ARP, ICMP etc.
   state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            6: parse_tcp;
	    17: parse_udp;
            default: accept;
    }
    }
    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {


    register<bit<1>>(MAX_REGISTER_ENTRIES) bloom_filter;

    //bloomfilter: a query returns either "possibly in set" or "definitely not in set."
    //Many more flows are normal than abnormal flows. Thus better performance 
    //will be by storing abnormal flows 
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_blacklisted;

    //Here performance will not be good, but once the filter says definitely not allowed, we are sure.
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_allowed;
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_first_ack;
    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_is_empty;

    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_ttl;
    register<bit<8>>(MAX_REGISTER_ENTRIES) reg_dttl;
	
     //Dload will be obtained by reversing the src-dst tuple
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_spkts;//src dst pkt count

    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_dpkts;//src dst pkt count

    //Reg not needed for state_INT
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_sbytes;//src dst byte count
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_dbytes;//src dst byte count

    //sum of TCP connection setup time : sum of synack and ackdat time
   
    register<bit<32>>(8) reg_ct_srv_dst;//Number of connections that contain the same service and srcip in last 100 connections
    //Note that only 8 possibilities: http, ftp, smtp, ssh, dns, ftp-data ,irc  and (-) if not much used service
    //Register not needed for dsport
    //dttl, Dpkts, dmeansz, Dload will be obtained by reversing the src-dst tuple
   
    //Registers for identifying the flow more apart from hash we may use source port
    register<bit<32>>(MAX_REGISTER_ENTRIES) reg_srcip;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_srcport;
    register<bit<16>>(MAX_REGISTER_ENTRIES) reg_dstport;

    register<bit<1>>(MAX_REGISTER_ENTRIES) reg_marked_malware;


	
    register<bit<48>>(MAX_REGISTER_ENTRIES) reg_time_last_pkt;
    register<bit<48>>(MAX_REGISTER_ENTRIES) reg_time_first_pkt;
    register<bit<48>>(MAX_REGISTER_ENTRIES) reg_syn_time;
    register<bit<48>>(MAX_REGISTER_ENTRIES) reg_tcprtt;

    //Store some statistics for the experiment
    counter(1, CounterType.packets) counter_hash_collisions;
    counter(1, CounterType.packets) counter_pkts;
    counter(1, CounterType.packets) counter_malware;
    counter(1, CounterType.packets) counter_true_detection;
    counter(1, CounterType.packets) counter_false_detection;
    counter(1, CounterType.packets) counter_flows;
    counter(1, CounterType.packets) counter_malware_flows;
    counter(1, CounterType.packets) counter_true_detection_flows;
    counter(1, CounterType.packets) counter_false_detection_flows;
    counter(1, CounterType.packets) counter_timeout;
  
    action init_register() {
	//intialise the registers to 0
	reg_time_last_pkt.write(meta.register_index, 0);
	reg_srcip.write(meta.register_index, 0);
 	reg_srcport.write(meta.register_index, 0);
 	reg_dstport.write(meta.register_index, 0);
 	reg_ttl.write(meta.register_index, 0);
	reg_dttl.write(meta.register_index, 0);
 	reg_spkts.write(meta.register_index, 0);
	reg_sbytes.write(meta.register_index, 0);
	reg_dpkts.write(meta.register_index, 0);
 	reg_dbytes.write(meta.register_index, 0);
 	reg_syn_time.write(meta.register_index, 0);
 	reg_tcprtt.write(meta.register_index, 0);
 	reg_marked_malware.write(meta.register_index, 0);
    }
	
     action get_register_index_tcp() {
    //Get register position
		hash(meta.register_index, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
	                        hdr.ipv4.dstAddr,
				hdr.tcp.srcPort,
	                        hdr.tcp.dstPort,
				hdr.ipv4.protocol},
				(bit<32>)MAX_REGISTER_ENTRIES);

		hash(meta.register_index_2, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr,
                                hdr.ipv4.dstAddr,
                                hdr.tcp.srcPort,
                                hdr.tcp.dstPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);
	}

    action get_register_index_udp() {
 	        hash(meta.register_index, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.srcAddr,
                                hdr.ipv4.dstAddr,
                                hdr.udp.srcPort,
                                hdr.udp.dstPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);

                hash(meta.register_index_2, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.srcAddr,
                                hdr.ipv4.dstAddr,
                                hdr.udp.srcPort,
                                hdr.udp.dstPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);
	}

    action get_register_index_inverse_tcp() {
    //Get register position for the same flow in another directon
    // just inverse the src and dst
                hash(meta.register_index_inverse, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.dstAddr,
                                hdr.ipv4.srcAddr,
                                hdr.tcp.dstPort,
                                hdr.tcp.srcPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);

                hash(meta.register_index_inverse_2, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.dstAddr,
                                hdr.ipv4.srcAddr,
                                hdr.tcp.dstPort,
                                hdr.tcp.srcPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);
     }

    action get_register_index_inverse_udp() {
                hash(meta.register_index_inverse, HashAlgorithm.crc16, (bit<16>)0, {hdr.ipv4.dstAddr,
                                hdr.ipv4.srcAddr,
                                hdr.udp.dstPort,
                                hdr.udp.srcPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);

                hash(meta.register_index_inverse_2, HashAlgorithm.crc32, (bit<16>)0, {hdr.ipv4.dstAddr,
                                hdr.ipv4.srcAddr,
                                hdr.udp.dstPort,
                                hdr.ipv4.protocol},
                                (bit<32>)MAX_REGISTER_ENTRIES);
    }
     
    action set_allowed(){
        //set bloom filter fields
        bloom_filter.write(meta.register_position_one, 1);
        bloom_filter.write(meta.register_position_two, 1);
    }

    action check_if_allowed(){
        //Read bloom filter cells to check if there are 1's
        bloom_filter.read(meta.register_cell_one, meta.register_position_one);
        bloom_filter.read(meta.register_cell_two, meta.register_position_two);
    }

    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    //we plan to use the following features for the moment
    //sttl ct_state_ttl dttl Sload Dpkts dmeansz state_INT sbytes sload smeansz tcprtt dsport dur ct_srv_dst

    //1.* sttl there by default
    //2. ct_state_ttl **to be called after sttl and dttl calc

    action calc_state() {
	//When Sload or Dload is 0 the state can be INT
	//Thus need to calculate sload, dload before
	// XX TODO Argus log shows only last state! 
	//XX TODO The following logic is only approx. correct!
	if ((meta.is_first == 1)||(meta.dttl == 0)) {
		if (hdr.ipv4.protocol == 6) //TCP
			meta.state = STATE_REQ;
		else meta.state = STATE_INT;
	}
	else {
                if (hdr.ipv4.protocol == 6) //TCP
                        meta.state = STATE_EST;
                else meta.state = STATE_CON;
        }
	//TODO for STATE_FIN, which may not be useful as it would be last packet of transaction
	if (hdr.ipv4.protocol == 6 && hdr.tcp.fin == (bit<1>)1) {
		meta.state = STATE_FIN;
	}
    }

    action calc_ct_state_ttl(){

            meta.ct_state_ttl = 0;
            if ((meta.sttl == 62 || meta.sttl == 63 || meta.sttl == 254 || meta.sttl == 255) 
		&& (meta.dttl == 252 || meta.dttl == 253) && meta.state == STATE_FIN) {
                meta.ct_state_ttl = 1;
	    }
            else if ((meta.sttl == 0 || meta.sttl == 62 || meta.sttl == 254) 
		&& (meta.dttl == 0) && meta.state == STATE_INT) {
                meta.ct_state_ttl = 2;
	    }
            else if((meta.sttl == 62 || meta.sttl == 254) 
		&& (meta.dttl == 60 || meta.dttl == 252 || meta.dttl == 253) 
		&& meta.state == STATE_CON){
                meta.ct_state_ttl = 3;
            }  
            else if((meta.sttl == 254) && (meta.dttl == 252) && meta.state == STATE_ACC){
                meta.ct_state_ttl = 4;
            }
            else if((meta.sttl == 254) && (meta.dttl == 252) && meta.state == STATE_CLO){
                meta.ct_state_ttl = 5;
            }
            else if((meta.sttl == 254) && (meta.dttl == 0) && meta.state == STATE_REQ){
                meta.ct_state_ttl = 7;
            }
            else {
		meta.ct_state_ttl = 0;
	    }
    }

    action read_ct_srv_dst() {
	//TODO XX The following is just for test
	//No. of connections that contain the same service (14) (ftp, http, ..) and destination address (3) (ipaddress) in 100 connections according to the last time (26).

	meta.ct_srv_dst = 10;
    }
   

    action init_features() {
	//they will be updated when needed
	//or easy but a bit slow: to read them now
	//feature order can be changed flexibly using registers configurable from control plane, etc.
 
	// In the traces bitrate = int(smeanz)*(totalpkts - 1)*8/dur
	//We will compare sbytes*(totalpkts - 1)*8 > th*dur*spkts;
 
	meta.feature1 = (bit<64>)meta.sttl;//sttl
	meta.feature2 = (bit<64>)meta.ct_state_ttl;//ct_state_ttl
	meta.feature3 = (bit<64>)meta.dttl;//dttl
	meta.feature4 = (bit<64>)(meta.sbytes*(meta.spkts - 1)*8) ;//needed for Sload
	meta.feature5 = (bit<64>)meta.dpkts;//dpkts
	meta.feature6 = (bit<64>)meta.dbytes;//Needed for dmeansz
	meta.feature7 = (bit<64>)meta.sbytes;//sbytes
	meta.feature8 = (bit<64>)(meta.dbytes*(meta.dpkts - 1)*8);//Needed for dload
	meta.feature9 = (bit<64>)meta.sbytes;//needed for smeansz
	meta.feature10 = (bit<64>)meta.tcprtt;//tcprtt
	meta.feature11 = (bit<64>)meta.dstport;//dstport
	meta.feature12 = (bit<64>)meta.dur;//dur

	meta.class = CLASS_NOT_SET;
	meta.class2 = CLASS_NOT_SET;
	meta.class3 = CLASS_NOT_SET;
    }

    action CheckFeature(bit<16> node_id, bit<16> f_inout, bit<64> threshold) {
	//XX For dur and tcprtt are in microseconds! Thus multiplied by 1000000 if in seconds!
	//XX For rate comparisons 'th' is multiplied by time delta as division is not allowed

	bit<64> feature = 0;
        bit<64> th = threshold;
	bit<16> f = f_inout + 1;

	if (f == 1) {
		
	    feature = meta.feature1;
	}
	else if (f == 2) {
	    feature = meta.feature2;
	}
	else if (f == 3) {
	    feature = meta.feature3;
	}
	else if (f == 4) {
	    feature = meta.feature4*1000000;
	    th = th*(bit<64>)meta.dur*(bit<64>)meta.sbytes; 
	}
	else if (f == 5) {
	    feature = meta.feature5;
	}
	else if (f == 6) {
	    feature = meta.feature6;
	    th = th*(bit<64>)meta.dpkts;
	}
	else if (f == 7) {
	    feature = meta.feature7;
	}
	else if (f == 8) {
	    feature = meta.feature8*1000000;
	    th = th*(bit<64>)meta.dur*(bit<64>)meta.sbytes;
	}
	else if (f == 9) {
	    feature = meta.feature9;
	    th = th*(bit<64>)meta.spkts;
	}
	else if (f == 10) {
	    feature = meta.feature10;
	}
	else if (f == 11) {
	    feature = meta.feature11;
	}
	else if (f == 12) {
	    feature = meta.feature12;
	}
	
	if (feature <= th) meta.isTrue = 1;
	else meta.isTrue = 0;

	meta.prevFeature = f - 1;

	meta.node_id = node_id;
    }

    action SetClass(bit<16> node_id, bit<16> class) {
	meta.class = class;
	meta.node_id = node_id; //just for debugging otherwise not needed
    }
    action SetClass2(bit<16> node_id, bit<16> class) {
	meta.class2 = class;
	meta.node_id = node_id; //just for debugging otherwise not needed
    }
    action SetClass3(bit<16> node_id, bit<16> class) {
	meta.class3 = class;
	meta.node_id = node_id; //just for debugging otherwise not needed
    }

    action SetDirection() {
	//need just for this setting as tcpreplay is sending all the packets to same interface
	meta.direction = 1;
    }

    action SetMalware() {
	//need just for this setting as tcpreplay is sending all the packets to same interface
	meta.malware = 1;
    }
     

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }



 	table direction{
	    key = {
		hdr.ipv4.dstAddr: lpm;    
	    }
	    actions = {
		NoAction;
		SetDirection;
	    }
	    size = 10;
	    default_action = NoAction();
	}
	
	table malware{ //For debugging
	    key = {
		hdr.ipv4.srcAddr: lpm;    
	    }
	    actions = {
		NoAction;
		SetMalware;
	    }
	    size = 10;
	    default_action = NoAction();
	}
	
	table malware_inverse { //For debugging
	    key = {
		hdr.ipv4.dstAddr: lpm;    
	    }
	    actions = {
		NoAction;
		SetMalware;
	    }
	    size = 10;
	    default_action = NoAction();
	}

	//TODO convert lavel1 --> level_1_1
	//TODO micro TABLE(N)

	table level1{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;	    
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}
	
	table level2{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level3{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}
	table level4{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level5{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level6{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level7{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level8{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level9{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level10{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level11{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass;
	    }
	    size = 1024;
	}

	table level_2_1 {
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;	    
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}
	
	table level_2_2{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_3{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}
	table level_2_4{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_5{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_6{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_7{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_8{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_9{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_10{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_2_11{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass2;
	    }
	    size = 1024;
	}

	table level_3_1{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;	    
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}
	
	table level_3_2{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_3{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}
	table level_3_4{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_5{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_6{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_7{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_8{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_9{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_10{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}

	table level_3_11{
	    key = {
		meta.node_id: exact;
		meta.prevFeature: exact;
		meta.isTrue: exact;
	    }
	    actions = {
		NoAction;
		CheckFeature;
		SetClass3;
	    }
	    size = 1024;
	}



    
    /* This will send the packet to a specifique port of the switch for output*/
    table ipv4_exact {
        key = {
            meta.class: exact;
	}
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

	table debug{
	    key = {
		meta.feature1: exact;
		meta.feature2: exact;
		meta.feature3: exact;
		meta.feature4: exact;
		meta.feature5: exact;
		meta.feature6: exact;
		meta.feature7: exact;
		meta.feature8: exact;
		meta.feature9: exact;
		meta.feature10: exact;
		meta.feature11: exact;
		meta.feature12: exact;
		meta.state: exact;
		meta.spkts: exact;
		meta.is_first: exact;
		hdr.ipv4.dstAddr: exact; 
		meta.hdr_srcport: exact;
		meta.hdr_dstport: exact;
		standard_metadata.ingress_global_timestamp: exact;
		meta.syn_time: exact;
		meta.register_index: exact;
		meta.register_index_inverse: exact;
		meta.direction: exact;
		meta.is_hash_collision: exact;
		meta.malware: exact;
		meta.marked_malware: exact;
		meta.class: exact;
		meta.sbytes: exact;
	    }
	    actions = {
		NoAction;
	    }
	    size = 1024;
	}


    //Invoke the tables using the apply method
    
    apply {

	    /*check the direction of packets going. 
	      For UNSW data, the emulation configuration is as follows
              Outside:
	      59.166.0.0 normal
              175.45.176.0 malware
              Inside: 
              149.171.126.0
	      Thus, mostly track 59.166.0.0/175.45.176.0 ---> 149.171.126.0 packets
	     */
	
	    //count all the packets 
	    direction.apply();
	    counter_pkts.count(0);
      
	    if ( hdr.ipv4.isValid()) {
		//Calculate all features
		//TODO optimize : feature needs to be calculated only if needed

	     if (hdr.ipv4.protocol == 6 || hdr.ipv4.protocol == 17) {//We treat only TCP or UDP packets	

	      if (meta.direction == 1) {

		if (hdr.ipv4.protocol == 6) {
			get_register_index_tcp();
			meta.hdr_srcport = hdr.tcp.srcPort;
			meta.hdr_dstport = hdr.tcp.dstPort;
		}
		else {
			get_register_index_udp(); 
			meta.hdr_srcport = hdr.udp.srcPort;
			meta.hdr_dstport = hdr.udp.dstPort;

		}

		//read_reg_to_check_collision srcip, srcport, dstport
		reg_srcip.read(meta.srcip, meta.register_index);
		reg_srcport.read(meta.srcport, meta.register_index);
		reg_dstport.read(meta.dstport, meta.register_index);
		reg_time_last_pkt.read(meta.time_last_pkt, (bit<32>)meta.register_index);
		
		if (meta.srcip == 0) {//It was an empty register
			meta.is_first = 1;
		}
		else if ((standard_metadata.ingress_global_timestamp - meta.time_last_pkt) > FLOW_TIMEOUT) {
			/*We havent heard from this flow it has been FLOW_TIMEOUT
			  We will initialse the register space
			  TODO check if init_register() is initialising all and only those needed. ;
			 */
			init_register();
			counter_timeout.count(0);
			meta.is_first = 1;
		}
		else if (meta.srcip != hdr.ipv4.srcAddr || meta.srcport != meta.hdr_srcport 
		|| meta.dstport != meta.hdr_dstport) {
			//Hash collision!
			//TODO handle hash collisions in a better way!
			meta.is_hash_collision = 1;
			counter_hash_collisions.count(0);
		}

		if (meta.is_hash_collision == 0) {
			
		if (meta.is_first == 1) {
			meta.time_first_pkt = standard_metadata.ingress_global_timestamp;
			reg_time_first_pkt.write((bit<32>)meta.register_index, meta.time_first_pkt);
			reg_srcip.write((bit<32>)meta.register_index, hdr.ipv4.srcAddr);
			reg_srcport.write((bit<32>)meta.register_index, meta.hdr_srcport);
			reg_dstport.write((bit<32>)meta.register_index, meta.hdr_dstport);
			counter_flows.count(0);
		}

		reg_spkts.read(meta.spkts, (bit<32>)meta.register_index);
		meta.spkts = meta.spkts + 1;
		reg_spkts.write((bit<32>)meta.register_index, meta.spkts);
	
		meta.sttl = hdr.ipv4.ttl;
		reg_ttl.write((bit<32>)meta.register_index, meta.sttl);

		reg_dttl.read(meta.dttl, (bit<32>)meta.register_index);


		//read_sbytes also used for sload
		reg_sbytes.read(meta.sbytes, (bit<32>)meta.register_index);
		meta.sbytes = meta.sbytes + standard_metadata.packet_length - 14;
		reg_sbytes.write((bit<32>)meta.register_index, meta.sbytes);
  

		// tcprtt
    		//SYN TIME
		if ((hdr.tcp.ack != (bit<1>)1)&&(hdr.tcp.syn == (bit<1>)1)) {//this is a SYN
			reg_syn_time.write((bit<32>)meta.register_index,
			standard_metadata.ingress_global_timestamp);
		}
		//ACK + SYN time
		else if ((hdr.tcp.ack == (bit<1>)1)&&(hdr.tcp.syn != (bit<1>)1)) {//this is an ACK

			reg_first_ack.read(meta.first_ack, (bit<32>)meta.register_index);
			if (meta.first_ack == 0) {
				//sum of synack(SYN to SYN_ACK time) and ackdat(SYN_ACK to ACK time)
				reg_syn_time.read(meta.syn_time, (bit<32>)meta.register_index);
				if (meta.syn_time > 0) {//There was a syn before
					meta.tcprtt = standard_metadata.ingress_global_timestamp - 								meta.syn_time;
					reg_tcprtt.write((bit<32>)meta.register_index, meta.tcprtt);
					//no longer a first ack
    		                        reg_first_ack.write((bit<32>)meta.register_index, 1);
				}    	
			}
		}
	

		//read all reverse flow features
		reg_dbytes.read(meta.dbytes, (bit<32>)meta.register_index);
		reg_dpkts.read(meta.dpkts, (bit<32>)meta.register_index);
		
		}//hash collision check

	     }//end of direction = 1

	     else {//direction = 0

		//TODO some flows can be marked malware even after analysing return flow!

		if (hdr.ipv4.protocol == 6) {
			get_register_index_inverse_tcp();
			meta.hdr_srcport = hdr.tcp.dstPort;//its inverse
			meta.hdr_dstport = hdr.tcp.srcPort;
		}
		else {
			//TODO what if it is neither TCP nor UDP?
			get_register_index_inverse_udp();
			meta.hdr_srcport = hdr.udp.dstPort;
			meta.hdr_dstport = hdr.udp.srcPort;

		}

		meta.register_index = meta.register_index_inverse;

		//read_reg_to_check_collision srcip, srcport, dstport
		reg_srcip.read(meta.srcip, meta.register_index);
		reg_srcport.read(meta.srcport, meta.register_index);
		reg_dstport.read(meta.dstport, meta.register_index);
		reg_time_last_pkt.read(meta.time_last_pkt, (bit<32>)meta.register_index);

		if (meta.srcip == 0) {//It was an empty register
			meta.is_first = 1;
		}
		else if ((standard_metadata.ingress_global_timestamp - meta.time_last_pkt) > FLOW_TIMEOUT) {
			/*We havent heard from this flow it has been FLOW_TIMEOUT
			  We will initialse the register space
			  TODO check if init_register() is initialising all and only those needed. ;
			 */
			init_register();
			counter_timeout.count(0);
			meta.is_first = 1;
		}
		else if (meta.srcip != hdr.ipv4.dstAddr || meta.srcport != meta.hdr_srcport 
		|| meta.dstport != meta.hdr_dstport) {
			//Hash collision!
			//TODO handle hash collisions in a better way!
			meta.is_hash_collision = 1;
			counter_hash_collisions.count(0);
		}

		if (meta.is_hash_collision == 0) {

		if (meta.is_first == 1) {//shouldn't happen!
			meta.time_first_pkt = standard_metadata.ingress_global_timestamp;
			reg_time_first_pkt.write((bit<32>)meta.register_index, meta.time_first_pkt);
			reg_srcip.write((bit<32>)meta.register_index, hdr.ipv4.dstAddr);
			reg_srcport.write((bit<32>)meta.register_index, meta.hdr_srcport);
			reg_dstport.write((bit<32>)meta.register_index, meta.hdr_dstport);

		}

		//dpkts and dload
		reg_dpkts.read(meta.dpkts, (bit<32>)meta.register_index);	
		meta.dpkts = meta.dpkts + 1;
 		reg_dpkts.write((bit<32>)meta.register_index, meta.dpkts);	
 		
		//dbytes
		reg_dbytes.read(meta.dbytes, (bit<32>)meta.register_index);
		meta.dbytes = meta.dbytes + standard_metadata.packet_length - 14;
		reg_dbytes.write((bit<32>)meta.register_index, meta.dbytes);

        	reg_time_last_pkt.write((bit<32>)meta.register_index, 		
				standard_metadata.ingress_global_timestamp );

		//Read other features from the sources to destination direction
		meta.dttl =  hdr.ipv4.ttl;
		reg_dttl.write((bit<32>)meta.register_index, meta.dttl);
		reg_ttl.read(meta.sttl, (bit<32>)meta.register_index);
		reg_sbytes.read(meta.sbytes, (bit<32>)meta.register_index);
		reg_spkts.read(meta.spkts, (bit<32>)meta.register_index);
		
		}//hash collision check

	      } // end of direction = 0

		//Read common features

		if (meta.is_hash_collision == 0) {
		//TODO on hash collision we are letting the flow pass
		//We can also do a false detection!

		reg_tcprtt.read(meta.tcprtt, (bit<32>)meta.register_index);
		reg_time_first_pkt.read(meta.time_first_pkt, (bit<32>)meta.register_index);
		meta.dur = standard_metadata.ingress_global_timestamp - meta.time_first_pkt;

		reg_time_last_pkt.write((bit<32>)meta.register_index, 		
					standard_metadata.ingress_global_timestamp );
		

		calc_state();
		calc_ct_state_ttl();
		read_ct_srv_dst();
	
		init_features();


		//start with parent node of decision tree
		meta.prevFeature = 0;
		meta.isTrue = 1;

		reg_marked_malware.read(meta.marked_malware, (bit<32>)meta.register_index);

		
		if (meta.direction == 1) {
			malware.apply();//For statistics
		}
		else {
			malware_inverse.apply();//For statistics
		}
		
		if (meta.marked_malware == 1) {
			meta.class = 1;//No need to check again!
		}	
		else {

		//decision tree 1

		level1.apply();
		
		if (meta.class == CLASS_NOT_SET) {
		  level2.apply();
		  if (meta.class == CLASS_NOT_SET) {
		    level3.apply();
		    if (meta.class == CLASS_NOT_SET) {
			level4.apply();
			if (meta.class == CLASS_NOT_SET) {
			  level5.apply();
			  if (meta.class == CLASS_NOT_SET) {
			    level6.apply();
			    if (meta.class == CLASS_NOT_SET) {
			      level7.apply();
			      if (meta.class == CLASS_NOT_SET) {
				level8.apply();
				if (meta.class == CLASS_NOT_SET) {
				  level9.apply();
				  if (meta.class == CLASS_NOT_SET) {
				    level10.apply();
			            if (meta.class == CLASS_NOT_SET) 
					level11.apply();
		}}}}}}}}}

		//decision tree 2
		meta.node_id = 287;
		meta.prevFeature = 0;
		meta.isTrue = 1;

		level_2_1.apply();
		
		if (meta.class2 == CLASS_NOT_SET) {
		  level_2_2.apply();
		  if (meta.class2 == CLASS_NOT_SET) {
		    level_2_3.apply();
		    if (meta.class2 == CLASS_NOT_SET) {
			level_2_4.apply();
			if (meta.class2 == CLASS_NOT_SET) {
			  level_2_5.apply();
			  if (meta.class2 == CLASS_NOT_SET) {
			    level_2_6.apply();
			    if (meta.class2 == CLASS_NOT_SET) {
			      level_2_7.apply();
			      if (meta.class2 == CLASS_NOT_SET) {
				level_2_8.apply();
				if (meta.class2 == CLASS_NOT_SET) {
				  level_2_9.apply();
				  if (meta.class2 == CLASS_NOT_SET) {
				    level_2_10.apply();
			            if (meta.class2 == CLASS_NOT_SET) 
					level_2_11.apply();
		}}}}}}}}}

		//decision tree 3 
		meta.node_id = 602;
		meta.prevFeature = 0;
		meta.isTrue = 1;

		level_3_1.apply();
		
		if (meta.class3 == CLASS_NOT_SET) {
		  level_3_2.apply();
		  if (meta.class3 == CLASS_NOT_SET) {
		    level_3_3.apply();
		    if (meta.class3 == CLASS_NOT_SET) {
			level_3_4.apply();
			if (meta.class3 == CLASS_NOT_SET) {
			  level_3_5.apply();
			  if (meta.class3 == CLASS_NOT_SET) {
			    level_3_6.apply();
			    if (meta.class3 == CLASS_NOT_SET) {
			      level_3_7.apply();
			      if (meta.class3 == CLASS_NOT_SET) {
				level_3_8.apply();
				if (meta.class3 == CLASS_NOT_SET) {
				  level_3_9.apply();
				  if (meta.class3 == CLASS_NOT_SET) {
				    level_3_10.apply();
			            if (meta.class3 == CLASS_NOT_SET) 
					level_3_11.apply();
		}}}}}}}}}

		//voting from results of different trees
		if (meta.class == CLASS_NOT_SET) meta.class = 0; //TODO to check why this can happen!
		if (meta.class2 == CLASS_NOT_SET) meta.class2 = 0;
		if (meta.class3 == CLASS_NOT_SET) meta.class3 = 0;		

		meta.class = meta.class + meta.class2 + meta.class3;

		if (meta.class <= 1) meta.class = 0;
		else meta.class = 1; 

		}//end of check for malware marked

		if (meta.malware == 1) {// meta.malware is calculated with priori knowledge for statistics

			counter_malware.count(0);

			if (meta.is_first == 1) {
				counter_malware_flows.count(0);
			}

			if(meta.class == 1) {
				counter_true_detection.count(0);
				
				if (meta.marked_malware == 0) {
					//We detect the flow as malware first time!			
					counter_true_detection_flows.count(0);
				}
				reg_marked_malware.write((bit<32>)meta.register_index,1);
			}
		 }
		 else {
			if(meta.class == 1) {
				counter_false_detection.count(0);
				
				if (meta.marked_malware == 0) {
					//We detect the flow as malware first time! even if false
					counter_false_detection_flows.count(0);
				}
				reg_marked_malware.write((bit<32>)meta.register_index,1);
			}
		}
		
		}//hash collision check

	      debug.apply();

	      
		
	   }//End of if (hdr.ipv4.protocol == 6 || hdr.ipv4.protocol == 17)

	        ipv4_exact.apply();

	}//End of if hdr.ipv4.isValid()
     
    }//End of apply
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	      hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
	    HashAlgorithm.csum16);
    }
}

/*************************************************************************

***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
