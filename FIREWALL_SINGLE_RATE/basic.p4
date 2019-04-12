/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<32> ADD_HIT = 1;

/*************************************************************************
*********************** R E G I S T E R S  *******************************
*************************************************************************/
const bit<32> MAX_SIZE = 1 << 16;

register<bit<32>> (MAX_SIZE) COUNT_REG;
register<bit<48>> (MAX_SIZE) TIME_REG;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/


typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> count_t;
typedef bit<48> time_t;
typedef bit<32> index_t;

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

struct metadata {
    /* empty */
    bit<48> time_elapse_total;
    bit<32> count_total;
    bit<1> to_drop;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
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

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
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

    //drop
    action drop() {
        mark_to_drop();
    }
    

    //regular forwarding
    action l3(macAddr_t dstAddr, egressSpec_t port, count_t max_count, time_t time_interval, index_t index) {

    	// READ ALL REGISTERS
    	COUNT_REG.read(meta.count_total, index);
    	TIME_REG.read(meta.time_elapse_total, index);

    	//calculate
    	meta.count_total = meta.count_total + ADD_HIT;

    	//Scenatio 1... enough time has elapse... reset all
    	if(standard_metadata.ingress_global_timestamp - meta.time_elapse_total > time_interval){
    		meta.time_elapse_total = standard_metadata.ingress_global_timestamp;
    		meta.count_total = 0;
    		meta.to_drop = 0;

    	}else{
    		// scenario 2... above hit threshold.. drop
    		if(meta.count_total>max_count){
    			meta.to_drop = 1;
    		}else{
    			//scenatio 3... all good
    			meta.to_drop = 0;
    		}
    	}

    	//check if packet drop is marked... if so dont update...
    	//if(meta.to_drop==0){
    		standard_metadata.egress_spec = port;
        	hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        	hdr.ethernet.dstAddr = dstAddr;
        	hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    	//}

    	//update all registers again
    	COUNT_REG.write(index, meta.count_total);
    	TIME_REG.write(index, meta.time_elapse_total);
    }
    
    table drop_it {
    	key = {
    		meta.to_drop: exact;
    	}
    	actions = {
    		drop;
    		NoAction;
    	}
    	size = 1;
    	default_action = NoAction();
    }
    //table to forward
    table simple_forward {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            l3;
            drop;
        }
        size = 1024;
        default_action = drop();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            simple_forward.apply();
            if(meta.to_drop==1){
            	drop_it.apply();
        	}
        }
    }
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
     apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
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
