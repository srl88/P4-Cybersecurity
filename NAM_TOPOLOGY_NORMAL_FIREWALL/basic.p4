/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<9> INGRESS_PORT= 1;

const bit<32> ADD_HIT = 1;
/*************************************************************************
*********************** R E G I S T E R S  *******************************
*************************************************************************/
const bit<32> MAX_SIZE = 1 << 16;
const bit<32> MIN_SIZE = 2;
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

header tunnel_t {
    bit<16> protocol_flag;
    ip4Addr_t dstAddr;
}

struct metadata {
    bit<48> time_elapse_total;
    bit<32> count_total;
    bit<32> index;
    bit<32> ip_count;
    bit<48> ip_time_elapse;
    bit<1> to_drop;
}

struct headers {
    ethernet_t   ethernet;
    tunnel_t     tunnel;
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
        transition select(standard_metadata.ingress_port){
            INGRESS_PORT: parse_ethernet;
            default: parse_ethernet;
        }
    }

    //start the paring
    state parse_ethernet{
    	// Read the header ethernet
    	packet.extract(hdr.ethernet);
    	//get the type and call the next state
    	transition select(hdr.ethernet.etherType){
    		0x800: parse_ipv4;
    		default:accept;
    	}
    }

    // ipv4 state for ip packages
    state parse_ipv4{
    	//extract the ipv4 struct and accept it
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
    action drop() {
        mark_to_drop();
    }
    
    action ipv4_exit(macAddr_t dstAddr, egressSpec_t port, count_t max_count, time_t time_interval, index_t index, count_t heavy_hitter){
        /*****************************************************
        *********************GET ALL VARIABLES ***************
        *****************************************************/
        // READ ALL REGISTERS
        COUNT_REG.read(meta.count_total, index);
        TIME_REG.read(meta.time_elapse_total, index);
        hash(meta.index, HashAlgorithm.crc32, MIN_SIZE, { hdr.ipv4.srcAddr }, MAX_SIZE);
        COUNT_REG.read(meta.ip_count , meta.index);
        TIME_REG.read(meta.ip_time_elapse , meta.index);

        meta.count_total = meta.count_total + ADD_HIT;
        meta.to_drop=0;
        meta.ip_count = meta.ip_count+ADD_HIT;

        /*****************************************************
        *********************TOTAL COUNT CHECK ***************
        *****************************************************/

        //Scenatio 1... enough time has elapse... reset all
        if(standard_metadata.ingress_global_timestamp - meta.time_elapse_total > time_interval){
            meta.time_elapse_total = standard_metadata.ingress_global_timestamp;
            meta.count_total = 0;
            meta.to_drop = 1;

        }else{
            // scenario 2... above hit threshold.. drop it
            if(meta.count_total>max_count){
                meta.to_drop = 0;
            }else{
                //scenatio 3... all good
                meta.to_drop = 1;
            }
        }


        /*****************************************************
        ********************* SINGLE IP CHECK  ***************
        *****************************************************/

        if(meta.to_drop==1){
            //same logic as above
            if(standard_metadata.ingress_global_timestamp - meta.ip_time_elapse > time_interval){
                meta.to_drop=1;
                meta.ip_time_elapse = standard_metadata.ingress_global_timestamp;
                meta.ip_count=0;
            }else{
                if(meta.ip_count>heavy_hitter){
                    meta.to_drop = 0;
                }else{
                    meta.to_drop = 1;
                }
            }
        }

        /*****************************************************
        *********************     FORWARD      ***************
        *****************************************************/
        //check if packet drop is marked... if so dont update...
        if(meta.to_drop==1){
            standard_metadata.egress_spec = port;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = dstAddr;
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        }

        //update all registers again
        COUNT_REG.write(index, meta.count_total);
        TIME_REG.write(index, meta.time_elapse_total);
        COUNT_REG.write(meta.index, meta.ip_count);
        TIME_REG.write(meta.index, meta.ip_time_elapse);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        meta.to_drop=1;
    }
    
    //table to drop the packet
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

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            ipv4_exit;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    
    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            if(meta.to_drop==0){
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

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
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
