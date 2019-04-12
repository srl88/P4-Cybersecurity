/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_TUNNEL = 0X123;
const bit<9> INGRESS_PORT= 1;
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

header tunnel_t {
    bit<16> protocol_flag;
    ip4Addr_t dstAddr;
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

    //Determine the protocol based on the port.
    state start {
        transition select(standard_metadata.ingress_port){
            INGRESS_PORT: parse_ethernet;
            default: parse_tunnel;
        }
    }

    //parse the ethernet header
    state parse_ethernet{
    	packet.extract(hdr.ethernet);
    	transition select(hdr.ethernet.etherType){
    		0x800: parse_ipv4;
    		default:accept;
    	}
    }

    //parse the ipv4 headedr
    state parse_ipv4{
    	packet.extract(hdr.ipv4);
    	transition accept;
    }

    //parse the tunnel 
    state parse_tunnel{
        packet.extract(hdr.tunnel);
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
    
    //INGRESS POINT TO THE NETWORK
    action ipv4_forward(egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.tunnel.setValid();
        hdr.ethernet.setInvalid();
        hdr.tunnel.dstAddr = hdr.ipv4.dstAddr;
        hdr.tunnel.protocol_flag = TYPE_TUNNEL;
    }
    
        //TUNNEL REGULAR ROUTING
    action routing_tunnel(egressSpec_t port){
        standard_metadata.egress_spec = port;
    }

    //TUNNEL EGRESS EXIT
    action egress_routing(macAddr_t dstAddr, macAddr_t srcAddr ,egressSpec_t port){
        standard_metadata.egress_spec = port;
        hdr.ethernet.setValid();
        hdr.ethernet.srcAddr = srcAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ethernet.etherType = TYPE_IPV4;
        hdr.tunnel.setInvalid();
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: exact;
        }
        actions = {
            ipv4_forward;
            drop;
        }
        size = 1024;
        default_action = drop();
    }
    
    table ip_tunnel{
        key = {
            hdr.tunnel.dstAddr: exact;
        }
        actions = {
            routing_tunnel;
            egress_routing;
            drop;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if(hdr.ethernet.isValid()){
            //regular processing
        	ipv4_lpm.apply();
        }
        else if(hdr.tunnel.isValid()){
            //special processing
            ip_tunnel.apply();
        }
        else{
        //Does not match our protocol so drop it
            mark_to_drop();
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
        // add headers
        packet.emit(hdr.ethernet);
        packet.emit(hdr.tunnel);
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
