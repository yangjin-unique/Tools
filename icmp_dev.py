#! /usr/bin/env python
# This is a tool script used with Ostinato to generate ICMP packets with special 
# ICMP Type & Code pairs on any designated interface, like eth0, eth1, lo.
# See ostinato.org for information about Ostinato.
# Author: Jin

# standard modules
import logging
import os
import sys
import time
import socket, struct

# ostinato modules 
from ostinato.core import ost_pb, DroneProxy
from ostinato.protocols.mac_pb2 import mac
from ostinato.protocols.ip4_pb2 import ip4, Ip4
from ostinato.protocols.icmp_pb2 import icmp, Icmp


def ipstr2long(ip):
    packedIp = socket.inet_aton(ip)
    return struct.unpack("!L", packedIp)[0]


# ICMP streams with type-code pairs
# add new ICMP type-code pairs here
ICMP_TYPE_CODE = [
        (3, 16), # Destination unreachable group, type = 3, code = 0~15
        (5, 4),  # Ridirect group, type = 5, code = 0~3
        (11, 2), # Time exceeded group, type = 11, code = 0~1
        (12, 3) # Parameter problem group, type = 12, code = 0~2
        ]

def main():
    # initialize defaults
    use_defaults = False
    host_name = '127.0.0.1' # default drone host name
    tx_port_number = 0
    src_mac = 0x000c292eba20 # pkt src mac, modify it 
    dst_mac = 0x18b169091010 # pkt dst mac, modify it
    src_ip = ipstr2long('192.168.168.2') # pkt scr ip, modify it
    dst_ip = ipstr2long('192.168.166.2') # pkt dst ip, modify it
    
    # compute total num of streams
    total_streams = sum([x[1] for x in ICMP_TYPE_CODE])
    print 'Total number of streams: %d' %total_streams
    
    # setup logging
    log = logging.getLogger(__name__)
    logging.basicConfig(level=logging.INFO)

    # command-line option/arg processing
    if len(sys.argv) > 1:
        if sys.argv[1] in ('-d', '--use-defaults'):
            use_defaults = True
        if sys.argv[1] in ('-h', '--help'):
            print('%s [OPTION]...' % (sys.argv[0]))
            print('Options:')
            print(' -d --use-defaults   run using default values')
            print(' -h --help           show this help')
            sys.exit(0)

    if not use_defaults:
        s = raw_input('Drone\'s Hostname/IP [%s]: ' % (host_name))
        host_name = s or host_name

    drone = DroneProxy(host_name)
    drone.TransmitMode = 'sequential'

    try:
        # connect to drone
        log.info('connecting to drone(%s:%d)' 
                % (drone.hostName(), drone.portNumber()))
        drone.connect()

        # retreive port id list
        log.info('retreiving port list')
        port_id_list = drone.getPortIdList()

        # retreive port config list
        log.info('retreiving port config for all ports')
        port_config_list = drone.getPortConfig(port_id_list)

        if len(port_config_list.port) == 0:
            log.warning('drone has no ports!')
            sys.exit(1)

        print('Port List')
        print('---------')
        print (port_config_list)
        for port in port_config_list.port:
            print('%d.%s (%s)' % (port.port_id.id, port.name, port.description))
            # use a loopback port as default tx/rx port 
            if ('lo' in port.name or 'loopback' in port.description.lower()):
                tx_port_number = port.port_id.id

        if not use_defaults:
            p = raw_input('Tx Port Id [%d]: ' % (tx_port_number))
            if p:
                tx_port_number = int(p)

        tx_port = ost_pb.PortIdList()
        tx_port.port_id.add().id = tx_port_number;

        sid = 1
        for icmp_stream in ICMP_TYPE_CODE:
            stype = icmp_stream[0]
            for scode in range(icmp_stream[1]):
                # add a stream
                print 'icmp (type, code) = (%d, %d)' %(stype, scode)
                stream_id = ost_pb.StreamIdList()
                stream_id.port_id.CopyFrom(tx_port.port_id[0])
                stream_id.stream_id.add().id = sid
                log.info('adding tx_stream %d' % stream_id.stream_id[0].id)
                drone.addStream(stream_id)

                # configure the stream
                stream_cfg = ost_pb.StreamConfigList()
                stream_cfg.port_id.CopyFrom(tx_port.port_id[0])
                s = stream_cfg.stream.add()
                s.stream_id.id = stream_id.stream_id[0].id
                s.core.is_enabled = True
                s.control.num_packets = 1

                # setup stream protocols as mac:eth2:ip4:icmp
                # setup mac header
                p = s.protocol.add()
                p.protocol_id.id = ost_pb.Protocol.kMacFieldNumber
                p.Extensions[mac].dst_mac = dst_mac
                p.Extensions[mac].src_mac = src_mac

                p = s.protocol.add()
                p.protocol_id.id = ost_pb.Protocol.kEth2FieldNumber

                #setup ip header
                p = s.protocol.add()
                p.protocol_id.id = ost_pb.Protocol.kIp4FieldNumber
                ip = p.Extensions[ip4]
                ip.src_ip = src_ip 
                ip.dst_ip = dst_ip 
                ip.dst_ip_mode = Ip4.e_im_fixed

                # setup icmp header
                p = s.protocol.add()
                p.protocol_id.id = ost_pb.Protocol.kIcmpFieldNumber
                icmp_va = p.Extensions[icmp] 
                icmp_va.icmp_version = Icmp.kIcmp4  # icmp version
                icmp_va.type = stype                # icmp type
                icmp_va.code = scode                # icmp code
                
                s.protocol.add().protocol_id.id = ost_pb.Protocol.kPayloadFieldNumber
            
                s.control.unit = ost_pb.StreamControl.e_su_packets # Send: Packets
		s.control.mode = ost_pb.StreamControl.e_sm_fixed # Mode: Fixed

                if sid < total_streams:
                    s.control.next = ost_pb.StreamControl.e_nw_goto_next
                else:
                    s.control.next = ost_pb.StreamControl.e_nw_goto_id # e_nw_stop

                s.core.ordinal = sid - 1 # keep stream transmitted in order
                sid += 1
                s.control.packets_per_sec = 20 # transmit rate: pkts per second
               
                log.info('configuring tx_stream %d' % stream_id.stream_id[0].id)
                drone.modifyStream(stream_cfg)

        log.info('clearing tx stats')
        drone.clearStats(tx_port)

        # start transmit
        log.info('starting transmit')
        drone.startTransmit(tx_port)

        # wait for transmit to finish
        log.info('waiting for transmit to finish ...')
        while True:
            try:
                time.sleep(5)
                tx_stats = drone.getStats(tx_port)
                if tx_stats.port_stats[0].state.is_transmit_on == False:
                    break
            except KeyboardInterrupt:
                log.info('Transmit terminated by user!!!')
                break

        # stop transmit and capture
        log.info('stopping transmit')
        drone.stopTransmit(tx_port)

        # get tx/rx stats
        log.info('retreiving stats')
        tx_stats = drone.getStats(tx_port)

        log.info('tx pkts = %d' % (tx_stats.port_stats[0].tx_pkts))

        # retrieve and dump received packets
        #log.info('getting Rx capture buffer')
        #drone.saveCaptureBuffer(buff, 'capture.pcap')
        #log.info('dumping Rx capture buffer')
        #os.system('tshark -r capture.pcap')
        #os.remove('capture.pcap')

        # delete streams
        log.info('deleting tx_stream %d' % stream_id.stream_id[0].id)
        drone.deleteStream(stream_id)
        # desconnect drone
        drone.disconnect()

    except Exception as ex:
        log.exception(ex)
        sys.exit(1)


if __name__ == '__main__':
    main()
