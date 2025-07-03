from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import tcp
from ryu.lib.packet import udp
from ryu.lib.packet import arp
from ryu.lib import hub
import csv
import time
import math
import statistics
from datetime import datetime
from ml import MachineLearningAlgo

# Configuración global
APP_TYPE = 1  # 1: ddos detection
PREVENTION = 1  # DDoS prevention activada
TEST_TYPE = 0   # 0: normal
INTERVAL = 5    # Intervalo de monitoreo en segundos
MIN_ATTACK_DURATION = 20  # Segundos mínimos para considerar ataque real
CONSECUTIVE_DETECTIONS = 3  # Número de detecciones positivas requeridas

# Estructuras globales para múltiples switches
gflows = {}
iteration = {}
old_ssip_len = {}
prev_flow_count = {}
flow_cookie = {}
BLOCKED_PORTS = {}
keystore = {}
attack_start_time = {}

def get_iteration(dpid):
    global iteration
    iteration.setdefault(dpid, 0)
    return iteration[dpid]

def set_iteration(dpid, count):
    global iteration
    iteration[dpid] = count

def get_old_ssip_len(dpid):
    global old_ssip_len
    old_ssip_len.setdefault(dpid, 0)
    return old_ssip_len[dpid]

def set_old_ssip_len(dpid, count):
    global old_ssip_len
    old_ssip_len[dpid] = count

def get_prev_flow_count(dpid):
    global prev_flow_count
    prev_flow_count.setdefault(dpid, 0)
    return prev_flow_count[dpid]

def set_prev_flow_count(dpid, count):
    global prev_flow_count
    prev_flow_count[dpid] = count

def get_flow_number(dpid):
    global flow_cookie
    flow_cookie.setdefault(dpid, 0)
    flow_cookie[dpid] += 1
    return flow_cookie[dpid]

def get_time():
    return datetime.now()

def calculate_value(key, val):
    key = str(key).replace(".", "_")
    if key in keystore:
        oldval = keystore[key]
        cval = (val - oldval) 
        keystore[key] = val
        return cval
    else:
        keystore[key] = val
        return 0

def init_portcsv(dpid):
    fname = f"switch_{dpid}_data.csv"
    with open(fname, 'a', buffering=1) as f:
        writ = csv.writer(f, delimiter=',')
        header = ["time", "sfe", "ssip", "rfip", "sdfp", "sdfb", "type"]
        writ.writerow(header)

def init_flowcountcsv(dpid):
    fname = f"switch_{dpid}_flowcount.csv"
    with open(fname, 'a', buffering=1) as f:
        writ = csv.writer(f, delimiter=',')
        header = ["time", "flowcount"]
        writ.writerow(header)

def update_flowcountcsv(dpid, row):
    fname = f"switch_{dpid}_flowcount.csv"
    with open(fname, 'a', buffering=1) as f:
        writ = csv.writer(f, delimiter=',')
        writ.writerow(row)

def update_portcsv(dpid, row):
    fname = f"switch_{dpid}_data.csv"
    with open(fname, 'a', buffering=1) as f:
        row.append(str(TEST_TYPE))
        writ = csv.writer(f, delimiter=',')
        writ.writerow(row)

def update_resultcsv(row):
    with open("result.csv", 'a', buffering=1) as f:
        row.append(str(TEST_TYPE))
        writ = csv.writer(f, delimiter=',')
        writ.writerow(row)

class DDoSML(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DDoSML, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.arp_ip_to_port = {}
        self.datapaths = {}
        self.mitigation = 0
        self.mlobj = None
        self.attack_status = {}
        
        if APP_TYPE == 1:
            self.mlobj = MachineLearningAlgo()
            self.logger.info("Modo de detección DDoS (ML) activado")
        else:
            self.logger.info("Modo de colección de datos activado")
        
        self.flow_thread = hub.spawn(self._flow_monitor)

    def _flow_monitor(self):
        hub.sleep(INTERVAL * 2)
        while True:
            for dp in self.datapaths.values():
                self.request_flow_metrics(dp)
            hub.sleep(INTERVAL)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        
        self.datapaths[dpid] = datapath
        self.mac_to_port.setdefault(dpid, {})
        self.arp_ip_to_port.setdefault(dpid, {})
        BLOCKED_PORTS.setdefault(dpid, [])
        self.attack_status.setdefault(dpid, {
            'active': False, 
            'start_time': 0,
            'positive_count': 0,
            'last_detection_time': 0
        })

        # Flujo por defecto (table-miss)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions, get_flow_number(dpid))

        # Flujo para ARP
        match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP)
        self.add_flow(datapath, 10, match, actions, get_flow_number(dpid))

        # Inicializar archivos CSV para este switch
        init_portcsv(dpid)
        init_flowcountcsv(dpid)
        self.logger.info(f"Switch {dpid} conectado")

    def request_flow_metrics(self, datapath):
        ofp_parser = datapath.ofproto_parser
        req = ofp_parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    def _speed_of_flow_entries(self, dpid, flows):
        curr_flow_count = len(flows)
        sfe = curr_flow_count - get_prev_flow_count(dpid)
        set_prev_flow_count(dpid, curr_flow_count)
        return sfe

    def _speed_of_source_ip(self, dpid, flows):
        ssip = set()
        for flow in flows:
            if 'ipv4_src' in flow.match:
                ssip.add(flow.match['ipv4_src'])
        
        cur_ssip_len = len(ssip)
        ssip_result = cur_ssip_len - get_old_ssip_len(dpid)
        set_old_ssip_len(dpid, cur_ssip_len)
        return ssip_result

    def _ratio_of_flowpair(self, dpid, flows):
        flow_count = max(len(flows) - 1, 1)
        interactive_flows = set()
        
        for flow in flows:
            if 'ipv4_src' in flow.match and 'ipv4_dst' in flow.match:
                src_ip = flow.match['ipv4_src']
                dst_ip = flow.match['ipv4_dst']
                flow_pair = frozenset({src_ip, dst_ip})
                interactive_flows.add(flow_pair)
        
        iflow = len(interactive_flows) * 2
        return float(iflow) / flow_count if flow_count > 0 else 1.0

    def _stddev_packets(self, dpid, flows):
        packet_counts = []
        byte_counts = []
        hdr = f"switch_{dpid}"
        
        for flow in flows:
            if 'ipv4_src' in flow.match and 'ipv4_dst' in flow.match:
                src_ip = flow.match['ipv4_src']
                dst_ip = flow.match['ipv4_dst']
                
                byte_key = f"{hdr}_{src_ip}_{dst_ip}.bytes_count"
                pkt_key = f"{hdr}_{src_ip}_{dst_ip}.packets_count"
                
                byte_diff = calculate_value(byte_key, flow.byte_count)
                pkt_diff = calculate_value(pkt_key, flow.packet_count)
                
                byte_counts.append(byte_diff)
                packet_counts.append(pkt_diff)
        
        try:
            stddev_pkt = statistics.stdev(packet_counts) if packet_counts else 0
            stddev_byte = statistics.stdev(byte_counts) if byte_counts else 0
            return stddev_pkt, stddev_byte
        except:
            return 0, 0

    def _is_real_attack(self, dpid, result):
        """Verifica si el ataque es real basado en duración y detecciones consecutivas"""
        status = self.attack_status[dpid]
        
        if '1' in result:
            status['positive_count'] += 1
            status['last_detection_time'] = time.time()
            
            if not status['active']:
                status['start_time'] = time.time()
                status['active'] = True
                self.logger.info(f"Switch {dpid}: Posible ataque iniciado - En evaluación...")
                return False
        else:
            # Decrementar contador si no hay detección reciente
            if time.time() - status['last_detection_time'] > INTERVAL * 2:
                status['positive_count'] = max(0, status['positive_count'] - 1)
        
        duration = time.time() - status['start_time']
        return (duration >= MIN_ATTACK_DURATION and 
                status['positive_count'] >= CONSECUTIVE_DETECTIONS)

    def _reset_attack_status(self, dpid):
        """Resetea el estado de ataque"""
        self.attack_status[dpid] = {
            'active': False,
            'start_time': 0,
            'positive_count': 0,
            'last_detection_time': 0
        }

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        flows = ev.msg.body
        
        gflows.setdefault(dpid, [])
        gflows[dpid].extend(flows)

        if ev.msg.flags == 0:
            sfe = self._speed_of_flow_entries(dpid, gflows[dpid])
            ssip = self._speed_of_source_ip(dpid, gflows[dpid])
            rfip = self._ratio_of_flowpair(dpid, gflows[dpid])
            sdfp, sdfb = self._stddev_packets(dpid, gflows[dpid])

            if APP_TYPE == 1 and get_iteration(dpid) == 1:
                self.logger.info(f"Switch {dpid} - sfe:{sfe} ssip:{ssip} rfip:{rfip} sdfp:{sdfp} sdfb:{sdfb}")
                result = self.mlobj.classify([sfe, ssip, rfip, sdfp, sdfb])
                
                if '1' in result:
                    if self._is_real_attack(dpid, result):
                        self.logger.warning(f"¡Ataque DDoS confirmado en Switch {dpid}!")
                        self.mitigation = 1
                        if PREVENTION == 1:
                            self._activate_prevention(dpid)
                    else:
                        self.logger.info(f"Switch {dpid}: Señales de ataque en progreso...")
                else:
                    self.logger.info(f"Switch {dpid}: Tráfico normal")
                    if self.mitigation == 1:
                        self._deactivate_prevention(dpid)
                        self.mitigation = 0
                    self._reset_attack_status(dpid)
            else:
                t = get_time().strftime("%m/%d/%Y, %H:%M:%S")
                update_portcsv(dpid, [t, str(sfe), str(ssip), str(rfip), str(sdfp), str(sdfb)])
                update_resultcsv([str(sfe), str(ssip), str(rfip), str(sdfp), str(sdfb)])

            gflows[dpid] = []
            set_iteration(dpid, 1)
            update_flowcountcsv(dpid, [get_time().strftime("%m/%d/%Y, %H:%M:%S"), str(get_prev_flow_count(dpid))])

    def _activate_prevention(self, dpid):
        """Activa medidas de prevención mejoradas"""
        datapath = self.datapaths.get(dpid)
        if not datapath:
            return
            
        self.logger.info(f"Iniciando prevención en Switch {dpid}")
        
        # 1. Bloquear puertos sospechosos
        suspicious_ports = self._identify_suspicious_ports(dpid)
        
        for port in suspicious_ports:
            if port not in BLOCKED_PORTS[dpid]:
                self.block_port(datapath, port)
                BLOCKED_PORTS[dpid].append(port)
                self.logger.info(f"Switch {dpid}: Puerto {port} bloqueado")
        
        # 2. Limitar tasa de flujos nuevos
        self._limit_new_flows(datapath)

    def _deactivate_prevention(self, dpid):
        """Desactiva medidas de prevención"""
        datapath = self.datapaths.get(dpid)
        if not datapath:
            return
            
        self.logger.info(f"Finalizando prevención en Switch {dpid}")
        
        # 1. Limpiar flujos de bloqueo
        for port in BLOCKED_PORTS[dpid]:
            self._remove_block_flow(datapath, port)
        
        # 2. Restaurar límites normales
        self._restore_normal_flow_limits(datapath)
        
        BLOCKED_PORTS[dpid] = []
        self.logger.info(f"Switch {dpid}: Prevención desactivada")

    def _identify_suspicious_ports(self, dpid):
        """Identifica puertos sospechosos basado en múltiples factores"""
        suspicious_ports = set()
        
        # 1. Puertos con muchas IPs diferentes
        for port, ip_list in self.arp_ip_to_port.get(dpid, {}).items():
            if len(ip_list) > 10:  # Más de 10 IPs diferentes
                suspicious_ports.add(port)
        
        # 2. Puertos con alta tasa de nuevos flujos
        if dpid in gflows and gflows[dpid]:
            port_flow_counts = {}
            for flow in gflows[dpid]:
                if 'in_port' in flow.match:
                    port = flow.match['in_port']
                    port_flow_counts[port] = port_flow_counts.get(port, 0) + 1
            
            avg_flows = sum(port_flow_counts.values()) / len(port_flow_counts) if port_flow_counts else 0
            for port, count in port_flow_counts.items():
                if count > avg_flows * 3:  # 3 veces el promedio
                    suspicious_ports.add(port)
        
        return list(suspicious_ports)

    def _limit_new_flows(self, datapath):
        """Limita la tasa de nuevos flujos durante un ataque"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Limitar a 100 nuevos flujos por segundo
        meter_id = 1
        bands = [parser.OFPMeterBandDrop(rate=100, burst_size=0)]
        meter_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=bands
        )
        datapath.send_msg(meter_mod)
        
        # Aplicar medidor a todos los flujos nuevos
        match = parser.OFPMatch()
        inst = [
            parser.OFPInstructionMeter(meter_id),
            parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, [])
        ]
        self.add_flow(datapath, 10, match, inst, get_flow_number(datapath.id))

    def _restore_normal_flow_limits(self, datapath):
        """Restaura límites normales de flujo"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # Eliminar medidor de tasa
        meter_mod = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_DELETE,
            meter_id=1
        )
        datapath.send_msg(meter_mod)

    def _remove_block_flow(self, datapath, portnumber):
        """Elimina reglas de bloqueo para un puerto"""
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=portnumber)
        
        mod = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=match,
            priority=100
        )
        datapath.send_msg(mod)

    def add_flow(self, datapath, priority, match, actions, serial_no, buffer_id=None, idletime=0, hardtime=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(
                datapath=datapath, cookie=serial_no, buffer_id=buffer_id,
                idle_timeout=idletime, hard_timeout=hardtime,
                priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(
                datapath=datapath, cookie=serial_no, priority=priority,
                idle_timeout=idletime, hard_timeout=hardtime,
                match=match, instructions=inst)
                
        datapath.send_msg(mod)

    def block_port(self, datapath, portnumber):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(in_port=portnumber)
        flow_serial_no = get_flow_number(datapath.id)
        self.add_flow(datapath, 100, match, [], flow_serial_no, hardtime=300)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("paquete truncado: %s de %s bytes",
                            ev.msg.msg_len, ev.msg.total_len)

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        dpid = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        
        if not eth:
            return

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        self.mac_to_port.setdefault(dpid, {})
        self.arp_ip_to_port.setdefault(dpid, {})
        self.arp_ip_to_port[dpid].setdefault(in_port, [])
        BLOCKED_PORTS.setdefault(dpid, [])

        self.mac_to_port[dpid][src] = in_port

        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt and arp_pkt.src_ip not in self.arp_ip_to_port[dpid][in_port]:
                self.arp_ip_to_port[dpid][in_port].append(arp_pkt.src_ip)

        if out_port != ofproto.OFPP_FLOOD:
            if eth.ethertype == ether_types.ETH_TYPE_IP:
                ip_pkt = pkt.get_protocol(ipv4.ipv4)
                if ip_pkt:
                    if self.mitigation and PREVENTION:
                        if (in_port not in BLOCKED_PORTS[dpid] and 
                            ip_pkt.src not in self.arp_ip_to_port[dpid].get(in_port, [])):
                            self.logger.warning(f"Bloqueando tráfico sospechoso desde {ip_pkt.src} en puerto {in_port}")
                            self.block_port(datapath, in_port)
                            BLOCKED_PORTS[dpid].append(in_port)
                            return

                    match = parser.OFPMatch(
                        in_port=in_port,
                        eth_type=ether_types.ETH_TYPE_IP,
                        ipv4_src=ip_pkt.src,
                        ipv4_dst=ip_pkt.dst)
                    
                    actions = [parser.OFPActionOutput(out_port)]
                    flow_serial_no = get_flow_number(dpid)
                    
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, flow_serial_no, 
                                     buffer_id=msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions, flow_serial_no)

        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

if __name__ == '__main__':
    from ryu.cmd import manager
    manager.main()