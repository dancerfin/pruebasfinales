#!/usr/bin/python
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from mininet.node import OVSSwitch, RemoteController
from mininet.link import TCLink
from mininet.util import quietRun
from time import sleep
import random
import sys
import os

# Configuración global
TEST_DURATION = 600
TRAFFIC_TYPES = ["normal", "attack", "mixed", "cli"]
DEFAULT_TYPE = "mixed"
SERVER_PORTS = [5001, 5002, 80]
SWITCH_STARTUP_DELAY = 5  # Espera entre inicio de switches

def clean_system():
    """Limpia todas las interfaces y procesos residuales"""
    info('*** Limpiando sistema\n')
    for i in range(1, 6):
        for j in range(1, 5):
            quietRun(f'ip link del s{i}-eth{j} 2>/dev/null')
    quietRun('ip -all netns del 2>/dev/null')
    quietRun('mn -c 2>/dev/null')
    for i in range(1, 6):
        quietRun(f'ovs-vsctl --if-exists del-br s{i}')

class AdvancedTopo(Topo):
    def __init__(self, **opts):
        clean_system()
        self.host_ips = {}
        self.server_hosts = [5, 7, 9, 11, 13]
        Topo.__init__(self, **opts)

    def build(self):
        info('*** Creando topología\n')
        
        # Crear switches con retardo entre ellos
        switches = []
        for i in range(1, 6):
            switch = self.addSwitch(f's{i}', protocols='OpenFlow13')
            switches.append(switch)
            sleep(SWITCH_STARTUP_DELAY)  # Retardo entre switches
        
        # Conectar switches con parámetros optimizados
        self.addLink(switches[0], switches[1], cls=TCLink, bw=20, delay='1ms', loss=0)
        self.addLink(switches[0], switches[2], cls=TCLink, bw=20, delay='1ms', loss=0)
        self.addLink(switches[1], switches[3], cls=TCLink, bw=15, delay='2ms', loss=0)
        self.addLink(switches[2], switches[4], cls=TCLink, bw=15, delay='2ms', loss=0)
        
        # Configurar hosts con retardo
        for i in range(1, 14):
            ip = f'10.1.1.{i}'
            host_name = f'h{i}'
            h = self.addHost(host_name, ip=ip+'/24',
                           mac=f"00:00:00:00:00:{i:02x}",
                           defaultRoute="via 10.1.1.254")
            
            # Conexión según topología con retardo
            if i <= 5:
                self.addLink(h, switches[0], cls=TCLink, bw=10, delay='1ms', loss=0)
            elif i <= 7:
                self.addLink(h, switches[1], cls=TCLink, bw=10, delay='1ms', loss=0)
            elif i <= 9:
                self.addLink(h, switches[2], cls=TCLink, bw=10, delay='1ms', loss=0)
            elif i <= 11:
                self.addLink(h, switches[3], cls=TCLink, bw=10, delay='1ms', loss=0)
            else:
                self.addLink(h, switches[4], cls=TCLink, bw=10, delay='1ms', loss=0)
            
            self.host_ips[host_name] = ip
            sleep(0.5)  # Pequeño retardo entre hosts

def main():
    setLogLevel('info')
    clean_system()
    
    try:
        test_type = DEFAULT_TYPE
        if len(sys.argv) > 1 and sys.argv[1] in TRAFFIC_TYPES:
            test_type = sys.argv[1]
        
        duration = TEST_DURATION
        if len(sys.argv) > 2 and sys.argv[2].isdigit():
            duration = int(sys.argv[2])
        
        # Crear red con mayor tiempo de espera
        topo = AdvancedTopo()
        c1 = RemoteController('c1', ip='127.0.0.1', port=6653)
        net = Mininet(topo=topo, controller=c1, link=TCLink,
                     autoSetMacs=True, cleanup=True, waitConnected=True)
        
        # Iniciar red con espera extendida
        net.start()
        sleep(10)  # Espera extendida para que todos los switches se conecten
        
        if test_type == "cli":
            CLI(net)
        else:
            # Iniciar servicios en servidores
            for host_num in topo.server_hosts:
                h = net.get(f'h{host_num}')
                h.cmd(f'iperf -s -p {SERVER_PORTS[0]} > /tmp/iperf_tcp_{host_num}.log &')
                h.cmd(f'iperf -u -s -p {SERVER_PORTS[1]} > /tmp/iperf_udp_{host_num}.log &')
                h.cmd(f'python3 -m http.server {SERVER_PORTS[2]} > /tmp/web_{host_num}.log 2>&1 &')
                sleep(1)  # Pequeño retardo entre servidores
            
            # Manejar ataques según tipo de prueba
            attackers = [1, 2, 6, 8]
            if test_type in ["attack", "mixed"]:
                num_attackers = len(attackers) if test_type == "attack" else 2
                for attacker in attackers[:num_attackers]:
                    net.get(f'h{attacker}').cmd(f'bash attack.sh > /tmp/attack_{attacker}.log &')
                    sleep(1)  # Retardo entre atacantes
            
            # Generar tráfico normal en hosts no atacantes
            normal_hosts = [h for h in range(1, 14) if h not in attackers[:num_attackers]]
            for host in normal_hosts[:5]:  # Limitar a 5 hosts normales
                net.get(f'h{host}').cmd(f'bash normal.sh > /tmp/normal_{host}.log &')
            
            # Esperar y monitorear
            for _ in range(duration//10):
                sleep(10)
                info('*** Tiempo restante: %ds\n' % (duration - _*10))
            
    except Exception as e:
        error('*** Error: %s\n' % e)
    finally:
        info('*** Finalizando\n')
        if 'net' in locals():
            net.stop()
        clean_system()

if __name__ == '__main__':
    main()