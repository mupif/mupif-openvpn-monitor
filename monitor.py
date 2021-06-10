#!/usr/local/anaconda3/envs/musicode/bin/python

# Licensed under GPL v3
# Copyright 2011 VPAC <http://www.vpac.org>
# Copyright 2012-2016 Marcus Furlong <furlongm@gmail.com>

try:
    import ConfigParser as configparser
except ImportError:
    import configparser

try:
    from ipaddr import IPAddress as ip_address
    from ipaddr import IPv6Address
except ImportError:
    from ipaddress import ip_address, IPv6Address


# this might go to the config file as well
REQUIRE_LOGIN=False 

import socket
import re
import argparse
import sys
import GeoIP
import sys
import os
import cgi
#import cgitb
#cgitb.enable()
from datetime import datetime
from humanize import naturalsize
from collections import OrderedDict, deque
from pprint import pformat
from semantic_version import Version as semver
import Pyro5, Pyro5.api, Pyro5.errors

import threading

from datetime import datetime 

import json, requests
from bottle import run, template, request, route, redirect
from bottle import response, get, post, static_file, default_app

import mupif as mp


Pyro5.config.SERIALIZER="serpent"
Pyro5.config.SERVERTYPE="multiplex"
Pyro5.config.COMMTIMEOUT = 0.3      # 1.5 seconds


# to be decoded from session_id, if provided
userid = ""


def output(s):
    global wsgi, wsgi_output
    if not wsgi:
        print(s)
    else:
        wsgi_output += s


def info(*objs):
    print("INFO:", *objs, file=sys.stderr)


def warning(*objs):
    print("WARNING:", *objs, file=sys.stderr)


def debug(*objs):
    print("DEBUG:\n", *objs, file=sys.stderr)


def get_date(date_string, uts=False):
    if not uts:
        return datetime.strptime(date_string, "%a %b %d %H:%M:%S %Y")
    else:
        return datetime.fromtimestamp(float(date_string))


def get_str(s):
    if s is None: return None
    return s.encode('ascii','xmlcharrefreplace').decode('utf-8')

class ConfigLoader(object):

    def __init__(self, config_file):
        self.settings = {}
        self.vpns = OrderedDict()
        config = configparser.RawConfigParser()
        contents = config.read(config_file)

        if not contents and config_file == './openvpn-monitor.conf':
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            if sys.prefix == '/usr':
                conf_path = '/etc/'
            else:
                conf_path = sys.prefix + '/etc/'
            config_file = conf_path + 'openvpn-monitor.conf'
            contents = config.read(config_file)

        if contents:
            info('Using config file: {0!s}'.format(config_file))
        else:
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            self.load_default_settings()

        for section in config.sections():
            if section == 'OpenVPN-Monitor':
                self.parse_global_section(config)
            else:
                self.parse_vpn_section(config, section)

    def load_default_settings(self):
        info('Using default settings => localhost:5555')
        self.settings = {'site': 'Default Site',
                         'geoip_data': '/usr/share/GeoIP/GeoIPCity.dat',
                         'datetime_format': '%d/%m/%Y %H:%M:%S'}
        self.vpns['Default VPN'] = {'name': 'default',
                                    'host': 'localhost',
                                    'port': '5555',
                                    'show_disconnect': False}

    def parse_global_section(self, config):
        global_vars = ['site', 'logo', 'latitude', 'longitude', 'maps', 'geoip_data', 'datetime_format', 'vpn_type']
        for var in global_vars:
            try:
                self.settings[var] = config.get('OpenVPN-Monitor', var)
            except configparser.NoOptionError:
                pass
        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(self.settings))


    def parse_vpn_section(self, config, section):
        self.vpns[section] = {}
        vpn = self.vpns[section]
        options = config.options(section)
        for option in options:
            try:
                vpn[option] = config.get(section, option)
                if vpn[option] == -1:
                    warning('CONFIG: skipping {0!s}'.format(option))
            except configparser.Error as e:
                warning('CONFIG: {0!s} on option {1!s}: '.format(e, option))
                vpn[option] = None
        if 'show_disconnect' in vpn and vpn['show_disconnect'] == 'True':
            vpn['show_disconnect'] = True
        else:
            vpn['show_disconnect'] = False
        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(vpn))



class MupifConfigLoader(object):

    def __init__(self, config_file):
        self.mupif = {}
        self.jobmans = OrderedDict()
        config = configparser.RawConfigParser()
        contents = config.read(config_file)

        if not contents and config_file == './mupif-monitor.conf':
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            if sys.prefix == '/usr':
                conf_path = '/etc/'
            else:
                conf_path = sys.prefix + '/etc/'
            config_file = conf_path + 'mupif-monitor.conf'
            contents = config.read(config_file)

        if contents:
            info('Using config file: {0!s}'.format(config_file))
        else:
            warning('Config file does not exist or is unreadable: {0!s}'.format(config_file))
            self.load_default_settings()

        for section in config.sections():
            if section == 'mupif':
                self.parse_mupif_section(config)
            else:
                pass
                # self.parse_jobman_section(config, section)

    def load_default_settings(self):
        info('Using default settings')
        self.mupif = {'nameserver_ip': '172.30.0.1',
                      'nameserver_port': '9090',
                      'mupifdb_ip': '172.30.0.1', # mupifDB rest API
                      'mupifdb_port': '5000'}

    def parse_mupif_section(self, config):
        global_vars = ['nameserver_ip', 'nameserver_port', 'mupifdb_ip', 'mupifdb_port']
        for var in global_vars:
            try:
                self.mupif[var] = config.get('mupif', var)
            except configparser.NoOptionError:
                pass

        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(self.settings))


    def parse_jobman_section(self, config, section):
        self.jobmans[section] = {}
        jobman = self.jobmans[section]
        options = config.options(section)
        for option in options:
            try:
                jobman[option] = config.get(section, option)
                if jobman[option] == -1:
                    warning('CONFIG: skipping {0!s}'.format(option))
            except configparser.Error as e:
                warning('CONFIG: {0!s} on option {1!s}: '.format(e, option))
                jobman[option] = None
        if args.debug:
            debug("=== begin section\n{0!s}\n=== end section".format(jobman))





class mupifMonitor(object):
    def __init__(self, cfg):
        self.ns = None

        self.cfg = cfg.mupif
        self.jobmans = cfg.jobmans
        self.collect_data()

        if False:
            if (self.ns):
                for key, jobman in list(self.jobmans.items()):
                    self.collect_jobman_data(jobman)
        else:
            self.jobmans={}
            # collect all registered jobmans from nameserver using jobman metadata tag
            if (self.ns):
                query = self.ns.yplookup(meta_any={"type:jobmanager"}) # XXX this is to be tested more
                info(query)
                threads = []
                start = datetime.now()
                for name, uri in query.items():
                    self.jobmans[name] = {}
                    jobmanRec=self.jobmans[name];
                    jobmanRec['uri']=uri
                    #self.collect_jobman_data(name, uri, jobmanRec)
                    thread = threading.Thread(target=self.collect_jobman_data, args=(name, uri, jobmanRec))
                    threads.append(thread)                   
                
                for t in threads:
                    t.start()

                for t in threads:
                    t.join()
                
                end = datetime.now()
                #print ("Request time: %s"%str(end-start))

    def collect_data(self):
        #print('collect_data called')
        #print (str(self.cfg))
        self.ns_socket_connect(nshost=self.cfg['nameserver_ip'],nsport=self.cfg['nameserver_port'])
        try:
            #print("Querying mupifDB status:\n")
            #print ('http://'+self.cfg['mupifdb_ip']+":"+self.cfg['mupifdb_port']+'/status')
            r=requests.get('http://'+self.cfg['mupifdb_ip']+":"+self.cfg['mupifdb_port']+'/status')
            #print("url:",  r.url)
            #print("Text:", r.text)
            status=r.json()
            #print(status)
            
            self.cfg['mupifdb_status'] = status['result'][0]
        except:
            self.cfg['mupifdb_status'] = {}
            
        
        

    def collect_jobman_data(self, name, uri, jobmanRec):

        s = datetime.now()
        hmackey = self.cfg['hmac_key'].encode(encoding='UTF-8')

        jobmanRec['status']='Failed'
        jobmanRec['note']=''
        jobmanRec['numberofrunningjobs']=''
        jobmanRec['showJobs'] = 'ON'
        try:
            
            j = Pyro5.api.Proxy(uri)
            j._pyroHmacKey = hmackey

            sig=j.getApplicationSignature()
            status = j.getStatus()
            #sig = 'KO'

            jobmanRec['status']="OK"
            jobmanRec['note']=sig
            
            #status = j.getStatus()
            
            #info(status)
            #print(status)
            jobmanRec['numberofrunningjobs']=len(status)
                                                             

        except Pyro5.errors.CommunicationError:
            jobmanRec['note']="Cannot connect to jobManager %s"%name
            
        jobmanRec['note']+="["+str(datetime.now()-s)+"]"
        return


    def ns_socket_connect(self, nshost, nsport):
        timeout = 3
        self.s = False
        self.cfg['error']=""
        try:
            self.s = socket.create_connection((nshost, nsport), timeout)
            if self.s:
                self.cfg['ns_status'] = 'OK'
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
                
        except socket.timeout as e:
            self.cfg['error'] = '{0!s}{1!s}'.format(e, nshost+':'+nsport)
            warning('socket timeout: {0!s}'.format(e))
            self.cfg['ns_status'] = 'Failed'
            if self.s:
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
        except socket.error as e:
            self.cfg['error'] = '{0!s}'.format(e.strerror)
            warning('socket error: {0!s}'.format(e))
            self.cfg['ns_status'] = 'Failed'
            return
        except Exception as e:
            self.cfg['error'] = '{0!s}'.format(e)
            warning('unexpected error: {0!s}'.format(e))
            self.cfg['ns_status'] = 'Failed'
            return


        try:
            self.ns=Pyro5.api.locate_ns(host=nshost, port=int(nsport))
            self.cfg['ns_status']="OK"
        except Exception:
            self.cfg['ns_status']="Failed"
            self.cfg['error'] = "Pyro5.api.locate_ns failed for NameServer on %s:%s" %(nshost, nsport)
    
    def _socket_recv(self, length):
        return self.s.recv(length).decode('utf-8')



class WireguardMgmtInterface(object):
    def __init__(self,cfg):
        self.vpns=cfg.vpns
        geoip_data = cfg.settings['geoip_data']
        self.gi = GeoIP.open(geoip_data, GeoIP.GEOIP_STANDARD)
        for iface,vpn in self.vpns.items():
            self.collect_data(iface,vpn)
        
    def collect_data(self,iface,vpn):
        import json,subprocess
        numver=open('/sys/module/wireguard/version').read()[:-1]
        vpn['version'] = 'Wireguard '+numver
        vpn['semver'] = semver(numver)
        vpn['socket_connected']=True
        peerMapJson=vpn.get('peer_map',None)
        peerMap=(json.load(open(peerMapJson,'r')) if peerMapJson else {})
        try:
            dta=json.loads(subprocess.check_output(['sudo','/usr/share/doc/wireguard-tools/examples/json/wg-json']))
        except subprocess.CalledProcessError:
            warnings.warn('Calling wg-json failed. You might need to add the line "ALL ALL=NOPASSWD: /usr/share/doc/wireguard-tools/examples/json/wg-json" to /etc/sudoers.d/10-wireguard-show.conf (and run chmod 0440 /etc/sudoers.d/10-wireguard-show.conf) to get wireguard information as regular user.')
            vpn['socket_connected']=False
            return
        dta=dta[iface]
        import netifaces
        ifaceip=netifaces.ifaddresses(iface)
        if netifaces.AF_INET in ifaceip: local_ip=ip_address(ifaceip[netifaces.AF_INET][0]['addr'])
        elif netiface.AF_INET6 in ifaceip: local_ip=ip_address(ifaceip[netifaces.AF_INET6][0]['addr'])
        else: local_ip='?'
        vpn['state']={
            'up_since':datetime.utcfromtimestamp(0),
            'connected':'?',
            'success':'?',
            'local_ip':local_ip,
            'remote_ip':'',
            'mode':'Server' # Client or Server
        }
        #import pprint
        #pprint.pprint(dta)
        activePeers=dict([(peerKey,peerData) for peerKey,peerData in dta['peers'].items() if 'transferRx' in peerData])
        vpn['stats']={
            'nclients':len(dta['peers']),
            'bytesin':sum([p['transferTx'] for p in activePeers.values()]),
            'bytesout':sum([p['transferRx'] for p in activePeers.values()]),
        }
        vpn['sessions']={}
        for peerKey,peerData in dta['peers'].items():
            session=vpn['sessions'][peerKey]={}
            cli=session['Client']={}
            cli['tuntap_read']=cli['tuntap_write']=cli['auth_read']=0
            cli['tcpudp_read']=peerData.get('transferRx',0)
            cli['tcpudp_write']=peerData.get('transferTx',0)
            if 0:
                print(1000*'#')
                from pprint import pprint
                pprint(peerKey)
                pprint(peerData)
            if 'endpoint' in peerData:
                # print(peerData['endpoint'])
                remote_str=peerData['endpoint']
                # copied from the OpeVPN monitor; ugly!
                if remote_str.count(':') == 1:
                    remote, port = remote_str.split(':')
                elif '(' in remote_str:
                    remote, port = remote_str.split('(')
                    port = port[:-1]
                else: remote=remote_str
                remote_ip=ip_address(remote)
                if isinstance(remote_ip, IPv6Address) and remote_ip.ipv4_mapped is not None:
                    session['remote_ip'] = remote_ip.ipv4_mapped
                else:
                    session['remote_ip'] = remote_ip
                if session['remote_ip'].is_private:
                    session['location'] = 'RFC1918'
                else:
                    try:
                        gir = self.gi.record_by_addr(str(session['remote_ip']))
                    except SystemError:
                        gir = None
                    if gir is not None:
                        session['location'] = get_str(gir['country_code'])
                        session['city'] = get_str(gir['city'])
                        session['country_name'] = gir['country_name']
                        session['longitude'] = gir['longitude']
                        session['latitude'] = gir['latitude']
            else: session['remote_ip']='<unknown>'

            session['local_ip']=peerData['allowedIps'][0]
            session['bytes_recv']=peerData.get('transferRx',0)
            session['bytes_sent']=peerData.get('transferTx',0)
            session['connected_since']=datetime.utcfromtimestamp(0)
            # TODO: read wireguard config and put friendly name here
            if peerKey in peerMap: session['username']=peerMap[peerKey]+'<br>'+peerKey[:10]+'‥'
            else: session['username']=peerKey[:10]+'‥'
            session['last_seen']=datetime.utcfromtimestamp(peerData.get('latestHandshake',0))





class OpenvpnMgmtInterface(object):

    def __init__(self, cfg, **kwargs):
        self.vpns = cfg.vpns

        if 'vpn_id' in kwargs:
            vpn = self.vpns[kwargs['vpn_id']]
            self._socket_connect(vpn)
            if vpn['socket_connected']:
                version = self.send_command('version\n')
                sem_ver = semver(self.parse_version(version).split(' ')[1])
                if sem_ver.minor == 4 and 'port' not in kwargs:
                    command = 'client-kill {0!s}\n'.format(kwargs['client_id'])
                else:
                    command = 'kill {0!s}:{1!s}\n'.format(kwargs['ip'], kwargs['port'])
                info('Sending command: {0!s}'.format(command))
                self.send_command(command)
                self._socket_disconnect

        geoip_data = cfg.settings['geoip_data']
        self.gi = GeoIP.open(geoip_data, GeoIP.GEOIP_STANDARD)

        for key, vpn in list(self.vpns.items()):
            self._socket_connect(vpn)
            if vpn['socket_connected']:
                self.collect_data(vpn)
                self._socket_disconnect()
        

    def collect_data(self, vpn):
        version = self.send_command('version\n')
        vpn['version'] = self.parse_version(version)
        vpn['semver'] = semver(vpn['version'].split(' ')[1])
        state = self.send_command('state\n')
        vpn['state'] = self.parse_state(state)
        stats = self.send_command('load-stats\n')
        vpn['stats'] = self.parse_stats(stats)
        status = self.send_command('status 3\n')
        vpn['sessions'] = self.parse_status(status, self.gi, vpn['semver'])

    def _socket_send(self, command):
        self.s.send(bytes(command, 'utf-8'))

    def _socket_recv(self, length):
        return self.s.recv(length).decode('utf-8')

    def _socket_connect(self, vpn):
        host = vpn['host']
        port = int(vpn['port'])
        timeout = 3
        self.s = False
        try:
            self.s = socket.create_connection((host, port), timeout)
            if self.s:
                vpn['socket_connected'] = True
                data = ''
                while 1:
                    socket_data = self._socket_recv(1024)
                    data += socket_data
                    if data.endswith('\r\n'):
                        break
        except socket.timeout as e:
            vpn['error'] = '{0!s}'.format(e)
            warning('socket timeout: {0!s}'.format(e))
            vpn['socket_connected'] = False
            if self.s:
                self.s.shutdown(socket.SHUT_RDWR)
                self.s.close()
        except socket.error as e:
            vpn['error'] = '{0!s}'.format(e.strerror)
            warning('socket error: {0!s}'.format(e))
            vpn['socket_connected'] = False
        except Exception as e:
            vpn['error'] = '{0!s}'.format(e)
            warning('unexpected error: {0!s}'.format(e))
            vpn['socket_connected'] = False

    def _socket_disconnect(self):
        self._socket_send('quit\n')
        self.s.shutdown(socket.SHUT_RDWR)
        self.s.close()

    def send_command(self, command):
        self._socket_send(command)
        data = ''
        if command.startswith('kill') or command.startswith('client-kill'):
            return
        while 1:
            socket_data = self._socket_recv(1024)
            socket_data = re.sub('>INFO(.)*\r\n', '', socket_data)
            data += socket_data
            if command == 'load-stats\n' and data != '':
                break
            elif data.endswith("\nEND\r\n"):
                break
        if args.debug:
            debug("=== begin raw data\n{0!s}\n=== end raw data".format(data))
        return data

    @staticmethod
    def parse_state(data):
        state = {}
        for line in data.splitlines():
            parts = line.split(',')
            if args.debug:
                debug("=== begin split line\n{0!s}\n=== end split line".format(parts))
            if parts[0].startswith('>INFO') or \
               parts[0].startswith('END') or \
               parts[0].startswith('>CLIENT'):
                continue
            else:
                state['up_since'] = get_date(date_string=parts[0], uts=True)
                state['connected'] = parts[1]
                state['success'] = parts[2]
                if parts[3]:
                    state['local_ip'] = ip_address(parts[3])
                else:
                    state['local_ip'] = ''
                if parts[4]:
                    state['remote_ip'] = ip_address(parts[4])
                    state['mode'] = 'Client'
                else:
                    state['remote_ip'] = ''
                    state['mode'] = 'Server'
        return state

    @staticmethod
    def parse_stats(data):
        stats = {}
        line = re.sub('SUCCESS: ', '', data)
        parts = line.split(',')
        if args.debug:
            debug("=== begin split line\n{0!s}\n=== end split line".format(parts))
        stats['nclients'] = int(re.sub('nclients=', '', parts[0]))
        stats['bytesin'] = int(re.sub('bytesin=', '', parts[1]))
        stats['bytesout'] = int(re.sub('bytesout=', '', parts[2]).replace('\r\n', ''))
        return stats

    @staticmethod
    def parse_status(data, gi, version):
        client_section = False
        routes_section = False
        sessions = {}
        client_session = {}

        for line in data.splitlines():
            parts = deque(line.split('\t'))
            if args.debug:
                debug("=== begin split line\n{0!s}\n=== end split line".format(parts))

            if parts[0].startswith('END'):
                break
            if parts[0].startswith('TITLE') or \
               parts[0].startswith('GLOBAL') or \
               parts[0].startswith('TIME'):
                continue
            if parts[0] == 'HEADER':
                if parts[1] == 'CLIENT_LIST':
                    client_section = True
                    routes_section = False
                if parts[1] == 'ROUTING_TABLE':
                    client_section = False
                    routes_section = True
                continue

            if parts[0].startswith('TUN') or \
               parts[0].startswith('TCP') or \
               parts[0].startswith('Auth'):
                parts = parts[0].split(',')
            if parts[0] == 'TUN/TAP read bytes':
                client_session['tuntap_read'] = int(parts[1])
                continue
            if parts[0] == 'TUN/TAP write bytes':
                client_session['tuntap_write'] = int(parts[1])
                continue
            if parts[0] == 'TCP/UDP read bytes':
                client_session['tcpudp_read'] = int(parts[1])
                continue
            if parts[0] == 'TCP/UDP write bytes':
                client_session['tcpudp_write'] = int(parts[1])
                continue
            if parts[0] == 'Auth read bytes':
                client_session['auth_read'] = int(parts[1])
                sessions['Client'] = client_session
                continue

            if client_section:
                session = {}
                parts.popleft()
                common_name = parts.popleft()
                remote_str = parts.popleft()
                if remote_str.count(':') == 1:
                    remote, port = remote_str.split(':')
                elif '(' in remote_str:
                    remote, port = remote_str.split('(')
                    port = port[:-1]
                else:
                    remote = remote_str
                    port = None
                remote_ip = ip_address(remote)
                if isinstance(remote_ip, IPv6Address) and \
                        remote_ip.ipv4_mapped is not None:
                    session['remote_ip'] = remote_ip.ipv4_mapped
                else:
                    session['remote_ip'] = remote_ip
                if port:
                    session['port'] = int(port)
                else:
                    session['port'] = ''
                if session['remote_ip'].is_private:
                    session['location'] = 'RFC1918'
                else:
                    try:
                        gir = gi.record_by_addr(str(session['remote_ip']))
                    except SystemError:
                        gir = None
                    if gir is not None:
                        session['location'] = get_str(gir['country_code'])
                        session['city'] = get_str(gir['city'])
                        session['country_name'] = gir['country_name']
                        session['longitude'] = gir['longitude']
                        session['latitude'] = gir['latitude']
                local_ipv4 = parts.popleft()
                if local_ipv4:
                    session['local_ip'] = ip_address(local_ipv4)
                else:
                    session['local_ip'] = ''
                if version.minor == 4:
                    local_ipv6 = parts.popleft()
                    if local_ipv6:
                        session['local_ip'] = ip_address(local_ipv6)
                session['bytes_recv'] = int(parts.popleft())
                session['bytes_sent'] = int(parts.popleft())
                parts.popleft()
                session['connected_since'] = get_date(parts.popleft(), uts=True)
                try:
                    username = parts.popleft()
                except:
                    username='UNDEF';
                if username != 'UNDEF':
                    session['username'] = username
                else:
                    session['username'] = common_name
                if version.minor == 4:
                    session['client_id'] = parts.popleft()
                    session['peer_id'] = parts.popleft()
                sessions[str(session['local_ip'])] = session

            if routes_section:
                local_ip = parts[1]
                last_seen = parts[5]
                if local_ip in sessions:
                    sessions[local_ip]['last_seen'] = get_date(last_seen, uts=True)

        if args.debug:
            if sessions:
                pretty_sessions = pformat(sessions)
                debug("=== begin sessions\n{0!s}\n=== end sessions".format(pretty_sessions))
            else:
                debug("no sessions")

        return sessions

    @staticmethod
    def parse_version(data):
        for line in data.splitlines():
            if line.startswith('OpenVPN'):
                return line.replace('OpenVPN Version: ', '')


class OpenvpnHtmlPrinter(object):

    def __init__(self, cfg, monitor, mupifMon):
        self.init_vars(cfg.settings, monitor, mupifMon)
        self.print_html_header()
        for key, vpn in self.vpns:
            if vpn['socket_connected']:
                self.print_vpn(key, vpn)
            else:
                self.print_unavailable_vpn(vpn)
        self.print_mupif_status(self.mupif_monitor)
        if self.maps:
            self.print_maps_html(self.mupif_monitor)
            self.print_html_footer()


    def init_vars(self, settings, monitor, mupifMon):

        self.vpns = list(monitor.vpns.items())
        self.mupif_monitor = mupifMon;

        self.site = 'Example'
        if 'site' in settings:
            self.site = settings['site']

        self.logo = None
        if 'logo' in settings:
            self.logo = settings['logo']

        self.maps = False
        if 'maps' in settings and settings['maps'] == 'True':
            self.maps = True

        self.latitude = -37.8067
        self.longitude = 144.9635
        if 'latitude' in settings:
            self.latitude = settings['latitude']
        if 'longitude' in settings:
            self.longitude = settings['longitude']

        self.datetime_format = settings['datetime_format']

    def print_html_header(self):

        global wsgi
        if not wsgi:
            output("Content-Type: text/html\n")
        output('<!doctype html>')
        output('<html><head>')
        output('<meta charset="utf-8">')
        output('<meta name="viewport" content="width=device-width, initial-scale=1">')
        output('<title>{0!s} VPN Status Monitor</title>'.format(self.site))
        output('<meta http-equiv="refresh" content="300" />')

        
        output('<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/css/bootstrap.min.css">')       
        output('<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.3.1/jquery.min.js"></script>')
        output('<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.4.0/js/bootstrap.min.js"></script>')
        output('<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.31.1/js/jquery.tablesorter.js"></script>')
        output('<script src="https://cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.31.1/js/jquery.tablesorter.widgets.js"></script>')
        


        # css
#        output('<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css" integrity="sha384-BVYiiSIFeK1dGmJRAkycuHAHRg32OmUcww7on3RYdg4Va+PmSTsz/K68vbdEjh4u" crossorigin="anonymous" />')
#        output('<link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap-theme.min.css" integrity="sha384-rHyoN1iRsVXV4nD0JutlnGaslCJuC7uwjduW9SVrLvRYooPp2bWYgmgJQIXwl/Sp" crossorigin="anonymous" />')
#        output('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/jquery.tablesorter/2.28.4/css/theme.bootstrap.min.css" integrity="sha256-cerl+DYHeG2ZhV/9iueb8E+s7rubli1gsnKuMbKDvho=" crossorigin="anonymous" />')
        if self.maps:
            output('<link rel="stylesheet" href="//cdnjs.cloudflare.com/ajax/libs/leaflet/1.0.2/leaflet.css" integrity="sha256-9mfj77orHLh2GsN7CbMvpjO/Wny/ZZhR7Pu7hy0Yig4=" crossorigin="anonymous" />')
            output('<script src="//cdnjs.cloudflare.com/ajax/libs/leaflet/1.0.2/leaflet.js" integrity="sha256-RS5bDpN9YmmUIdtdu8ESPjNp1Bg/Fqu90PwN3uawdSQ=" crossorigin="anonymous"></script>')

            #output('var List0_Icon = L.icon({')
            #output('                    iconUrl: \'/images/logos/template.png\',')
            #output('')
            #output('                    iconSize:     [38, 95], // size of the icon')
            #output('                    iconAnchor:   [22, 94], // point of the icon which will correspond to marker\'s location')
            #output('                    popupAnchor:  [-3, -76] // point from which the popup should open relative to the iconAnchor')
            #output('                    });')


            
        
        output('</head><body>')
        ############local storage
        output('<script>')
        #        output('$(document).ready(()=>{console.log(localStorage.panels)});')
        output('$(document).ready(()=>{')
        output('$(".panel .panel-collapse").on("shown.bs.collapse", function ()')
        output('{')
        output('var active = $(this).attr(\'id\');')
        output('console.log(active);')
        output('var panels= localStorage.panels === undefined ? new Array() : JSON.parse(localStorage.panels);')
        output('if ($.inArray(active,panels)==-1) //check that the element is not in the array')
        output('panels.push(active);')
        output('localStorage.panels=JSON.stringify(panels);')
        output('});')
        

        output('$(".collapse").on(\'hidden.bs.collapse\', function ()')
        output('{')
        output('var active = $(this).attr(\'id\');')
        output('var panels= localStorage.panels === undefined ? new Array() : JSON.parse(localStorage.panels);')
        output('var elementIndex=$.inArray(active,panels);')
        output('if (elementIndex!==-1) //check the array')
        output('{')
        output('panels.splice(elementIndex,1); //remove item from array')
        output('}')
        output('localStorage.panels=JSON.stringify(panels); //save array on localStorage')
        output('});')

        output('var panels=localStorage.panels === undefined ? new Array() : JSON.parse(localStorage.panels); //get all panels')
        output('for (var i in panels){ //<-- panel is the name of the cookie')
        output('if ($("#"+panels[i]).hasClass(\'panel-collapse\')) // check if this is a panel')
        output('{')
        output('$("#"+panels[i]).collapse("show");')
        output('}')
        output('}')


        output('$("#searchVpnTable").on("keyup", function() {')
        output('var value = $(this).val().toLowerCase();')
        output('$("#vpnSessions tbody").children(\'tr\').filter(function() {')
        output('$(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)')
        output('});')
        output('});')



        output('$("#searchJobManTable").on("keyup", function() {')
        output('var value = $(this).val().toLowerCase();')
        output('$("#jobManSessions tbody").children(\'tr\').filter(function() {')
        output('$(this).toggle($(this).text().toLowerCase().indexOf(value) > -1)')
        output('});')
        output('});')

        
        output('$("#vpnSessions").tablesorter();')
        output('$("#jobManSessions").tablesorter();')







        
        #end of document ready
        output('});')
        output('</script>')





        
        output('<nav class="navbar navbar-inverse">')
        output('<div class="container-fluid">')
        output('<div class="navbar-header">')
        output('<button type="button" class="navbar-toggle" ')
        output('data-toggle="collapse" data-target="#myNavbar">')
        output('<span class="icon-bar"></span>')
        output('<span class="icon-bar"></span>')
        output('<span class="icon-bar"></span>')
        output('</button>')

        output('<a class="navbar-brand" href="#">')
        output('{0!s} VPN Status Monitor</a>'.format(self.site))

        output('</div><div class="collapse navbar-collapse" id="myNavbar">')
        output('<ul class="nav navbar-nav"><li class="dropdown">')
        output('<a class="dropdown-toggle" data-toggle="dropdown" href="#">VPN')
        output('<span class="caret"></span></a>')
        output('<ul class="dropdown-menu">')



        


        
        for key, vpn in self.vpns:
            if vpn['name']:
                anchor = vpn['name'].lower().replace(' ', '_')
                output('<li><a href="#{0!s}">{1!s}</a></li>'.format(anchor, vpn['name']))
        output('</ul></li>')

        if self.maps:
            output('<li><a href="#map_canvas">Map View</a></li>')


        if REQUIRE_LOGIN:
            from keycloak import KeycloakOpenID
            import keycloak
            # if session_key defined
            # display user + logout
            # else display login
            keycloak_conf = json.loads(open('keycloak.json').read())
            global userid
            keycloak_openid = KeycloakOpenID(server_url=keycloak_conf['auth-server-url'] + "/", realm_name=keycloak_conf['realm'],client_id=keycloak_conf['resource'],client_secret_key=keycloak_conf['credentials']['secret'])
            #config_well_know = keycloak_openid.well_know()
            #print(config_well_know)
            #print(sys.argv)
            arguments = cgi.FieldStorage()
            if ('code' in arguments):
                code = arguments.getvalue('code')
                #print(code)
                #print('-----------------------------------------------')
                token = keycloak_openid.token(grant_type="authorization_code", code=code, redirect_uri="http://mech2018.fsv.cvut.cz/mupif/openvpn-monitor2/monitor.py")
                #token = keycloak_openid.token(grant_type="authorization_code", code=code, redirect_uri="http://172.30.0.1/mupif/openvpn-monitor2/monitor.py")
                userinfo = keycloak_openid.userinfo(token['access_token'])
                userid = userinfo['preferred_username']
                #print(userid)
            else:
                login_url = keycloak_openid.auth_url("http://mech2018.fsv.cvut.cz/mupif/openvpn-monitor2/monitor.py")
                #login_url = keycloak_openid.auth_url("http://172.30.0.1/mupif/openvpn-monitor2/monitor.py")
                #print ('<br> Welcome Anonymous !')
                #print ('<a href="'+login_url+'"> Login here </a>')
                #print ('<br>')
                
                #userinfo = keycloak_openid.userinfo(token['access_token'])




            
            #try:
            #    token = keycloak_openid.token('user', 'password')
            #except keycloak.exceptions.KeycloakAuthenticationError:
            #    userid = ''
            #token = keycloak_openid.token("user", "password", totp="012345")
            #token = keycloak_openid.token(grant_type="authorization_code", code=code)

    #        if 'code' in request.query.keys():
    #            code = request.query['code']
                # Get WellKnow

            # Get Token
            #token = keycloak_openid.token("user", "password")
            # Get Userinfo
            


            
            if (userid):
                output('<li><a>Logged in as '+userid+' | Logout</a></li>')
            else:
                print ('<li><a href="'+login_url+'"> Login</a></li>')
                #output('<li><a href="login.py">Login</a></li>')


        output('</ul>')

        if self.logo:
            output('<a href="#" class="pull-right"><img alt="self.logo" ')
            output('style="max-height:46px; padding-top:3px;" ')
            output('src="{0!s}"></a>'.format(self.logo))


        output('</div></div></nav>')
        output('<div class="container-fluid">')

    @staticmethod
    def print_session_table_headers(vpn_mode, show_disconnect):
        server_headers = ['Username / Hostname', 'VPN IP',
                          'Remote IP', 'Location', 'Bytes In',
                          'Bytes Out', 'Connected Since', 'Last Ping', 'Time Online']
        if show_disconnect:
            server_headers.append('Action')

        client_headers = ['Tun-Tap-Read', 'Tun-Tap-Write', 'TCP-UDP-Read',
                          'TCP-UDP-Write', 'Auth-Read']

        if vpn_mode == 'Client':
            headers = client_headers
        elif vpn_mode == 'Server':
            headers = server_headers

        output('<input class="form-control" id="searchVpnTable" type="text" placeholder="Search..">')
        output('<table id="vpnSessions" class="table table-striped table-bordered tablesorter')
        output('table-hover table-condensed table-responsive ')
        output('tablesorter tablesorter-bootstrap">')
        output('<thead><tr>')
        for header in headers:
            output('<th>{0!s}</th>'.format(header))
        output('</tr></thead><tbody>')

    @staticmethod
    def print_session_table_footer():
        output('</tbody></table>')

    @staticmethod
    def print_unavailable_vpn(vpn):
        anchor = vpn['name'].lower().replace(' ', '_')
        output('<div class="panel panel-danger" id="{0!s}">'.format(anchor))
        output('<div class="panel-heading">')
        output('<h3 class="panel-title">{0!s}</h3></div>'.format(vpn['name']))
        output('<div class="panel-body">')
        output('Could not connect to ')
        output('{0!s}:{1!s} ({2!s})</div></div>'.format(vpn['host'],
                                                        vpn['port'],
                                                        vpn['error']))

    def print_vpn(self, vpn_id, vpn):


        if vpn['state']['success'] == 'SUCCESS':
            pingable = 'Yes'
        else:
            pingable = 'No'

        connection = vpn['state']['connected']
        nclients = vpn['stats']['nclients']
        bytesin = vpn['stats']['bytesin']
        bytesout = vpn['stats']['bytesout']
        vpn_mode = vpn['state']['mode']
        vpn_sessions = vpn['sessions']
        local_ip = vpn['state']['local_ip']
        remote_ip = vpn['state']['remote_ip']
        up_since = vpn['state']['up_since']
        show_disconnect = vpn['show_disconnect']


        anchor = vpn['name'].lower().replace(' ', '_')
        #output('<div class="panel panel-success" id="{0!s}">'.format(anchor))


        output('<div class="panel panel-info">')
        output('      <div data-toggle="collapse" class="panel-heading text-center"  data-target="#VPNStatusPanel" class="panel-heading collapsed" >')
        output('          <div class="panel-title">%s</div>'%vpn_id)
        output('     </div>')        
        output('     <div id="VPNStatusPanel" class="panel-collapse collapse">')

          
        output('<table id = "vpnTable" class="table table-condensed table-responsive">')
        output('<thead><tr><th id="mode">VPN Mode</th><th mode = "status">Status</th><th>Pingable</th>')
        output('<th>Clients</th><th>Total Bytes In</th><th>Total Bytes Out</th>')
        output('<th>Up Since</th><th>Local IP Address</th>')
        if vpn_mode == 'Client':
            output('<th>Remote IP Address</th>')
        output('</tr></thead><tbody>')
        output('<tr><td>{0!s}</td>'.format(vpn_mode))
        output('<td>{0!s}</td>'.format(connection))
        output('<td>{0!s}</td>'.format(pingable))
        output('<td>{0!s}</td>'.format(nclients))
        output('<td>{0!s} ({1!s})</td>'.format(bytesin, naturalsize(bytesin, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(bytesout, naturalsize(bytesout, binary=True)))
        output('<td>{0!s}</td>'.format(up_since.strftime(self.datetime_format)))
        output('<td>{0!s}</td>'.format(local_ip))

        if vpn_mode == 'Client':
            output('<td>{0!s}</td>'.format(remote_ip))
        output('</tr></tbody></table>')

        if vpn_mode == 'Client' or nclients > 0:
            self.print_session_table_headers(vpn_mode, show_disconnect)
            self.print_session_table(vpn_id, vpn_mode, vpn_sessions, show_disconnect)
            self.print_session_table_footer()

        output('<span class="label label-default">{0!s}</span>'.format(vpn['version']))
        output('</div></div>')



#        output('<div class="panel panel-default">')
#        output('<div data-toggle="collapse" data-target="#panel2" class="panel-heading collapsed">')
#        output('<h4 class="panel-title">')
#        output('<a> Panel 2 </a>')
#        output('</h4>')
#        output('</div>')
#        output('<div id="panel2" class="panel-collapse collapse">')
#        output('<div class="panel-body">')
#        output('</div>')
#        output('</div>')
#        output('</div>')




    @staticmethod
    def print_mupif_status(mupif_monitor):
        #print (str(mupif_monitor.cfg))
        ns_ip = mupif_monitor.cfg['nameserver_ip']
        ns_port = mupif_monitor.cfg['nameserver_port']
        ns_status = mupif_monitor.cfg['ns_status']
        ns_note = mupif_monitor.cfg['error']

        mupifdb_ip = mupif_monitor.cfg['mupifdb_ip']
        mupifdb_port = '' # mupif_monitor.cfg['mupifdb_port']
        mupifdb_status = mupif_monitor.cfg['mupifdb_status'].get('mupifDBStatus', "Failed")
        mupifdbscheduler_status = mupif_monitor.cfg['mupifdb_status'].get('schedulerStatus', "Failed")
        
        
        

        userGroup = 'None'
        if REQUIRE_LOGIN:
            json_file = open('userGroup_2_userID.json', 'r')
            json_str = json_file.read()
            userGroup_2_userID = json.loads(json_str)[0]
            for key in userGroup_2_userID:
                userID = key
                if userID == userid:
                     userGroup = userGroup_2_userID.get(userID)
            print(userGroup)

            


        output('<div class="panel panel-info">')
        output('      <div data-toggle="collapse" class="panel-heading text-center"  data-target="#MupifStatusPanel" class="panel-heading collapsed" >')
#        output('          <button class="glyphicon glyphicon-plus-sign pull-left" data-toggle="collapse" data-target="#MupifStatusPanel"></button>')
        output('          <div class="panel-title">MuPIF Status</div>')
        output('     </div>')
        output('     <div id="MupifStatusPanel" class="panel-collapse collapse">')
        
        output('      <p>')
        ##### small nameserver table
        output('      <table id="Mupif-Components" class="table table-stripped table-bordered">')
        output('           <thead><tr><th>Component</th><th>IP</th><th>port</th><th>Status</th><th>Note</th></tr></thead>')
        output('           <tbody>')
        if (ns_status == "OK"):
            trclass = "success"
        else:
            trclass = "danger"
        output('               <tr"><td>Nameserver</td><td>{0!s}</td><td>{1!s}</td><td class="{4!s}">{2!s}</td><td>{3!s}</td></tr>'.format(ns_ip, ns_port, ns_status, ns_note, trclass))
        if (mupifdb_status == "OK"):
            trclass = "success"
        else:
            trclass = "danger"
                               
        output('               <tr"><td>MupifDB</td><td>{0!s}</td><td>{1!s}</td><td class="{4!s}">{2!s}</td><td>{3!s}</td></tr>'.format(mupifdb_ip, mupifdb_port, mupifdb_status, "", trclass))

        if (mupifdbscheduler_status == "OK"):
            trclass = "success"
        else:
            trclass = "danger"
        output('               <tr"><td>MupifDB Scheduler</td><td>{0!s}</td><td>{1!s}</td><td class="{4!s}">{2!s}</td><td>{3!s}</td></tr>'.format("", "", mupifdbscheduler_status, str(mupif_monitor.cfg['mupifdb_status'].get('mupifDBSchedulerStatus', "")), trclass))
                        
        
        output('               </tr>')
        output('           </tbody>')
        output('      </table>')
        output('      </p>')


        ### table for job managers
        output('<input class="form-control" id="searchJobManTable" type="text" placeholder="Search..">')
        output('      <table id="jobManSessions" class="table table-striped table-bordered tablesorter')
        output('       table-hover table-condensed table-responsive ')
        output('       tablesorter tablesorter-bootstrap">')
        output('         <thead>')
        output('             <tr><th></th><th id ="id">JobManager ID</th><th>Signature</th><th>URI</th><th>Running jobs</th><th>Status</th><th></th></tr>')
        output('         </thead>')
        output('         <tbody>')
        index = 0
        for name, jobman in mupif_monitor.jobmans.items():
            if (jobman['status'] == "OK"):
                trclass = "success"
            else:
                trclass = "warning"
                #@todo: check the rights for each job man and show the delte button if appropriate
            #print(jobman['note'])
            #print(jobman['numberofrunningjobs'])
            if(jobman['status'] == "OK" and jobman['numberofrunningjobs'] > 0):
                index = index+1
                if(userGroup == name or userGroup == 'CTU' ):
                    output('     <tr class = "tablesorter"> <td> <button id="button" type="button" class="btn btn-primary" data-toggle="collapse" data-target="#collapseme_{6!s}"><span class="glyphicon glyphicon-plus"></button></td><td>{0!s}</td><td>{1!s}</td><td>{2!s}</td><td>{3!s}</td><td class="{5!s}">{4!s}</td><td><a class = "button" href="delete_jm.py?jobManName={0!s}"><span class="glyphicon glyphicon-trash"></span></a></td></tr>'.format(name, jobman['note'], jobman['uri'], jobman['numberofrunningjobs'], jobman['status'], trclass, index))
                else:
                    output('     <tr class = "tablesorter"> <td> <button id="button" type="button" class="btn btn-primary" data-toggle="collapse" data-target="#collapseme_{6!s}"><span class="glyphicon glyphicon-plus"></button></td><td>{0!s}</td><td>{1!s}</td><td>{2!s}</td><td>{3!s}</td><td class="{5!s}">{4!s}</td></tr>'.format(name, jobman['note'], jobman['uri'], jobman['numberofrunningjobs'], jobman['status'], trclass, index))

                jobMan = mp.pyroutil.connectJobManager(mupif_monitor.ns, name, 'mupif-secret-key')
                ##jobMan.terminateJob('27@Abaqus@Mupif.LIST')

                output('<tr class= "tablesorter-childRow">')
                output('      <td></td>')
                output('      <td colspan = "6" align = "center">')
                #output('<td><div class="collapse out" id="collapseme_{0!s}">Should be collapsed</div></td></tr>'.format(index))
                output('<div class="collapse out" id="collapseme_{0!s}">'.format(index))
                #####
                output('        <table id = "JobTable{0!s}" class="table table-borderless">'.format(index))
                output('<thead><tr><th>Job ID</th><th>Port</th><th>User@host</th><th>Running time</th></thead>')

                status = jobMan.getStatus()
                for rec in status:

                    jobid = rec[0]
                    #print(jobid)
                    port = (rec[3])
                    user = rec[2]
                    mins = rec[1]//60
                    hrs  = mins//24
                    mins = mins%60
                    sec  = int(rec[1])%60
                    jobtime = "%02d:%02d:%02d"%(hrs, mins, sec)
                    if(userGroup == name or userGroup == "CTU" ):
                        output('<tr><td>{0!s}</td><td>{1!s}</td><td>{2!s}</td><td>{3!s}</td></td><td><a class = "button" href="deleteJM.py?jobManName={4!s}&jobName={0!s}"><span class="glyphicon glyphicon-trash"></span></a></td></tr>'.format(jobid, -1, user, jobtime, name))

                    else:
                        output('<tr><td>{0!s}</td><td>{1!s}</td><td>{2!s}</td><td>{3!s}</td></td></tr>'.format(jobid, -1, user, jobtime, name, trclass))

                output('</table>')
                output(' </div></tr>')

            ### There are no jobs
            else:
                if(userGroup == name or userGroup == "CTU"):
                    output('<tr><td></td><td>{0!s}</td><td>{1!s}</td><td>{2!s}</td><td>{3!s}</td><td class="{5!s}">{4!s}</td><td><a class = "button" href="delete_jm.py?jobManName={0!s}"><span class="glyphicon glyphicon-trash"></span></a></td></tr>'.format(name, jobman['note'], jobman['uri'], jobman['numberofrunningjobs'], jobman['status'], trclass))
                else:
                    output('<tr><td></td><td>{0!s}</td><td>{1!s}</td><td>{2!s}</td><td>{3!s}</td><td class="{5!s}">{4!s}</td></tr>'.format(name, jobman['note'], jobman['uri'], jobman['numberofrunningjobs'], jobman['status'], trclass))

                    
        output('</tbody></table>')



        output('</div></div>')


        

       #output('<div>')
       # output('<a class="btn btn-primary" data-toggle="collapse" href="#multiCollapseExample1" role="button" aria-expanded="false"')
       # output('aria-controls="multiCollapseExample1">Toggle first element</a>')
       # output('<button class="btn btn-primary" type="button" data-toggle="collapse" data-target="#multiCollapseExample2"')
       # output('aria-expanded="false" aria-controls="multiCollapseExample2">Toggle second element</button>')
       # output('<button class="btn btn-primary" type="button" data-toggle="collapse" data-target=".multi-collapse"')
       # output('aria-expanded="false" aria-controls="multiCollapseExample1 multiCollapseExample2">Toggle both elements</button>')
       # output('</div>')
       # output('<!--/ Collapse buttons -->')
       # output('<!-- Collapsible content -->')
       # output('<div class="row">')
       # output('<div class="col">')
       # output('<div class="collapse multi-collapse" id="multiCollapseExample1">')
       # output('<div class="card card-body">')
       # output('Anim pariatur cliche reprehenderit, enim eiusmod high life accusamus terry richardson ad squid. Nihil')
       # output('anim keffiyeh helvetica, craft beer labore wes anderson cred nesciunt sapiente ea proident.')
       # output('</div>')
       # output('</div>')
       # output('</div>')
       # output('<div class="col">')
       # output('<div class="collapse multi-collapse" id="multiCollapseExample2">')
       # output('<div class="card card-body">')
       # output('Anim pariatur cliche reprehenderit, enim eiusmod high life accusamus terry richardson ad squid. Nihil')
       # output('anim keffiyeh helvetica, craft beer labore wes anderson cred nesciunt sapiente ea proident.')
       # output('</div>')
       # output('</div>')
       # output('</div>')
       # output('</div>')
       # output('<!--/ Collapsible content -->')






        

    @staticmethod
    def print_client_session(session):
        tuntap_r = session['tuntap_read']
        tuntap_w = session['tuntap_write']
        tcpudp_r = session['tcpudp_read']
        tcpudp_w = session['tcpudp_write']
        auth_r = session['auth_read']
        output('<td>{0!s} ({1!s})</td>'.format(tuntap_r, naturalsize(tuntap_r, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(tuntap_w, naturalsize(tuntap_w, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(tcpudp_r, naturalsize(tcpudp_w, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(tcpudp_w, naturalsize(tcpudp_w, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(auth_r, naturalsize(auth_r, binary=True)))

    def print_server_session(self, vpn_id, session, show_disconnect):
        total_time = str(datetime.now() - session['connected_since'])[:-7]
        bytes_recv = session['bytes_recv']
        bytes_sent = session['bytes_sent']
        output('<td>{0!s}</td>'.format(session['username']))
        output('<td>{0!s}</td>'.format(session['local_ip']))
        output('<td>{0!s}</td>'.format(session['remote_ip']))

        if 'location' in session:
            if session['location'] == 'RFC1918':
                output('<td>RFC1918</td>')
            else:
                flag = '{0!s}flags/{1!s}.png'.format(image_path, session['location'].lower())
                if 'city' in session and 'country_name' in session:
                    country = session['country_name']
                    city = session['city']
                    if city:
                        full_location = '{0!s}, {1!s}'.format(city, country)
                    else:
                        full_location = country
                output('<td><img src="{0!s}" title="{1!s}" alt="{1!s}" /> '.format(flag, full_location))
                output('{0!s}</td>'.format(full_location))
        else:
            output('<td>Unknown</td>')

        output('<td>{0!s} ({1!s})</td>'.format(bytes_recv, naturalsize(bytes_recv, binary=True)))
        output('<td>{0!s} ({1!s})</td>'.format(bytes_sent, naturalsize(bytes_sent, binary=True)))
        output('<td>{0!s}</td>'.format(
            session['connected_since'].strftime(self.datetime_format)))
        if 'last_seen' in session:
            output('<td>{0!s}</td>'.format(
                session['last_seen'].strftime(self.datetime_format)))
        else:
            output('<td>ERROR</td>')
        output('<td>{0!s}</td>'.format(total_time))
        if show_disconnect:
            output('<td><form method="post">')
            output('<input type="hidden" name="vpn_id" value="{0!s}">'.format(vpn_id))
            if 'port' in session:
                output('<input type="hidden" name="ip" value="{0!s}">'.format(session['remote_ip']))
                output('<input type="hidden" name="port" value="{0!s}">'.format(session['port']))
            if 'client_id' in session:
                output('<input type="hidden" name="client_id" value="{0!s}">'.format(session['client_id']))
            output('<button type="submit" class="btn btn-xs btn-danger">')
            output('<span class="glyphicon glyphicon-remove"></span> ')
            output('Disconnect</button></form></td>')

    def print_session_table(self, vpn_id, vpn_mode, sessions, show_disconnect):
        for key, session in list(sessions.items()):
            output('<tr>')
            if vpn_mode == 'Client':
                self.print_client_session(session)
            elif vpn_mode == 'Server':
                self.print_server_session(vpn_id, session, show_disconnect)
            output('</tr>')

    def print_maps_htmlNew(self):
        #output('<div class="panel panel-info"><div class="panel-heading">')

        output('<div class="panel panel-info">')
        output('      <div data-toggle="collapse" class="panel-heading text-center"  data-target="#MapStatusPanel" class="panel-heading collapsed" >')
#        output('          <button class="glyphicon glyphicon-plus-sign pull-left" data-toggle="collapse" data-target="#MapStatusPanel"></button>')
        output('          <div class="panel-title">Map View</div>')
        output('     </div>')        
        output('<div id ="MapStatusPanel" class="panel-collapse collapse">')
        output('<div id="map_canvas" style="height:500px"></div>')
        output('<script type="text/javascript">')
        output('var map = L.map("map_canvas");')
        output('var centre = L.latLng({0!s}, {1!s});'.format(self.latitude, self.longitude))
        output('map.setView(centre, 8);')
        output('url = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";')
        output('var layer = new L.TileLayer(url, {});')
        output('map.addLayer(layer);')
        output('var bounds = L.latLngBounds(centre);')
        for vkey, vpn in self.vpns:
            if 'sessions' in vpn:
                output('bounds.extend(centre);')
                for skey, session in list(vpn['sessions'].items()):
                    if 'longitude' in session and 'latitude' in session:
                        output('var latlng = new L.latLng({0!s}, {1!s});'.format(
                            session['latitude'], session['longitude']))
                        output('bounds.extend(latlng);')
                        output('var marker = L.marker(latlng).addTo(map);')
                        output('var popup = L.popup().setLatLng(latlng);')
                        output('popup.popupOpen = true;')
                        output('popup.setContent("{0!s} - {1!s}");'.format(
                            session['username'], session['remote_ip']))
                        output('marker.bindPopup(popup);')
        output('map.fitBounds(bounds);')
        output('</script>')
        output('</div>')
        output('</div>')


    def print_maps_html(self, mupif_monitor):
        output('<div class="panel panel-info">')
        output('      <div data-toggle="collapse" class="panel-heading text-center"  data-target="#MapStatusPanel" class="panel-heading collapsed" >')

        output('<h3 class="panel-title">Map View</h3></div>')
        output('<div class="panel-collapse" div id ="MapStatusPanel">')
        #output('<div id ="MapStatusPanel" class="panel-collapse collapse">')
        output('<div id="map_canvas" style="height:500px"></div>')
        output('<script type="text/javascript">')

        output('var map = L.map("map_canvas");')

        output('var centre = L.latLng({0!s}, {1!s});'.format(self.latitude, self.longitude))
        output('map.setView(centre, 8);')
        output('url = "https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png";')
        output('var layer = new L.TileLayer(url, {});')
        ## icons
        output('var IconType = L.Icon.extend({')
        output('        options: {')
        output('            iconSize:     [38, 95],')
        output('            iconAnchor:   [22, 94],')
        output('            popupAnchor:  [-3, -76]')
        output('        }')
        output('});')

        output('var huhu = new IconType({iconUrl: \'images/logos/template.png\'});')
        ## end of icons
        output('map.addLayer(layer);')
        output('var bounds = L.latLngBounds(centre);')


        ## finish this part
        ip2nRunningJobs = {}
        for vkey, vpn in self.vpns:
            if 'sessions' in vpn:
                output('bounds.extend(centre);')
                for skey, session in list(vpn['sessions'].items()):
                    nRunningJobs = 0
                    ip = session.get('local_ip')
                    for name, jobman in mupif_monitor.jobmans.items():
                        #if( str(ip) in jobman['uri']):
                        if( jobman['uri'].find(str(ip)) > 0 ):
                            if ip in ip2nRunningJobs:
                                ip2nRunningJobs[ip] += jobman['numberofrunningjobs']
                            else:
                                ip2nRunningJobs[ip] = jobman['numberofrunningjobs']
                            break


            
            if 'sessions' in vpn:
                output('bounds.extend(centre);')
                for skey, session in list(vpn['sessions'].items()):
                    nRunningJobs = 0
                    ip = session.get('local_ip')
                    for name, jobman in mupif_monitor.jobmans.items():
                        #if( str(ip) in jobman['uri']):
                        if( jobman['uri'].find(str(ip)) > 0 ):
                            nRunningJobs = jobman['numberofrunningjobs']
                            break

                    if 'longitude' in session and 'latitude' in session:
                        output('var latlng = new L.latLng({0!s}, {1!s});'.format(
                            session['latitude'], session['longitude']))
                        output('bounds.extend(latlng);')
                        #output('var marker = L.marker(latlng,{icon:huhu}).addTo(map);')
                        output('var marker = L.marker(latlng).addTo(map);')
                        output('var popup = L.popup().setLatLng(latlng);')
                        #output('popup.setContent("{0!s} - {1!s}");'.format(
                        #    session['username'], session['remote_ip']))
                        nRunningJobs = ip2nRunningJobs.get(ip, 0)
                        output('popup.setContent("{0!s}: {1!s} running jobs");'.format(session['username'], nRunningJobs))
                        output('marker.bindPopup(popup, {autoClose: false});')
                        output('marker.openPopup();')
         
        output('map.fitBounds(bounds);')
        output('</script>')
        output('</div></div>')

        
    def print_html_footer(self):
        output('<div class="well well-sm">')
        output('Page automatically reloads every 5 minutes.')
        output('Last update: <b>{0!s}</b></div>'.format(
            datetime.now().strftime(self.datetime_format)))
        output('</div></body></html>')


def main(**kwargs):
    cfg = ConfigLoader(args.config)
    mupifcfg=MupifConfigLoader(args.mupifconfig);

    vpn_type=cfg.settings.get('vpn_type','openvpn')
    if vpn_type=='openvpn': monitor=OpenvpnMgmtInterface(cfg, **kwargs)
    elif vpn_type=='wireguard': monitor=WireguardMgmtInterface(cfg,**kwargs)
    else: raise RuntimeError('Unrecognized vpn_type "{vpn_type}" (must be one of: openvpn, wireguard).')

    mupifMon = mupifMonitor(mupifcfg)
    
    #parse user info
    cgiargs = cgi.FieldStorage()
    if REQUIRE_LOGIN:
        global userid
        if ("session_key" in cgiargs):
            userid=login.fetch_username(cgiargs["session_key"])

    
    OpenvpnHtmlPrinter(cfg, monitor, mupifMon)
    
    if args.debug:
        pretty_vpns = pformat((dict(monitor.vpns)))
        debug("=== begin vpns\n{0!s}\n=== end vpns".format(pretty_vpns))

def display_page():
    print ("<title>You are going to be redirected</title>")
    print ("</HEAD>\n")
    print ("<BODY BGCOLOR = white>\n")
    print ("Succesfully authorized, show MuPIF status is")
    print ("</BODY>\n")
    print ("</HTML>\n")

        
def get_args():
    parser = argparse.ArgumentParser(
        description='Display a html page with openvpn status and connections')
    parser.add_argument('-d', '--debug', action='store_true',
                        required=False, default=False,
                        help='Run in debug mode')
    parser.add_argument('-c', '--config', type=str,
                        required=False, default='./openvpn-monitor.conf',
                        help='Path to config file openvpn-monitor.conf')
    parser.add_argument('-m', '--mupifconfig', type=str,
                        required=False, default='./mupif-monitor.conf',
                        help='Path to config file mupif-monitor.conf')
    parser.add_argument('--dump-only',action='store_true',default=False,help='Only dump current data and exit')
    return parser.parse_args()

# print(__name__)
if __name__ == '__main__':
    args = get_args()
    if args.dump_only:
        from collections import namedtuple
        cfg=namedtuple('Cfg',('vpns','settings'))(vpns={'musicode':{}},settings={'geoip_data':'./data/GeoLiteCity.dat'})
        WireguardMgmtInterface(cfg=cfg)
        import pprint
        pprint.pprint(cfg.vpns)
        sys.exit(0)
    wsgi = False
    image_path = 'images/'
    main()
else:
    class args(object):
        debug = False
        config = './openvpn-monitor.conf'
        mupifconfig='./mupif-monitor.conf'

    wsgi = True
    wsgi_output = ''
    image_path = ''

    owd = os.getcwd()
    os.chdir(os.path.dirname(__file__))
    sys.path.append(os.path.dirname(__file__))
    if owd != os.getcwd() and sys.prefix != '/usr':
        # virtualenv
        images_dir = owd + '/share/openvpn-monitor/images/'
    else:
        images_dir = 'images'

    application = default_app()

    @get('/')
    def get_slash():
        return render()

    @post('/')
    def post_slash():
        vpn_id = request.forms.get('vpn_id')
        ip = request.forms.get('ip')
        port = request.forms.get('port')
        client_id = request.forms.get('client_id')
        return render(vpn_id=vpn_id, ip=ip, port=port, client_id=client_id)

    def render(**kwargs):
        global wsgi_output
        wsgi_output = ''
        main(**kwargs)
        response.content_type = 'text/html;'
        return wsgi_output

    @get('/<filename:re:.*\.(jpg|png)>')
    def images(filename):
        return static_file(filename, root=images_dir)
