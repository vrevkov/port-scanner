#!/usr/bin/env python3
import socket
import yaml
import json
import threading
from flask import Flask, Response
from apscheduler.schedulers.background import BackgroundScheduler
from prometheus_client import Gauge, generate_latest


APP_NAME = 'port-scanner'
CONFIG_PATH = 'config.yaml'
RESULT_PATH = 'result.json'
TIMEOUT = 2
app = Flask(__name__)
sched = BackgroundScheduler(daemon=True)
port_scan_status = Gauge('port_scan_status', 'Status of given port',
          ['hostname', 'ip', 'port'])


def load_config(path):
    ''' Get spec from config file, lookup hostnames and return list of lists
    with hostname, ip, port values
    {'yandex.ru': ['80', '443']} = 
    [
        ['yandex.ru', '77.88.55.80', '80'], 
        ['yandex.ru', '77.88.55.88', '80'],
        ['yandex.ru', '77.88.55.80', '443'], 
        ['yandex.ru', '77.88.55.88', '443'],
        ...
    ]
    '''
    result = []
    with open(path) as file:
        spec = yaml.load(file, Loader=yaml.FullLoader)
    for hostname, ports in spec.items():
        ips = socket.gethostbyname_ex(hostname)[2]
        for ip in ips:
            for port in ports:
                result.append([hostname, ip, port])
    return result


def port_scan(host_port, timeout=TIMEOUT, result=[]):
    ''' Get host_port as list [hostname, ip, port], scan ip:port, 
    append scan result to this list: [hostname, ip, port, status] and than
    append it to common result list
    '''
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    if sock.connect_ex((host_port[1], host_port[2])) == 0:
        host_port.append(1)
        result.append(host_port)
    else:
        host_port.append(0)
        result.append(host_port)
    sock.close()


def parallel_scan():
    ''' Run port_scan in parallel mode, save result in common list
    than return this list
    '''
    result = []
    spec = load_config(CONFIG_PATH)
    threads = [threading.Thread(target=port_scan, kwargs={'host_port': i,
                                'result': result}) for i in spec]
    [t.start() for t in threads]
    [t.join() for t in threads]
    return result


def save_scan_result():
    ''' Get scan result and save it to RESULT_PATH file in pretty format
        {
            "hostname": {
                "ip1" {
                    "port1": "status",
                    "port2": "status"
                },
                "ip2" {
                    "port1": "status",
                    "port2": "status"
                }
            }
        }
    '''
    pretty_json = {}
    scan_result = parallel_scan()
    for x in scan_result:
        hostname, ip, port, status = x
        if hostname not in pretty_json.keys():
            pretty_json[hostname] = {}
        if ip not in pretty_json[hostname].keys():
            pretty_json[hostname][ip] = {}
        if status == 1:
            pretty_json[hostname][ip][port] = 'open'
        else:
            pretty_json[hostname][ip][port] = 'closed'
    with open(RESULT_PATH, 'w') as file:
        file.write(json.dumps(pretty_json, indent=4))
    update_prometheus_metrics()


def update_prometheus_metrics():
    ''' Update prometheus metrics from RESULT_PATH
    '''
    with open(RESULT_PATH, 'r') as file:
        result = json.load(file)
    port_scan_status._metrics.clear()
    for hostname, ips in result.items():
        for ip, ports in ips.items():
            for port, status in ports.items():
                if status == 'open':
                    port_scan_status.labels(hostname, ip, port).set(1)
                else:
                    port_scan_status.labels(hostname, ip, port).set(0)

    
@app.route(f'/{APP_NAME}/scan')
def read_result():
    ''' Get result from RESULT_PATH file
    '''
    with open(RESULT_PATH, 'r') as file:
        return json.load(file)


@app.route(f'/{APP_NAME}/metrics')
def metrics():
    ''' Get prometheus metrics
    '''
    return Response(generate_latest(), mimetype=str('text/plain; charset=utf-8'))


@app.route('/health')
def health():
    ''' Get app health
    '''
    return {'status': 'up'}


def main():
    update_prometheus_metrics()
    sched.add_job(save_scan_result, 'cron', minute='*')
    sched.start()
    app.run()


if __name__ == '__main__':
    main()
