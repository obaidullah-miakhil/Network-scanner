import socket
import ipaddress
from flask import Flask, render_template, request, redirect, url_for
app = Flask(__name__)

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send(b'ViolentPython\r\n')
        results = connSkt.recv(100)
        connSkt.close()
        return (tgtPort, True, results)
    except:
        return (tgtPort, False, None)

def portScan(tgtHost, tgtPorts):
    results = []
    try:
        tgtIP = socket.gethostbyname(tgtHost)
    except:
        return None, "Cannot resolve '%s': Unknown host" % tgtHost
    
    try:
        tgtName = socket.gethostbyaddr(tgtIP)
        scanResults = f"Scan Results for: {tgtName[0]}"
    except:
        scanResults = f"Scan Results for: {tgtIP}"
    
    socket.setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        scanResults += f"\nScanning port {tgtPort}"
        port, status, response = connScan(tgtHost, int(tgtPort))
        if status:
            scanResults += f"\n[+] {port}/tcp open"
            scanResults += f"\n[+] {str(response)}"
        else:
            scanResults += f"\n[-] {port}/tcp closed"
    return scanResults, None

def subnetScan(subnet):
    results = []
    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except ValueError as e:
        return None, f"Invalid subnet: {e}"
    
    results.append(f"Scanning Subnets for: {network}")
    host_list = list(network.hosts())[:10]
    for host in host_list:
        host_ip = str(host)
        results.append(f"Scanning Host: {host_ip}")
        scanResult, error = portScan(host_ip, ['80', '443'])
        if error:
            results.append(error)
        else:
            results.append(scanResult)
    return '\n'.join(results), None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    scan_type = request.form['scan_type']
    if scan_type == 'host':
        tgtHost = request.form['tgtHost']
        tgtPorts = request.form['tgtPorts'].split(',')
        results, error = portScan(tgtHost, tgtPorts)
    elif scan_type == 'subnet':
        subnet = request.form['subnet']
        results, error = subnetScan(subnet)
    
    if error:
        return render_template('results.html', results=error)
    else:
        return render_template('results.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
