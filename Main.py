import nmap

import re

import ipaddress

nm = nmap.PortScanner()

#Checks if string is in IPv4 format
ip_add_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

port_min = 0
port_max = 65535

open_ports = []
results = []

while True:
    ip_add_entered = input("\nPlease enter the ip address that you want to scan: ")
    try:
        ipaddress.ip_address(ip_add_entered)
        break
    except ValueError:
        print("Invalid IP address.")

while True:
    print("Please enter the range of ports you want to scan in format: <int>-<int> (ex would be 60-120)")
    port_range = input("Enter port range: ")
    port_range_valid = port_range_pattern.search(port_range.replace(" ",""))
    if port_range_valid:
        port_min = int(port_range_valid.group(1))
        port_max = int(port_range_valid.group(2))
        break

print("\nChecking host status...")
try:
    nm.scan(hosts=ip_add_entered, arguments="-sn")
    host_status = nm[ip_add_entered].state()
    print(f"Host {ip_add_entered} is {host_status.upper()}")
except nmap.NmapError:
    print("\nHost status not found.")


port_range_str = f"{port_min}-{port_max}"
nm.scan(ip_add_entered, ports=port_range_str, arguments="-sT")  # TCP connect scan


for port in range(port_min, port_max + 1):
    try:
        port_status = nm[ip_add_entered]['tcp'][port]['state']
        results.append(f"{port},{port_status}\n")
    except KeyError:
        results.append(f"{port},filtered/unreachable\n")

#CSV File
csv_file = f"{ip_add_entered}.csv"
with open(csv_file, "w") as f:
    f.writelines(results)

#Human Readable File
txt_file = f"{ip_add_entered}--{port_min}-{port_max}.txt"
with open(txt_file, "w") as f:
    f.write(f"Scan results for {ip_add_entered} ({port_min}-{port_max})\n")
    f.write("="*40 + "\n")
    f.write(f"Host {ip_add_entered}\n")
    f.write(f"Network Status: {host_status.upper()}\n\n")

    if open_ports:
        f.write(f"Open Ports: {', '.join(map(str, open_ports))}\n\n")
    else:
        f.write("No open ports found.\n\n")
    for line in results:
        port, state = line.strip().split(",")
        f.write(f"Port {port}: {state}\n")