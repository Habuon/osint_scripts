import os
from subprocess import PIPE, STDOUT, Popen


def reverse_resolve(ips: list) -> dict:
	result = dict()
	for ip in ips:
		command = f"dig +short -x {ip}"
		with Popen(command, stdout=PIPE, stderr=STDOUT, shell=True) as process:
		    output = process.communicate()[0].decode("utf-8").strip().split("\n")
		result[ip] = [x.rstrip(".") for x in output] 
	return result


def resolve_ips(domains: list) -> dict:
	servers = dict()
	for domain in domains:
		command = f"dig +short a {domain}"
		with Popen(command, stdout=PIPE, stderr=STDOUT, shell=True) as process:
			output = process.communicate()[0].decode("utf-8").strip().split("\n")
		output = output[-1]
		if len(output) == 0:
			continue
		servers[output] = servers.get(output, []) + [domain]
	return servers
	
	
def main():
	additional_ips = ["65.21.124.52", "5.178.48.39", "212.5.207.122", "195.80.166.170"]
	domains = []
	with open("domains", "r") as f:
		for line in f:
			line=line.strip()
			if len(line) == 0:
				continue
			domains.append(line)
	
	servers = resolve_ips(domains)
	
	all_ips = list(servers.keys()) + additional_ips

	reverse = reverse_resolve(all_ips)

	result = {ip: set([x for x in servers.get(ip, []) + reverse.get(ip, []) if len(x) != 0]) for ip in all_ips}
	for key, value in result.items():
		print(key, "\t", value)
	
	with open("ips", "w") as f:
		for k in servers.keys():
			print(k, file=f)
			
		


if __name__ == "__main__":
	main()
