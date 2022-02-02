<h1 align="center">
 Harp
 </h1>

  CLI based internal network discovery tool using passive and active ARP methods. **Harp** is designed to enumerate private IPv4 ranges with ARP by setting up an ARP listener for a determined time then slowly ARP scanning input ranges over the given time. CIDR input is reduced and randomized when scanning and time between requests is randomized. 

  Found hosts can optionally be searched for their FQDNs and aims to only lookup each host once. **Harp** can be ran as a listener or as a scanner and listener with the ability to run repeatedly. Input can be read from `-i` or from `stdin` and formats include: a CIDR, list of CIDRs or a list of IPs. Output is stored within a DataFrame and is automatically loaded from the output directory as a database between runs. 

  ## Getting Started

- [Usage](#usage)
- [Install](#install)
- [Output](#output)

## Usage

```
$ harp.py -h
usage: harp.py [-h] [-i INPUT] [-o OUTPUT] [-s] [-c CYCLES] [-w WAIT] [-q] [-l]

Network reconnaissance tool to discover hosts using ARP.

optional arguments:
  -h, --help            show this help message and exit
  -i INPUT, --input INPUT
                        Input list of IPs, list of CIDRs, or a CIDR range.
  -o OUTPUT, --output OUTPUT
                        Prints and loads CSV files to directory. The default is cwd.
  -s, --suppress        Only performs ARP scans and ignores fetching FQDN.
  -c CYCLES, --cycles CYCLES
                        Number of cycles to repeat.
  -w WAIT, --wait WAIT  Minutes keep the listener open and spread scans throughout (if enabled).
  -q, --quiet           Hides banner and only prints found IPs to CLI.
  -l, --listen          Skips all active scans and only starts the listener.
```

Input a CIDR range
```
harp.py -i 10.0.0.0/24

echo '10.0.0.0/24' | python3 harp.py
```

Input a file of IPs or CIDR ranges
```
harp.py -i hosts.txt

harp.py -i cidrs.txt

cat hosts.txt | python3 harp.py

cat cidrs.txt | python3 harp.py
```


Do ARP scan of range, passively listen for ARP requests while scanning, and fetch FQDN of found hosts
```
python3 harp.py -i 10.0.0.0/24
```
Do ARP scan of range, passively listen for ARP requests while scanning, but do not fetch FQDN of found hosts
```
python3 harp.py -i 10.0.0.0/24 -s
```
Do not do ARP scan but passively listen for ARP traffic and capture hosts for 30 minutes
```
python3 harp.py -l -w 30
```
Do ARP scan on input range while passively listening for ARP traffic aiming for 360 minutes of listening and spread the scans over 360 minutes then repeat 1 time.
```
harp.py -i 10.0.0.0/24 -w 360 -c 1
 ▄ .▄ ▄▄▄· ▄▄▄   ▄▄▄·
██▪▐█▐█ ▀█ ▀▄ █·▐█ ▄█
██▀▐█▄█▀▀█ ▐▀▀▄  ██▀·
██▌▐▀▐█ ▪▐▌▐█•█▌▐█▪·•
▀▀▀ · ▀  ▀ .▀  ▀.▀
Reducing input to /29 subnets...
Loaded output file with 1 records
[19:24:12] Starting Cycle 1/1
[19:24:12] Starting ARP Sniffing...
Starting ARP capture for ~360 minutes...
Reducing input to /29 subnets...
[19:24:12] Starting ARP scan...
Reduced input CIDRs to 32 subnets
Switching subnet scans every 675.0 seconds.
Time between packets will be 2.636719 seconds.
Captured 10.0.0.142 requesting 10.0.0.0
Captured 10.0.0.142 requesting 10.0.0.1
Captured 10.0.0.142 requesting 10.0.0.2
Captured 10.0.0.142 requesting 10.0.0.3
Captured 10.0.0.142 requesting 10.0.0.4
Captured f6:92:bf:5c:3a:7c responding 10.0.0.1
Captured 10.0.0.142 requesting 10.0.0.5
Captured 10.0.0.142 requesting 10.0.0.6
Captured 10.0.0.142 requesting 10.0.0.7
Captured b8:27:eb:55:d1:38 responding 10.0.0.5
Captured 98:8d:46:87:41:4a responding 10.0.0.4
Found 3 live hosts in 10.0.0.0/29
Captured 10.0.0.1 requesting 10.0.0.142
Captured a4:e4:64:dc:06:d4 responding 10.0.0.142
Captured 10.0.0.146 requesting 10.0.0.142
Captured a4:e4:64:dc:06:d4 responding 10.0.0.142
Captured 10.0.0.142 requesting 10.0.0.4
Captured 98:8d:46:87:41:4a responding 10.0.0.4
Captured 10.0.0.142 requesting 10.0.0.214
Captured 10.0.0.142 requesting 10.0.0.107
Captured e4:92:bf:59:4b:e7 responding 10.0.0.107
Captured e4:92:bf:59:4b:c1 responding 10.0.0.214
Captured 10.0.0.142 requesting 10.0.0.4
Captured 98:8d:46:87:41:4a responding 10.0.0.4
Captured 10.0.0.1 requesting 10.0.0.142
Captured a4:e4:64:dc:06:d4 responding 10.0.0.142
Captured 10.0.0.142 requesting 10.0.0.107
Captured 10.0.0.142 requesting 10.0.0.214
Captured e4:92:bf:59:4b:e7 responding 10.0.0.107
Captured e4:92:bf:59:4b:c1 responding 10.0.0.214
Captured 10.0.0.142 requesting [19:25:25]
[19:55:39] Writing output.
Discovered total 8 hosts and 6 FQDNs
```
Do the above but three times and only print found IPs to CLI and output to file
```
python3 harp.py -i 10.0.0.0/24 -w 30 -c 3 -o ./testing/ -q
  10.0.0.1
  10.0.0.5
10.0.0.32
10.0.0.107
10.0.0.154
10.0.0.214
10.0.0.3
10.0.0.243
10.0.0.203
10.0.0.245
10.0.0.134
10.0.0.115
10.0.0.122
10.0.0.69
```


## Install

**Harp** works on Windows and *Nix systems and requires Python. Windows users may need to install [npcap](https://npcap.org/).


```
git clone 
```

```
pip install -r requirements.txt
```

## Output

The `-o` flag is used to direct the CSV output file to a directory. Output file is comma seperated.

```
cat harp-output.csv | csvtomd
```

### harp-output.csv

|IP|MAC|FQDN|
 |---|---|--|
|IP Address|MAC Address|FQDN|

#### *FQDN is only available if surpress is not enabled
