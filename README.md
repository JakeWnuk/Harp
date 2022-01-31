<h1 align="center">
 Harp
 </h1>

  CLI based internal network discovery tool using passive and active ARP methods. **Harp** is designed to enumerate private IPv4 ranges with ARP sweeps then sleep and capture ARP requests passively to gather hosts. Found hosts can optionally be searched for their FQDNs and aims to only lookup each host once. **Harp** can be ran as a listener or as a scanner with the ability to scan then passively enumerate repeatedly. Input can be read from `-i` or from `stdin` and formats include: a CIDR, list of CIDRs or a list of IPs. Output is stored within a DataFrame and is automatically loaded from the output directory as a database between runs. 

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
  -w WAIT, --wait WAIT  Minutes to wait between cycles.
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


Do ARP scan of range and fetch FQDN of found hosts
```
python3 harp.py -i 10.0.0.0/24
```
Do ARP scan of range but do not fetch FQDN of found hosts
```
python3 harp.py -i 10.0.0.0/24 -s
```
Do not do ARP scan but passively listen for ARP traffic and capture hosts for 30 minutes
```
python3 harp.py -l -w 30
```
Do ARP scan on input range then print (and load) dataframe to output directory
```
python3 harp.py -i 10.0.0.0/24 -o ./testing/
```
Do ARP scan on input range then passively listen for ARP traffic and capture hosts for 1 minute two times then print (and load) dataframe to output directory
```
python3 harp.py -i 10.0.0.0/24 -w 1 -c 2 -o ./testing/

 ▄ .▄ ▄▄▄· ▄▄▄   ▄▄▄·
██▪▐█▐█ ▀█ ▀▄ █·▐█ ▄█
██▀▐█▄█▀▀█ ▐▀▀▄  ██▀·
██▌▐▀▐█ ▪▐▌▐█•█▌▐█▪·•
▀▀▀ · ▀  ▀ .▀  ▀.▀
Loaded output file with 14 records
[22:21:06] Starting ARP scan...
Starting 10.0.0.0/24
Found 14 live hosts in 10.0.0.0/24
[22:21:15] Writing output.
Discovered total 16 hosts and 13 FQDNs.
[22:21:15] Starting ARP Sniffing...
Starting ARP capture for 1 minutes...
Captured 10.0.0.1 requesting 10.0.0.32
Captured 10.0.0.32 requesting 10.0.0.1
Captured e0:b4:64:dc:06:e9 responding 10.0.0.32
Captured 10.0.0.32 requesting 10.0.0.3
Captured 10.0.0.3 requesting 10.0.0.32
Captured 10.0.0.1 requesting 10.0.0.32
Captured 10.0.0.32 requesting 10.0.0.1
Captured e0:b4:64:dc:06:e9 responding 10.0.0.142
Captured 10.0.0.32 requesting 10.0.0.3
Captured 10.0.0.3 requesting 10.0.0.32
[22:22:27] Starting Cycle 1/2
[22:22:27] Starting ARP scan...
Starting 10.0.0.0/24
Found 11 live hosts in 10.0.0.0/24
[22:22:31] Starting ARP Sniffing...
Starting ARP capture for 1 minutes...
Captured 10.0.0.1 requesting 10.0.0.32
Captured 10.0.0.32 requesting 10.0.0.1
Captured 10.0.0.154 requesting 10.0.0.107
Captured e0:b4:64:dc:06:e9 responding 10.0.0.32
Captured 10.0.0.154 requesting 10.0.0.214
Captured 10.0.0.115 requesting 10.0.0.107
Captured 10.0.0.32 requesting 10.0.0.3
Captured 10.0.0.3 requesting 10.0.0.32
Captured 10.0.0.134 requesting 10.0.0.1
Captured e0:b4:64:dc:06:e9 responding 10.0.0.142
Captured 10.0.0.1 requesting 10.0.0.32
Captured 10.0.0.32 requesting 10.0.0.1
Captured 10.0.0.32 requesting 10.0.0.3
Captured 10.0.0.3 requesting 10.0.0.32
Found 1 new hosts and 1 new FQDNs.
[22:23:44] Writing output.
Discovered total 17 hosts and 14 FQDNs.
[22:23:44] Starting Cycle 2/2
[22:23:44] Starting ARP scan...
Starting 10.0.0.0/24
Found 8 live hosts in 10.0.0.0/24
[22:23:48] Starting ARP Sniffing...
Starting ARP capture for 1 minutes...
Captured 0.0.0.0 requesting 10.0.0.69
Captured 0.0.0.0 requesting 10.0.0.69
Captured 0.0.0.0 requesting 10.0.0.69
Captured 10.0.0.69 requesting 10.0.0.69
Captured e0:b4:64:dc:06:e9 responding 10.0.0.32
Captured 10.0.0.69 requesting 10.0.0.69
Captured 10.0.0.69 requesting 10.0.0.69
Captured 10.0.0.32 requesting 10.0.0.3
Captured e0:b4:64:dc:06:e9 responding 10.0.0.142
Captured 10.0.0.3 requesting 10.0.0.32
Captured 10.0.0.1 requesting 10.0.0.32
Captured 10.0.0.32 requesting 10.0.0.1
Captured 10.0.0.115 requesting 10.0.0.107
Captured 10.0.0.115 requesting 10.0.0.214
Captured 10.0.0.154 requesting 10.0.0.107
Captured e0:b4:64:dc:06:e9 responding 10.0.0.32
Captured 10.0.0.154 requesting 10.0.0.214
Captured 10.0.0.32 requesting 10.0.0.3
Captured 10.0.0.3 requesting 10.0.0.32
Found 1 new hosts and 1 new FQDNs.
[22:24:54] Writing output.
Discovered total 18 hosts and 15 FQDNs.
```
Do the above but only print found IPs to CLI and output to file
```
python3 harp.py -i 10.0.0.0/24 -w 30 -c 2 -o ./testing/ -q
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
