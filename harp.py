#!/usr/bin/python3

import argparse
import datetime as dt
import ipaddress

import pandas as pd
from scapy.all import *


def message(msg, title=False, stat=False, word=False, banner=False):
    """
    Prints formatted text to CLI
    """

    class Colors:
        BLUE = '\033[94m'
        GREEN = "\033[32m"
        YELLOW = '\033[93m'
        ENDC = '\033[0m'
        BOLD = '\033[1m'

    banner_text = """ ▄ .▄ ▄▄▄· ▄▄▄   ▄▄▄·
██▪▐█▐█ ▀█ ▀▄ █·▐█ ▄█
██▀▐█▄█▀▀█ ▐▀▀▄  ██▀·
██▌▐▀▐█ ▪▐▌▐█•█▌▐█▪·•
▀▀▀ · ▀  ▀ .▀  ▀.▀ """

    if title:
        print(f'{Colors.GREEN}{Colors.BOLD}[{str(dt.datetime.now().strftime("%H:%M:%S"))}] {msg}{Colors.ENDC}')
    elif stat:
        print(f'{Colors.BLUE}{msg}{Colors.ENDC}')
    elif word:
        return f'{Colors.YELLOW}{Colors.BOLD}{msg}{Colors.ENDC}{Colors.BLUE}'
    elif banner:
        print(f'{Colors.YELLOW}{banner_text}{Colors.ENDC}')


def validate_cidr(cidr_str):
    """
    Takes a string of a CIDR and returns if it is valid
    :param cidr_str: a str with a CIDR value
    :return: list obj with the CIDR
    """
    cidr_regex = r'^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/([0-9]|[1-2][0-9]|3[0-2]))$'
    if not re.match(cidr_regex, cidr_str):
        message(f'Input is either not a valid CIDR notation file name: {message(str(cidr_str), word=True)}', stat=True)
        exit()
    return list(cidr_str.split(' '))


def transform_cidr(ip_var):
    """
    Accepts CIDR string or list of IP addresses
    :param ip_var: either str or list containing IPs or CIDRs
    :return: CIDR string or list of CIDRs
    """
    # convert str
    if type(ip_var) == str:
        output_lst = validate_cidr(ip_var)
        return output_lst
    # convert list of ips
    elif type(ip_var) == list and len(ip_var) > 1:
        nets = [ipaddress.ip_network(ip) for ip in ip_var]
        cidr = list(ipaddress.collapse_addresses(nets))
        output_lst = []
        for itr in cidr:
            output_lst.append(format(itr))
        return output_lst
    # convert list of cidrs
    elif type(ip_var) == list and len(ip_var) == 1:
        output_lst = validate_cidr(ip_var[0])
        return output_lst
    else:
        message('Input can not be parsed.', title=True)
        exit()


def reduce_cidr(cidr_list, nprefix=29):
    """
    Reduces a list of CIDR values to smaller subnets
    :param cidr_list: a list of CIDR values
    :param nprefix: the new prefix for subnet
    :return: a list of reduces CIDRs
    """
    message(f'Reducing input to {message("/" + str(nprefix), word=True)} subnets...', stat=True)
    output_lst = []
    for line in cidr_list:
        try:
            for subnet in ipaddress.ip_network(line.strip(), False).subnets(new_prefix=nprefix):
                output_lst.append(format(subnet))
        except ValueError as e:
            message(f'Input already reduced skipping...', stat=True)
            return cidr_list
    return output_lst


class Harp:
    def __init__(self, in_var, do_suppress, sleep_min, listen_mode):
        self.in_var = in_var
        self.suppress = do_suppress
        self.sleep = sleep_min
        self.listen_mode = listen_mode

        # check if it exists in cwd and then read in else make empty
        if os.path.exists(os.path.join(args.output, 'harp-output.csv')):
            self.hosts_df = pd.read_csv(os.path.join(args.output, 'harp-output.csv'))
            message(f'Loaded output file with {message(len(self.hosts_df), word=True)} records', stat=True)
        else:
            self.hosts_df = pd.DataFrame(columns=['IP', 'MAC'])

        if self.listen_mode:
            out_df = self.start_sniff()
            self.hosts_df = pd.concat([self.hosts_df, out_df])
            self.print_output()
            exit()

    def run(self, in_var, do_suppress):
        """
        Runs an ARP scan and returns a df with live hosts
        :param in_var: input variable either a str or list containing IPs or CIDRs
        :param do_suppress: do not request FQDN (bool)
        return: pd.DataFrame with only new results not in self.hosts_df
        """
        input_cidr = transform_cidr(in_var)
        input_cidr = reduce_cidr(input_cidr)

        try:
            hosts_df = self.arp_scan(input_cidr)
        except OSError as e:
            message(f'{str(e)}! Are you root?', title=True)
            exit()

        new_df = self.compare(hosts_df)

        if do_suppress:
            return new_df
        else:
            hosts_df = self.fqdn(new_df)

        return hosts_df

    def fqdn(self, df):
        """
        Gets the FQDN and adds it as a new col for the df
        :param df: pd.DataFrame holding IP addresses
        return: input DF with a new FQDN column
        """
        if len(df) != 0:
            df['FQDN'] = df['IP'].apply(lambda x: self.get_fqdn(x))
            return df
        else:
            return df

    def arp_scan(self, cidr_var):
        """
        Accepts CIDR string or list of CIDRs
        :param cidr_var: either a str or list containing formatted CIDRs
        :return: pd.DataFrame with live IPs and their physical addresses
        """
        hosts = pd.DataFrame(columns=['IP', 'MAC'])
        message('Starting ARP scan...', title=True)
        try:
            # sleep interval determined by the number of input
            sleep_interval = (self.sleep * 60) / len(cidr_var)
            # assumes /29 will have 8 addresses - CHANGE IF YOU CHANGE NPREFIX OF REDUCE_CIDR()
            pkt_interval = sleep_interval / (len(cidr_var) * 8)
            message(f'Reduced input CIDRs to {message(len(cidr_var), word=True)} subnets', stat=True)
            message(f'Switching subnet scans every {message(round(sleep_interval, 2), word=True)} seconds.', stat=True)
            message(f'Time between packets will be {message(round(pkt_interval, 6), word=True)} seconds.', stat=True)
            # if its a list of CIDRs
            if type(cidr_var) == list:
                random.shuffle(cidr_var)
                for cidr in cidr_var:
                    resp, unresp = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(cidr)), timeout=4, verbose=0, inter=pkt_interval)
                    time.sleep(0.1)
                    message(f'Found {message(str(len(resp)), word=True)} live hosts in {message(str(cidr), word=True)}', stat=True)
                    for h in resp:
                        hosts.loc[hosts.shape[0]] = [h[1].psrc, h[1].hwsrc]
                    time.sleep(random.uniform(0, 0.2))
            # if its a CIDR string
            elif type(cidr_var) == str:
                resp, unresp = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(cidr_var)), timeout=4, verbose=0, inter=pkt_interval)
                message(f'Found {message(str(len(resp)), word=True)} live hosts in {message(str(cidr_var), word=True)}', stat=True)
                for h in resp:
                    hosts.loc[hosts.shape[0]] = [h[1].psrc, h[1].hwsrc]
            return hosts
        except socket.gaierror:
            message('Socket Error!', title=True)
            exit()

        return hosts

    @staticmethod
    def get_fqdn(adr):
        """
        Uses socket to request FQDN of an IP
        :return: string of FQDN
        """
        try:
            fqdn = socket.getfqdn(str(adr))
            if str(fqdn) == str(adr):
                return 'NONE'
            else:
                return str(fqdn)
        except socket.herror:
            pass

    def print_output(self):
        """
        Prints output to CLI and file
        :return: None
        """
        message('Writing output.', title=True)
        try:
            message(f'Discovered total {message(str(len(self.hosts_df)), word=True)} hosts and {message(len(self.hosts_df["FQDN"].loc[~self.hosts_df["FQDN"].isin(["NONE"])]), word=True)} FQDNs.', stat=True)
        except KeyError:
            message(f'Discovered total {message(str(len(self.hosts_df)), word=True)} hosts.', stat=True)
        self.hosts_df.to_csv(os.path.join(args.output, 'harp-output.csv'), index=False)

    def cycle(self):
        """
        Process to run ARP scan and passive collection multiple times
        :return: None
        """
        # run new scan and add new hosts
        new_sniffed = self.start_sniff()
        self.hosts_df = pd.concat([self.hosts_df, new_sniffed])
        self.print_output()

    def compare(self, df):
        """
        Compares self.host_df with a new df and returns new entries
        :param df: pd.DataFrame to compare self.hosts_df with
        :return: pd.DataFrame
        """
        try:
            c_df = self.hosts_df.merge(df, how='outer', on=['IP', 'MAC', 'FQDN'], indicator=True, copy=True).loc[
                lambda x: x['_merge'] == 'right_only']
        except KeyError:
            c_df = self.hosts_df.merge(df, how='outer', on=['IP', 'MAC'], indicator=True, copy=True).loc[
                lambda x: x['_merge'] == 'right_only']
        c_df.drop(columns=['_merge'], inplace=True)

        return c_df

    def start_sniff(self):
        """
        Function to start ARP listener and record requests then ETL them
        :return: pd.DataFrame
        """
        sniffed_df = pd.DataFrame(columns=['IP', 'MAC'])
        wait_flux = random.uniform(5, 30)
        message(f'Starting ARP Sniffing...', title=True)
        message(f'Starting ARP capture for {message("~" + str(args.wait), word=True)} minutes...', stat=True)
        sniffer = AsyncSniffer(prn=self.arp_monitor_callback, filter="arp", store=1)
        sniffer.start()

        # scan or sleep
        if not self.listen_mode:
            out_df = self.run(self.in_var, self.suppress)
            self.hosts_df = pd.concat([self.hosts_df, out_df])
            self.print_output()
        else:
            time.sleep((args.wait * 60) + wait_flux)
        sniffer.stop()
        sniffed_pkt = sniffer.results

        for pkt in sniffed_pkt:
            if str(pkt[1].psrc) != '0.0.0.0':
                sniffed_df.loc[sniffed_df.shape[0]] = [pkt[1].psrc, pkt[1].hwsrc]

        # check sniffed hosts and add new hosts
        new_sniffed = self.compare(sniffed_df)
        new_sniffed.drop_duplicates(subset=['IP', 'MAC'], inplace=True)

        if self.suppress:
            pass
        else:
            new_sniffed = self.fqdn(new_sniffed)

        return new_sniffed

    @staticmethod
    def arp_monitor_callback(pkt):
        """
        Out of the box function for monitoring ARP
        :param pkt: packet from scapy
        :return: output str but packets are captured by sniff()
        """
        # add finding new stuff to df if it doesnt exist and print
        if ARP in pkt and pkt[ARP].op in (1, 2):
            if pkt[ARP].op == 1:
                return message("Captured " + message(pkt[ARP].psrc, word=True) + " requesting " + message(pkt[ARP].pdst, word=True), stat=True)
            # these are mostly informational for the CLI the logic does not parse them
            if pkt[ARP].op == 2:
                return message("Captured " + message(pkt[ARP].hwsrc, word=True) + " responding " + message(pkt[ARP].psrc, word=True), stat=True)


if __name__ == '__main__':
    conf.use_pcap = True
    parser = argparse.ArgumentParser(
        description='Network reconnaissance tool to discover hosts using ARP.')
    parser.add_argument("-i", "--input", action="store", default='no input found',
                        help='Input list of IPs, list of CIDRs, or a CIDR range.')
    parser.add_argument("-o", "--output", action="store", default=os.getcwd(),
                        help="Prints and loads CSV files to directory. The default is cwd.")
    parser.add_argument("-s", "--suppress", action="store_true", default=False,
                        help="Only performs ARP scans and ignores fetching FQDN.")
    parser.add_argument("-c", "--cycles", action="store", default=1, type=int,
                        help="Number of cycles to repeat.")
    parser.add_argument("-w", "--wait", action="store", default=30, type=int,
                        help="Minutes keep the listener open and spread scans throughout (if enabled).")
    parser.add_argument("-q", "--quiet", action="store_true", default=False,
                        help="Hides banner and only prints found IPs to CLI.")
    parser.add_argument("-l", "--listen", action="store_true", default=False,
                        help="Skips all active scans and only starts the listener.")
    args = parser.parse_args()

    # overwrite empty input for listener
    if args.listen:
        args.input = '10.0.0.0/24'

    if not sys.stdin.isatty() and str(args.input) == 'no input found':
        message('Reading from STDIN...', stat=True)
        args.input = sys.stdin

    input_df = pd.DataFrame
    try:
        # reads stdin, list of IPs, and list of CIDRs
        input_df = pd.read_table(args.input, header=None, names=['CIDR/IP'])
        input_lst = input_df['CIDR/IP'].tolist()
    except FileNotFoundError:
        # reads input flag CIDR range
        if type(args.input) == str:
            input_lst = validate_cidr(args.input)
        elif type(args.input) == list:
            input_list = args.input

    try:
        if not args.quiet:
            message('', banner=True)
        elif args.quiet:
            sys.stdout = open(os.devnull, 'w')
        try:
            input_var = transform_cidr(input_lst)
            input_var = reduce_cidr(input_var)
        except TypeError:
            message(f'Input is either not a valid CIDR notation or file name.', stat=True)
            exit()

        MyHarp = Harp(input_var, args.suppress, args.wait, args.listen)
        for i in range(0, int(args.cycles)):
            message(f'Starting Cycle {message(str(i + 1) + "/" + str(args.cycles), word=True)}', title=True)
            MyHarp.cycle()

        if args.quiet:
            sys.stdout = sys.__stdout__
            print(MyHarp.hosts_df['IP'].to_string(index=False))

    except KeyboardInterrupt:
        message("CTRL + C Pressed! Writing output then quiting...", title=True)
        MyHarp.print_output()
