import re
import argparse

def parse_wep_key(wepkey, keyid):

    print wepkey

    # Match and parse WEP key
    tmp_key = ""
    if re.match('^([0-9a-fA-F]{2}){5}$', wepkey) or re.match ('^([0-9a-fA-F]{2}){13}$', wepkey):
        tmp_key = wepkey
    elif re.match('^([0-9a-fA-F]{2}[:]){4}[0-9a-fA-F]{2}$', wepkey) or re.match('^([0-9a-fA-F]{2}[:]){12}[0-9a-fA-F]{2}$', wepkey):
        tmp_key = re.sub(':', '', wepkey)
    elif re.match ('^([0-9a-fA-F]{4}[-]){2}[0-9a-fA-F]{2}$', wepkey) or re.match ('^([0-9a-fA-F]{4}[-]){6}[0-9a-fA-F]{2}$', wepkey):
        tmp_key = re.sub('-', '', wepkey)
    else:
        return None
    g = lambda x: chr(int(tmp_key[::2][x],16)*16+int(tmp_key[1::2][x],16))

    conf_wepkey = ''
    for i in range(len(tmp_key)/2):
        conf_wepkey += g(i)

    return conf_wepkey

def sanitize_bssid(bssid):

    # Match and parse BSSID
    if re.match('^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', bssid):
        return bssid.lower()

    msg = 'Invalid bssid.'
    raise argparse.ArgumentTypeError(msg)

def sanitize_smac(smac):

    if type(smac) == str and re.match('^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$', smac):
        return smac.lower()

    msg = 'Invalid SMAC.'
    raise argparse.ArgumentTypeError(msg)

def sanitize_ipdns(ipdns):

    if re.match('^(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])\.(\d|[1-9]\d|1\d\d|2[0-4]\d|25[0-5])$', ipdns):
        return ipdns

    msg = 'Error: Wrong IP address'
    raise argparse.ArgumentTypeError(msg)
