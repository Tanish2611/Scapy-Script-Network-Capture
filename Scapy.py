#!/usr/bin/env python3
"""
WiFi Device Tracking & Clock Skew Capture  -  v4.0
====================================================
Captures 802.11 frames in monitor mode and writes 28-field metadata to CSV
for device behavioural analysis and clock-skew fingerprinting research.

Requirements:
    pip install scapy
    sudo / root privileges
    WiFi adapter placed in monitor mode before running

Quick start:
    sudo airmon-ng check kill
    sudo airmon-ng start wlan0          # produces wlan0mon
    sudo python3 wifi_capture_v4.py
"""

# Scapy prints a bunch of warnings on import about missing optional libs.
# Suppress them before anything else loads or they'll clutter the terminal.
import warnings
warnings.filterwarnings('ignore')

import os
import sys
import csv
import time
import signal
import hashlib
import argparse
from datetime import datetime

try:
    from scapy.layers.dot11 import (
        Dot11, Dot11Beacon, Dot11Elt,
        Dot11ProbeReq, Dot11ProbeResp,
        Dot11Auth, Dot11AssoReq, RadioTap
    )
    from scapy.packet import Raw
    from scapy.sendrecv import sniff
    from scapy.config import conf
    conf.use_pcap = True
    conf.sniff_promisc = True
except ImportError as e:
    print(f"[ERROR] Scapy import failed: {e}")
    print("        Fix with:  pip install scapy")
    sys.exit(1)


# ---------------------------------------------------------------------------
# CSV field schema
# ---------------------------------------------------------------------------
# This list defines both the column order in the output file and which keys
# get pulled out of the metadata dict when writing each row.  Don't reorder
# without also updating any downstream analysis scripts.

WIFI_FIELDS = [
    # Timing fields used for clock-skew analysis
    'timestamp', 'epoch_time_ns', 'packet_number',
    'inter_arrival_time_ms', 'timing_jitter',
    # 802.11 frame identity
    'src_mac', 'dst_mac', 'bssid',
    'frame_type', 'frame_subtype', 'frame_size',
    # RF signal info from the RadioTap header
    'signal_strength_dbm', 'channel', 'frequency_mhz',
    # Device fingerprinting from Information Elements
    'vendor_oui', 'supported_rates', 'ht_capabilities', 'encryption_type',
    # Frame control flags and addressing behaviour
    'sequence_number', 'retry_flag', 'power_management', 'packet_direction',
    # Network context - only populated on beacon frames
    'ssid', 'beacon_interval', 'tsf_timestamp', 'device_capability_hash',
    # Derived behavioural features
    'burst_indicator', 'temporal_pattern_hash',
]


# ---------------------------------------------------------------------------
# Global runtime state
# ---------------------------------------------------------------------------
# These are written to by the packet handler on every captured frame.
# Keeping them global avoids passing them through multiple call layers on
# every packet, which matters at high capture rates.

last_packet_time = 0     # time.time() * 1000 of the previous captured packet
timing_history   = []    # rolling window of the last 10 inter-arrival times
packet_counter   = 0     # running count of packets written to disk
START_TIME       = time.time()

# Capture configuration - set once at startup by main() or configure_filtering()
OUTPUT_FILE          = 'wifi_device_tracking.csv'
INTERFACE            = None
FILTER_MODE          = 'all'   # 'all' captures everything, 'bssid' filters by AP
TARGET_BSSIDS        = []
MONITOR_CLIENTS_ONLY = False


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def safe_get_attr(obj, attr, default=None):
    # Scapy field access can throw on malformed frames, so wrap it
    try:
        return getattr(obj, attr, default)
    except Exception:
        return default


def safe_addr_to_str(addr):
    # MAC addresses occasionally come back as None or the string "None"
    # from Scapy when a field is missing in the frame.  Return empty string
    # in both cases so CSV rows don't end up with the literal word "None".
    try:
        s = str(addr)
        return s if s and s != 'None' else ''
    except Exception:
        return ''


# ---------------------------------------------------------------------------
# Layer extractors
# ---------------------------------------------------------------------------

def extract_basic_info(pkt):
    # Pull the frame-level fields that are present on every 802.11 packet:
    # MAC addresses, frame type/subtype, and the retry + power-save bits
    # from the Frame Control field.
    info = {}
    try:
        info['frame_size']    = len(pkt)
        info['timestamp']     = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
        info['epoch_time_ns'] = time.time_ns()

        if not pkt.haslayer(Dot11):
            return info

        d = pkt[Dot11]

        # addr1 = receiver, addr2 = transmitter, addr3 = BSSID.
        # We label them dst/src/bssid to keep the CSV readable.
        info['src_mac']       = safe_addr_to_str(safe_get_attr(d, 'addr2', ''))
        info['dst_mac']       = safe_addr_to_str(safe_get_attr(d, 'addr1', ''))
        info['bssid']         = safe_addr_to_str(safe_get_attr(d, 'addr3', ''))
        info['frame_type']    = safe_get_attr(d, 'type',    0)
        info['frame_subtype'] = safe_get_attr(d, 'subtype', 0)

        # FCfield is a bitmask.  Bit 3 = retry, bit 4 = power management.
        fc = safe_get_attr(d, 'FCfield', 0)
        info['retry_flag']       = 1 if (fc & 0x08) else 0
        info['power_management'] = 1 if (fc & 0x10) else 0

        # The sequence control field packs fragment number in the low 4 bits
        # and sequence number in the upper 12 bits.
        sc = safe_get_attr(d, 'SC', 0)
        if sc:
            info['sequence_number'] = (sc >> 4) & 0xFFF

    except Exception as e:
        print(f"[WARNING] Basic extraction error: {e}")

    return info


def extract_signal_info(pkt):
    # Signal strength comes from the RadioTap header that the adapter prepends
    # in monitor mode.  Different drivers expose it under different attribute
    # names, so we check a few options before giving up.
    info = {}
    try:
        signal_dbm = None
        if hasattr(pkt, 'dBm_AntSignal'):
            signal_dbm = pkt.dBm_AntSignal
        elif hasattr(pkt, 'SignalStrength'):
            signal_dbm = pkt.SignalStrength
        elif pkt.haslayer(RadioTap):
            signal_dbm = safe_get_attr(pkt[RadioTap], 'dBm_AntSignal')

        # Use -70 as a fallback but only when there really is no data.
        # Checking is not None matters here because 0 dBm is a valid reading.
        info['signal_strength_dbm'] = signal_dbm if signal_dbm is not None else -70

        channel = None
        if hasattr(pkt, 'Channel'):
            channel = pkt.Channel
        elif pkt.haslayer(RadioTap):
            channel = safe_get_attr(pkt[RadioTap], 'Channel')

        info['channel'] = channel

        # Convert channel number to centre frequency in MHz.
        # 2.4 GHz channels are spaced 5 MHz apart starting at 2412 (ch 1).
        # 5 GHz channels follow the UNII band numbering convention.
        if channel:
            if 1 <= channel <= 14:
                info['frequency_mhz'] = 2412 + (channel - 1) * 5
            elif 36 <= channel <= 177:
                info['frequency_mhz'] = 5000 + channel * 5
            else:
                info['frequency_mhz'] = None
        else:
            info['frequency_mhz'] = None

    except Exception as e:
        print(f"[WARNING] Signal extraction error: {e}")
        info.setdefault('signal_strength_dbm', -70)
        info.setdefault('channel', None)
        info.setdefault('frequency_mhz', None)

    return info


def extract_beacon_info(pkt):
    # TSF (Timing Synchronisation Function) timestamps are broadcast by APs
    # in beacon frames.  They're the main input for clock-skew fingerprinting
    # because each AP's oscillator drifts at a slightly different rate.
    info = {}
    try:
        if not (pkt.haslayer(Dot11) and pkt.haslayer(Dot11Beacon)):
            return info
        b = pkt[Dot11Beacon]
        info['tsf_timestamp']   = safe_get_attr(b, 'timestamp', 0)
        info['beacon_interval'] = safe_get_attr(b, 'beacon_interval', 100)
    except Exception as e:
        print(f"[WARNING] Beacon extraction error: {e}")
    return info


def extract_ie_info(pkt):
    # Information Elements are a TLV structure appended to management frames.
    # We walk the chain looking for the IEs we care about.  The cap at 20
    # elements is a safety measure against malformed frames looping forever.
    info = {
        'ssid': '',
        'supported_rates': '',
        'vendor_oui': '',
        'encryption_type': '',
        'ht_capabilities': '',
    }
    try:
        if not pkt.haslayer(Dot11Elt):
            return info

        elt = pkt[Dot11Elt]
        elements_processed = 0

        while elt and elements_processed < 20:
            try:
                elt_id   = safe_get_attr(elt, 'ID')
                elt_info = safe_get_attr(elt, 'info', b'')
                if elt_id is None:
                    break

                if elt_id == 0 and elt_info:
                    # IE 0 is the SSID.  Most are valid UTF-8 but some APs
                    # emit non-standard encodings, so fall back to hex.
                    try:
                        info['ssid'] = elt_info.decode('utf-8', errors='ignore')
                    except Exception:
                        info['ssid'] = elt_info.hex()[:32]

                elif elt_id == 1 and elt_info:
                    # IE 1 is Supported Rates.  Each byte encodes a rate in
                    # 500 kbps units, with the MSB as a "basic rate" flag.
                    try:
                        rates = [str((x & 0x7f) / 2) for x in elt_info[:8]]
                        info['supported_rates'] = ','.join(rates)
                    except Exception:
                        pass

                elif elt_id == 45 and elt_info:
                    # IE 45 is HT Capabilities (802.11n).  Store the raw hex
                    # for downstream parsing - it contains MIMO stream counts,
                    # channel width support, and guard interval settings.
                    info['ht_capabilities'] = elt_info.hex()[:16]

                elif elt_id == 48:
                    # IE 48 is the RSN (Robust Security Network) element,
                    # which means WPA2 is in use.
                    info['encryption_type'] = 'WPA2'

                elif elt_id == 221 and len(elt_info) >= 3:
                    # IE 221 is Vendor Specific.  The first 3 bytes are the OUI.
                    # Microsoft's WPA IE (00:50:f2:01) predates RSN and indicates
                    # WPA1.  Only set WPA if we haven't already seen WPA2.
                    oui = elt_info[:3].hex()
                    info['vendor_oui'] = oui
                    if len(elt_info) >= 4 and elt_info[:4] == b'\x00\x50\xf2\x01':
                        if not info['encryption_type']:
                            info['encryption_type'] = 'WPA'

                elements_processed += 1

                # Dot11Elt chains as nested payloads rather than a list
                if hasattr(elt, 'payload') and isinstance(elt.payload, Dot11Elt):
                    elt = elt.payload
                else:
                    break

            except Exception:
                break

    except Exception as e:
        print(f"[WARNING] IE extraction error: {e}")

    return info


def calculate_behavioral_features(basic_info, signal_info, timing_info):
    # Derive a few higher-level features from the raw fields.
    # The MD5 hashes are compact fingerprints for grouping packets from the
    # same device - not for cryptographic security.
    try:
        dst = basic_info.get('dst_mac', '')
        if dst == 'ff:ff:ff:ff:ff:ff':
            direction = 'broadcast'
        elif dst and len(dst) > 1 and dst[1].lower() in '13579bdf':
            # The second hex digit of the MAC tells you multicast.
            # Any odd value in that nibble means the multicast bit is set.
            direction = 'multicast'
        else:
            direction = 'unicast'

        # A burst is any packet that arrives within 50ms of the previous one.
        # The first packet always gets inter_arrival=0, so burst_indicator=1
        # on packet 1 - this matches the behaviour in the captured CSV.
        ia = timing_info.get('inter_arrival_time_ms', 0)
        burst = 1 if ia < 50 else 0

        # Device capability hash: short fingerprint based on the last 4 bytes
        # of the MAC (vendor-assigned part), frame type, and signal level.
        # Changes between packets from the same device but provides a rough
        # cluster key when signal is stable.
        cap_str = '|'.join([
            basic_info.get('src_mac', '')[-8:],
            str(basic_info.get('frame_type', 0)),
            str(signal_info.get('signal_strength_dbm', -70)),
        ])
        cap_hash = hashlib.md5(cap_str.encode()).hexdigest()[:8]

        # Temporal pattern hash: fingerprint of timing behaviour.
        # Jitter is multiplied by 1000 to move it to integer microseconds
        # before hashing so small float differences don't produce collisions.
        tmp_str = '|'.join([
            str(int(timing_info.get('timing_jitter', 0) * 1000)),
            str(burst),
            str(basic_info.get('retry_flag', 0)),
        ])
        tmp_hash = hashlib.md5(tmp_str.encode()).hexdigest()[:8]

        return {
            'packet_direction':       direction,
            'burst_indicator':        burst,
            'device_capability_hash': cap_hash,
            'temporal_pattern_hash':  tmp_hash,
        }

    except Exception as e:
        print(f"[WARNING] Behavioral calculation error: {e}")
        return {
            'packet_direction':       'unknown',
            'burst_indicator':        0,
            'device_capability_hash': '',
            'temporal_pattern_hash':  '',
        }


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------

def should_capture_packet(basic_info):
    # In 'all' mode we skip filtering entirely to avoid the overhead on
    # every packet.  In 'bssid' mode we check which addresses are in our
    # target list.  MONITOR_CLIENTS_ONLY widens the match to include client
    # traffic addressed to or from a target AP, not just the AP's own frames.
    if FILTER_MODE == 'all':
        return True
    try:
        bssid   = basic_info.get('bssid',   '').lower()
        src_mac = basic_info.get('src_mac', '').lower()
        dst_mac = basic_info.get('dst_mac', '').lower()
        targets = [b.lower() for b in TARGET_BSSIDS]

        if MONITOR_CLIENTS_ONLY:
            return (bssid in targets or src_mac in targets or dst_mac in targets)
        else:
            return bssid in targets

    except Exception as e:
        print(f"[WARNING] Filtering error: {e}")
        return True


# ---------------------------------------------------------------------------
# Metadata orchestrator
# ---------------------------------------------------------------------------

def extract_all_metadata(pkt, packet_num):
    # Run all the extractors and merge their outputs into a single flat dict
    # that maps directly onto WIFI_FIELDS.  Timing has to be calculated here
    # rather than in a separate extractor because it depends on the global
    # last_packet_time being updated in the right order.
    global timing_history, last_packet_time

    metadata = {field: None for field in WIFI_FIELDS}
    metadata['packet_number'] = packet_num

    try:
        basic_info = extract_basic_info(pkt)

        # Calculate inter-arrival time and rolling jitter.
        # time.time() * 1000 gives milliseconds as a float which gives us
        # sub-millisecond precision without needing time.time_ns() here.
        current_time     = time.time() * 1000
        inter_arrival_ms = 0
        timing_jitter    = 0

        if last_packet_time > 0:
            inter_arrival_ms = current_time - last_packet_time

            timing_history.append(inter_arrival_ms)
            if len(timing_history) > 10:
                timing_history.pop(0)

            # Mean absolute deviation over the window.
            # We need at least 3 samples before jitter is meaningful.
            if len(timing_history) >= 3:
                mean = sum(timing_history) / len(timing_history)
                timing_jitter = sum(abs(t - mean) for t in timing_history) / len(timing_history)

        last_packet_time = current_time

        timing_info = {
            'inter_arrival_time_ms': inter_arrival_ms,
            'timing_jitter':         timing_jitter,
        }

        signal_info      = extract_signal_info(pkt)
        beacon_info      = extract_beacon_info(pkt)
        ie_info          = extract_ie_info(pkt)
        behavioral_feats = calculate_behavioral_features(basic_info, signal_info, timing_info)

        # Merge all dicts.  Order matters if keys overlap - later dicts win.
        # In practice there's no overlap between these extractors.
        all_info = {
            **basic_info,
            **signal_info,
            **beacon_info,
            **ie_info,
            **timing_info,
            **behavioral_feats,
        }

        for field in WIFI_FIELDS:
            if field in all_info:
                metadata[field] = all_info[field]

    except Exception as e:
        print(f"[ERROR] Metadata extraction error for packet {packet_num}: {e}")

    return metadata


# ---------------------------------------------------------------------------
# CSV I/O
# ---------------------------------------------------------------------------

def initialize_csv():
    # Create the file fresh at the start of each run and write the header row.
    # If the file already exists this will overwrite it - intentional, since
    # a partial CSV from a previous crash would have misaligned row counts.
    try:
        with open(OUTPUT_FILE, 'w', newline='') as f:
            csv.writer(f).writerow(WIFI_FIELDS)
        print(f"[+] Output file ready: {OUTPUT_FILE}")
    except Exception as e:
        print(f"[ERROR] Cannot create output file: {e}")
        sys.exit(1)


def save_packet_to_csv(metadata):
    # Append one row per packet.  Converting everything to str() means None
    # values become the empty string in the CSV rather than the word "None",
    # which is friendlier for pandas and most data tools.
    try:
        with open(OUTPUT_FILE, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([str(metadata.get(field, '')) for field in WIFI_FIELDS])
    except Exception as e:
        print(f"[WARNING] CSV write error: {e}")


# ---------------------------------------------------------------------------
# Packet handler
# ---------------------------------------------------------------------------

def packet_handler(pkt):
    global packet_counter

    # Ignore anything that isn't 802.11 - this can happen if Scapy picks up
    # stray non-WiFi frames depending on the adapter and driver
    if not pkt.haslayer(Dot11):
        return

    basic_info = extract_basic_info(pkt)
    if not should_capture_packet(basic_info):
        return

    packet_counter += 1
    metadata = extract_all_metadata(pkt, packet_counter)
    save_packet_to_csv(metadata)

    # Print a one-line status update every 100 packets so you can see the
    # capture is running without flooding the terminal
    if packet_counter % 100 == 0:
        elapsed = time.time() - START_TIME
        rate    = packet_counter / elapsed if elapsed > 0 else 0
        bssid   = str(metadata.get('bssid') or 'N/A')[:17]
        print(
            f"[{packet_counter:>6}] {rate:5.1f} pkt/s  |  "
            f"Type {metadata.get('frame_type', '?')}.{metadata.get('frame_subtype', '?')}  |  "
            f"Signal {metadata.get('signal_strength_dbm', '?')} dBm  |  "
            f"BSSID {bssid}"
        )
        if FILTER_MODE != 'all' and TARGET_BSSIDS:
            print(f"         Targeting {len(TARGET_BSSIDS)} BSSID(s)")
        print()


# ---------------------------------------------------------------------------
# AP scanner
# ---------------------------------------------------------------------------

def scan_for_aps(iface, duration=10):
    # Passive scan - just listen for beacon frames for a fixed time.
    # No probe requests are sent, so this won't alert IDS systems.
    # Returns a dict of {bssid: {ssid, signal, channel}} sorted by signal.
    print(f"\n[*] Scanning for access points on {iface} ({duration}s)...")
    discovered = {}

    def _scan_handler(pkt):
        try:
            if not (pkt.haslayer(Dot11) and pkt.haslayer(Dot11Beacon)):
                return
            bssid = safe_addr_to_str(pkt[Dot11].addr3)
            if not bssid or bssid == '00:00:00:00:00:00':
                return

            sig = -70
            if hasattr(pkt, 'dBm_AntSignal'):
                sig = pkt.dBm_AntSignal

            ssid = '<Hidden>'
            if pkt.haslayer(Dot11Elt) and pkt[Dot11Elt].ID == 0 and pkt[Dot11Elt].info:
                try:
                    ssid = pkt[Dot11Elt].info.decode('utf-8', errors='ignore')
                except Exception:
                    ssid = pkt[Dot11Elt].info.hex()[:16]

            ch = getattr(pkt, 'Channel', '?')
            discovered[bssid] = {'ssid': ssid, 'signal': sig, 'channel': ch}
        except Exception:
            pass

    sniff(iface=iface, prn=_scan_handler, timeout=duration, store=False)

    if discovered:
        sorted_aps = sorted(discovered.items(), key=lambda x: x[1]['signal'], reverse=True)
        print(f"\n[*] Found {len(discovered)} access points:\n")
        print(f"{'#':>3}  {'SSID':<28} {'BSSID':17}  {'Ch':>3}  Signal")
        print('-' * 65)
        for idx, (bssid, d) in enumerate(sorted_aps[:40], 1):
            name = (d['ssid'][:25] + '...') if len(d['ssid']) > 25 else d['ssid']
            print(f"{idx:>3}. {name:<28} {bssid}  {str(d['channel']):>3}  {d['signal']:>4} dBm")
    else:
        print('[WARNING] No APs found - is the interface in monitor mode?')

    return discovered


# ---------------------------------------------------------------------------
# Interactive filtering menu
# ---------------------------------------------------------------------------

def configure_filtering():
    global TARGET_BSSIDS, FILTER_MODE, MONITOR_CLIENTS_ONLY

    print('\n' + '-' * 55)
    print('  Monitoring Configuration')
    print('-' * 55)
    print('  1.  Capture all traffic')
    print('  2.  Target specific BSSID(s)')
    print('  3.  Client monitoring mode  (traffic to/from target APs)')
    print('-' * 55)

    choice = input('\nSelect option (1 / 2 / 3): ').strip()

    if choice not in ('2', '3'):
        FILTER_MODE = 'all'
        print('[+] Mode: capture all traffic')
        return

    FILTER_MODE = 'bssid'
    MONITOR_CLIENTS_ONLY = (choice == '3')

    do_scan = input('[?] Scan for APs first? (y / N): ').strip().lower()
    discovered = {}
    if do_scan == 'y':
        discovered = scan_for_aps(INTERFACE)

    if choice == '2':
        print('\n[*] BSSID targeting mode')
    else:
        print('\n[*] Client monitoring mode')

    if discovered:
        raw = input(
            'Enter AP number(s) from list (e.g. 1,3)  or  m  for manual BSSID entry: '
        ).strip()

        if raw.lower() == 'm':
            raw_bssids = input('Enter BSSID(s) comma-separated: ').strip()
            TARGET_BSSIDS = [b.strip() for b in raw_bssids.split(',') if b.strip()]
        else:
            try:
                sorted_aps = sorted(discovered.items(), key=lambda x: x[1]['signal'], reverse=True)
                indices = [int(x.strip()) - 1 for x in raw.split(',')]
                TARGET_BSSIDS = [sorted_aps[i][0] for i in indices if 0 <= i < len(sorted_aps)]
                if not TARGET_BSSIDS:
                    raise ValueError
            except (ValueError, IndexError):
                print('[WARNING] Invalid selection - switching to manual entry.')
                raw_bssids = input('Enter BSSID(s) comma-separated: ').strip()
                TARGET_BSSIDS = [b.strip() for b in raw_bssids.split(',') if b.strip()]
    else:
        raw_bssids = input('Enter target BSSID(s) comma-separated: ').strip()
        TARGET_BSSIDS = [b.strip() for b in raw_bssids.split(',') if b.strip()]

    print(f'\n[+] {FILTER_MODE.upper()} mode  |  {len(TARGET_BSSIDS)} target(s)')
    if MONITOR_CLIENTS_ONLY:
        print('    Focus: devices connecting to target APs')
    for b in TARGET_BSSIDS:
        print(f'    - {b}')


# ---------------------------------------------------------------------------
# Ctrl+C handler
# ---------------------------------------------------------------------------

def signal_handler(sig, frame):
    elapsed = time.time() - START_TIME
    rate    = packet_counter / elapsed if elapsed > 0 else 0

    size_mb = 0.0
    try:
        size_mb = os.path.getsize(OUTPUT_FILE) / (1024 * 1024)
    except OSError:
        pass

    print('\n\n' + '-' * 55)
    print('  Capture stopped')
    print('-' * 55)
    print(f'  Packets captured : {packet_counter:,}')
    print(f'  Duration         : {elapsed:.1f} s')
    print(f'  Average rate     : {rate:.1f} pkt/s')
    print(f'  Output file      : {OUTPUT_FILE}  ({size_mb:.2f} MB)')
    print('-' * 55)
    sys.exit(0)


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------
# Flags are all optional - if you don't pass them the interactive menus
# will ask for the same information at runtime.

def build_parser():
    p = argparse.ArgumentParser(
        description='WiFi Device Tracking & Clock Skew Capture  v4.0',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument('-i', '--iface',
                   help='Monitor-mode interface  (e.g. wlan0mon)')
    p.add_argument('-o', '--output',
                   default='wifi_device_tracking.csv',
                   help='Output CSV path  (default: wifi_device_tracking.csv)')
    p.add_argument('--bssid',
                   metavar='MAC', nargs='+',
                   help='Target BSSID(s) - skips interactive menu')
    p.add_argument('--clients-only',
                   action='store_true',
                   help='Client monitoring mode when used with --bssid')
    p.add_argument('--scan',
                   action='store_true',
                   help='Run AP scan and exit without capturing')
    p.add_argument('--scan-duration',
                   type=int, default=10, metavar='SEC',
                   help='AP scan duration in seconds  (default: 10)')
    return p


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    global INTERFACE, OUTPUT_FILE, FILTER_MODE, TARGET_BSSIDS, MONITOR_CLIENTS_ONLY

    args = build_parser().parse_args()

    if os.geteuid() != 0:
        print('\n[ERROR] Root privileges are required.')
        print('        Run with:  sudo python3 wifi_capture_v4.py\n')
        sys.exit(1)

    print('\n' + '=' * 55)
    print('  WiFi Device Tracking  &  Clock Skew Capture')
    print('  v4.0  -  Behavioural Analysis Mode')
    print('=' * 55)

    INTERFACE = args.iface or input(
        '\n[?] Monitor-mode interface  (e.g. wlan0mon): '
    ).strip()
    if not INTERFACE:
        print('[ERROR] Interface is required.')
        sys.exit(1)

    OUTPUT_FILE = args.output

    # Scan-only mode: show nearby APs then exit without starting a capture
    if args.scan:
        scan_for_aps(INTERFACE, args.scan_duration)
        sys.exit(0)

    # If BSSIDs were passed on the command line we skip the interactive menu
    if args.bssid:
        FILTER_MODE          = 'bssid'
        TARGET_BSSIDS        = args.bssid
        MONITOR_CLIENTS_ONLY = args.clients_only
        print(f'\n[+] BSSID mode  |  {len(TARGET_BSSIDS)} target(s)  |  '
              f'clients-only={MONITOR_CLIENTS_ONLY}')
    else:
        configure_filtering()

    print('\n' + '-' * 55)
    print('  Capture Configuration')
    print('-' * 55)
    print(f'  Interface  : {INTERFACE}')
    print(f'  Mode       : {FILTER_MODE.upper()}')
    if TARGET_BSSIDS:
        print(f'  Targets    : {len(TARGET_BSSIDS)} BSSID(s)')
        for b in TARGET_BSSIDS:
            print(f'               - {b}')
    if MONITOR_CLIENTS_ONLY:
        print(f'  Focus      : client traffic only')
    print(f'  Fields     : {len(WIFI_FIELDS)}')
    print(f'  Output     : {OUTPUT_FILE}')
    print('-' * 55)

    confirm = input('\n[?] Start capture? (Y / n): ').strip().lower()
    if confirm == 'n':
        print('Aborted.')
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    initialize_csv()

    print(f'\n[*] Capturing on {INTERFACE}...')
    print(f'    Progress printed every 100 packets')
    print(f'    Press Ctrl+C to stop\n')

    try:
        sniff(iface=INTERFACE, prn=packet_handler, store=False)
    except PermissionError:
        print('[ERROR] Permission denied - confirm the interface is in monitor mode.')
        sys.exit(1)
    except OSError as e:
        print(f'\n[ERROR] Capture failed: {e}')
        print('\n  Troubleshooting:')
        print('    iwconfig                          - list interfaces')
        print('    sudo airmon-ng check kill          - stop conflicting services')
        print('    sudo airmon-ng start wlan0         - enable monitor mode')
        print('    iwconfig wlan0mon                  - verify monitor mode is active')
        sys.exit(1)


if __name__ == '__main__':
    main()

