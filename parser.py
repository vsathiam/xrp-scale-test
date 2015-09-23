# Assumes the output file is already in the folder
from math import floor
import json
import sys,csv
import time

class parser:
    """ A class to extract any useful information from the iperf3
    json output. Then users can access whatever fields they
    are interested in. """

    def __init__(self,startTime):
        self.bps = 0
        self.bytes = 0
        self.runLength = 0
        self.intervalBPS = []
        self.intervalSeconds = []
        self.intervalLength = 0
        self.hostUtilization = 0
        self.remoteUtilization = 0
        self.startTime = startTime
        self.streamTime = 0
    
    def write_csv(self,filename,rows):
            '''
            Write CSV file containing results of TOP
            '''
        
            with open(filename, "ab") as csv_file:
                writer = csv.writer(csv_file,delimiter=',', quoting=csv.QUOTE_MINIMAL)
                writer.writerow(rows)
    

    def extract(self, efile):
        csv_row_header = ["Timestamp", "Bandwidth"]
        csv_row_values = []
        writecsvfile = efile.split('.json')[0]+"--extract.csv"
        self.write_csv(writecsvfile, csv_row_header)
        
        with open(efile) as dataFile:
            data = json.load(dataFile)
        
        
        #self.bps = data['end']['sum_received']['bits_per_second']
        #self.bytes = data['end']['sum_received']['bytes']
        #self.runLength = data['end']['sum_received']['seconds']
        #self.hostUtilization = data['end']['cpu_utilization_percent']['host_total'] / 100.0
        #self.remoteUtilization = data['end']['cpu_utilization_percent']['remote_total'] / 100.0
        #self.intervalLength = floor(data['intervals'][0]['sum']['seconds'])
        for i in xrange(len(data['intervals'])):
            #self.intervalBPS.append(data['intervals'][i]['sum']['bits_per_second'])
            
            for j in data['intervals'][i]['streams']:
                #self.intervalSeconds.append(j['end'])
                self.streamTime = floor(self.startTime + j['end'])
                modified = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(self.streamTime))
                csv_row_values.append(modified)
                csv_row_values.append(data['intervals'][i]['sum']['bits_per_second'])
                self.write_csv(writecsvfile, csv_row_values)
                self.streamTime = 0
                csv_row_values = []