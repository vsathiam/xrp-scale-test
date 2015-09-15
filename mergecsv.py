from glob import glob
import os, time, csv


def generate_singlecsv(csvinputfilepath, csvoutputfilepath):
    
    '''
    Combine several CSV files (generated from output of show stations executed
    on several WAPs) into a single CSV file
    Add Columns - Timestamp, AP_IP, 2.4GHz Stations, 5GHz Stations and populate the rows from CSV files
    '''
   
    timestring = time.strftime("%m.%d.%y.%H.%M.%S", time.localtime())
    csvinputfile = os.path.join(csvinputfilepath, "WAP-sta-count-*.csv")
    csvoutputfile = os.path.join(csvoutputfilepath, "Combined-"+timestring+".csv")
    rows = ["Timestamp", "AP_IP", "2.4GHz Stations", "5GHz Stations"]
    
    print "CSV IN",csvinputfile, "CSV OUT", csvoutputfile
    
    with open(csvoutputfile, 'a') as singlefile:
        writer = csv.writer(singlefile,delimiter=',', quoting=csv.QUOTE_MINIMAL)
        writer.writerow(rows)
    
    with open(csvoutputfile, 'a') as singlefile:   
        for csvFile in glob(csvinputfile):
            f = open(csvFile, "r")
            f.next()
            for line in f:
                singlefile.write(line)
                

generate_singlecsv("/Users/vsathiam/Documents/LOGS", "/Users/vsathiam/Documents/LOGS/combined")