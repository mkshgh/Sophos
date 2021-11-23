# Dependencies
import xml.etree.ElementTree as ET
import csv
import sys
# Input: xml file exported from the vsphere firewall rules
# Output: csv file exported to csv
# sys.argv[1] takes input from the file
def sxml2csv(xml_locaion:str=sys.argv[1],ouput_csv:str=''):
    # location for output csv
    ouput_csv = xml_locaion.split('.')[0]+'.csv'

    # creating a tree of the xml file
    tree = ET.parse(xml_locaion)
    # the third node has the index of the config
    # the second node of config has the sections that we want
    # [0][0]
    root = tree.getroot()
    print(root.tag)
    
    # Total rules in the sophos
    total = len(root.findall('FirewallRule'))
    # Data frame
    network_policy_nested = ['SourceZones','DestinationZones','SourceNetworks','DestinationNetworks','Identity']
    header = ['Name','Description','Status']
    User_Network_Policy = ['Action','LogTraffic','MatchIdentity','WebFilter','ApplicationControl']

    with open(ouput_csv,"w", newline="") as csv_write:
        writer = csv.writer(csv_write)
        writer.writerow(['Name','Description','Status','SourceZones','DestinationZones','SourceNetworks','DestinationNetworks','Identity','Action','LogTraffic','MatchIdentity','WebFilter','ApplicationControl'])
        for firewallrules in root.findall('FirewallRule'):
            # Store the data to store in the csv here
            csv_data = []
            # This adds the ['Name','Description','Status']
            for data in header:
                csv_data.append(firewallrules.find(data).text)

            # If you enter except group it means that the data has more nodes nested in
            # This only loops ['SourceZones','DestinationZones','SourceNetworks','DestinationNetworks','Identity']
            for data in network_policy_nested:
                # store the array temporarily
                temp_arr = []
                # For handling the Error when looping None data type
                try:
                    for temp in firewallrules[-1].find(data):
                        temp_arr.append(temp.text)
                    csv_data.append(temp_arr)
                except TypeError:
                    # there might be no data in the source
                    csv_data.append('Any')

            # This contains the Network or the policy rules
            for data in User_Network_Policy:
                # the last item is the UserPolicy or the NetworkPolicy 
                # This adds these ['Action','LogTraffic','MatchIdentity','WebFilter','ApplicationControl']
                try:
                    csv_data.append(firewallrules[-1].find(data).text)
                except:
                    csv_data.append('None')

            writer.writerow(csv_data)

# print('start') 
# enter the xml file name here 
# put the file in the same directory for now
sxml2csv()
# print('finish')
