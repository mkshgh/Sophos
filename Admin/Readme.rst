Sophos For Admins
===================


======================
sxml2csv.py
======================
**Extract Firewall Rules in CSV from xml**

.. code-block:: language

   # Only the firewall rules must be exported from sophos firewall else won't work
   python sxml2csv.py your_firewall_rules.xml
   
   # Outputs data in following format
   ['Name','Description','Status','SourceZones','DestinationZones','SourceNetworks','DestinationNetworks','Identity','Action','LogTraffic','MatchIdentity','WebFilter','ApplicationControl']
   .......
   ..
   .
