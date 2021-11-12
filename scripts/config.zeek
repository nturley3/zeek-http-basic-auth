## Determines whether to record the password used during basic authentication in the HTTP log.
redef HTTP::default_capture_password = T;


## Determines whether to check just inbound traffic or also include outbound traffic.
## Set this to True if you only want to check traffic destined to your define local networks regardless of origin.
## Set this to false if you want to check traffic destined to any network regardless of origin.
## Recommend setting this to "T" to consume fewer resources for Zeek clusters, but "F" if running on a pcap file. 
const check_only_local_net: bool = F;

