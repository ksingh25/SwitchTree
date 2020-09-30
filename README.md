# SwitchTree
Detection of network attacks using Random Forests

Please cite this paper if you use this code:

`Jong-Hyouk Lee and Kamal Singh, "SwitchTree: In-network Computing and Traffic Analyses with Random Forests", Neural Computing and Applications (2020)`
 
We perform in-network analysis of the network data by exploiting the power of programmable data plane. 
SwitchTree embeds Random Forest algorithm inside a programmable switch such that the 
Random Forest is configurable and re-configurable at runtime. We show how some flow level 
stateful features can be estimated, such as the round trip time and bitrate of each flow. 

To run the code
1. Use or Create a BMv2 VM or machine. Debugging should be disabled otherwise several packets will be lost. (Todo: provide a script to install BMVv2 environment)
2. Copy the switchtree folder to tutorials/exercises/ folder
3. cd to switchtree folder 
4. `make`
5. Add rules to P4 switch by 

`simple_switch_CLI < commands_1_tree.txt`
6. Send the traffic using tcpreplay. A demo test file containing 1000 packets is provided in demo_data. It is extracted from UNSW database.

`sudo tcpreplay -i s1-eth1 UNSW_1000_packets.pcap`
7. To obtain results, you make check the counter values. The number of malware flows injected (tracked using other means for statistics) is provided by counter_malware_flows and 
the actually detected ones are provided by counter_true_detection_flows. 

`simple_switch_CLI < get_results.txt`



To use SwitchTree with 3 trees: 

`cp  switchtree.3trees switchtree.p4`
`make clean`
`make`
`simple_switch_CLI < commands_3_trees.txt`

Note you may need to exit and type make again to reinitialize and do a new test with new data. 
