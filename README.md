# SwitchTree
In-Network detection of attacks using Random Forests

Please cite this paper if you use this code:

`Jong-Hyouk Lee and Kamal Singh, "SwitchTree: In-network Computing and Traffic Analyses with Random Forests", Neural Computing and Applications (2020)`
 
We perform in-network analysis of the network data by exploiting the power of programmable data planes. 
SwitchTree coded in P4 embeds Random Forest algorithm inside a programmable switch such that the 
Random Forest is configurable and re-configurable at runtime. We show how some flow level 
stateful features can be estimated, such as the round trip time and bitrate of each flow. 
Main references for this work are [IISY](https://github.com/cucl-srg/IIsy) and [pForest](https://arxiv.org/abs/1909.05680).

# Quick Start Guide
To run the code
1. Use or Create a BMV2 VM or machine. For example you may download the VM from here provided by P4 developer day: https://drive.google.com/uc?id=1lYF4NgFkYoRqtskdGTMxy3sXUV0jkMxo&export=download
2. Debugging and logging should be disabled otherwise several packets will be lost during real-time tests. This can be done by downloading the source of behavioral-model (https://github.com/p4lang/behavioral-model) and recompiling it using the options that disable logging
`cd behavioral-model/
sudo ./configure 'CXXFLAGS=-g -O3' 'CFLAGS=-g -O3' --disable-logging-macros --disable-elogger
sudo make
sudo make install`

3. Copy the switchtree folder to tutorials/exercises/ folder
4. cd to switchtree folder 

4. `make`

5. Open a new terminal and cd to tutorials/exercises/switchtree folder. Add rules (trained Decision Trees were translated to SwitchTree P4 rules using a script) to P4 switch by 

`simple_switch_CLI < commands_1_tree.txt`

6. Send the traffic using tcpreplay. A demo test file containing 1000 packets is provided in demo_data. It is extracted from UNSW database.

`sudo tcpreplay -i s1-eth1 demo_data/UNSW_1000_packets.pcap`

7. To obtain results, you make check the counter values. The number of malware flows injected (tracked using other means for statistics) is provided by counter_malware_flows and 
the actually detected ones are provided by counter_true_detection_flows. 

`simple_switch_CLI < get_results.txt`



To use SwitchTree with 3 trees: 

`cp  switchtree.3trees switchtree.p4`

`make clean`

`make`

`simple_switch_CLI < commands_3_trees.txt`

Note you may need to exit and type make again to reinitialize and do a new test with new data. 
