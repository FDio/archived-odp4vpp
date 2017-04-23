##odp4vpp:

#Introduction:
------------

odp4vpp project aims to provide VPP with an additional vnet device based on OpenDataPlane (ODP is similar yet different from DPDK), with provisions for hardwareacceleration of packet paths. It envisions three deployment scenarios:

-Server + NICs
-Systems on a Chip
-SmartNIC with low to very high core count

#Build Procedure:
----------------

The source code add support to build VPP with either odp-linux or odp-dpdk.

1) Build vpp with odp-linux:

Build the odp linux package by compiling odp from odp git repository:

git clone https://git.linaro.org/lng/odp.git

Follow the README steps for complete build.

cd odp
./bootstrap
./configure --prefix= <odp-path>
make install

Set the environment variables with ODP config:

export PLATFORM=odp
export ODP_INST_PATH=<odp-path>

Build vpp:

Follow the README steps for complete build.

cd vpp
make install-dep
make build
make run

2) Build vpp with odp-dpdk:

Build the odp-dpdk package by compiling odp-dpdk from odp-dpdk git repository:

git clone https://git.linaro.org/lng/odp-dpdk.git

Follow the README.DPDK steps for complete build with dpdk.

cd odp-dpdk
./bootstrap
./configure --prefix= <odp-dpdk-path> --with-sdk-install-path=<dpdk-dir>/x86_64-native-linuxapp-gcc
make install

Set the environment variables with ODP config:

export PLATFORM=odp
export ODP_INST_PATH=<odp-dpdk-path>

Note : Also check and copy dpdk/odp-dpdk libraries to default /usr/lib path for linking with vpp.

Build vpp:

Follow the README steps for complete build.

cd vpp
make install-dep
make build
make run

#Test Steps:
------------

Below is a basic verification test.

Note :For odp-dpdk the port has to bound with dpdk driver prior to test and interface name is passed as 0,1..etc.

1)Configure odp packet interface with mode ie (0-burst,1-queue,2-schedule) default mode is 0.

-create pktio-interface name <int name> hw-addr <mac> mode <0/1/2>
-set int ip address odp-<int name> X.X.X.X/24
-set int state odp-<int name> up

2)Check the interface state:
-sh int

3)Ping the configured interface from host machine and check the ARP and ipv4 FIB table:
-sh ip arp
-sh ip fib

4)Check the interface counters:
-sh int

5)Check the statistics:
-show run

6)Packet trace can be enabled using :
-trace add odp-packet-input 10
-show trace

7)Delete the interface:
-delete pktio-interface name <int name>


Example:
-------

Below is example config logs:

with odp-linux:

DBGvpp# create pktio-interface name enp0s8 hw-addr 08:00:27:1b:5e:48
odp-enp0s8
DBGvpp# set int ip address odp-enp0s8 192.168.1.4/24
DBGvpp# set int state odp-enp0s8 up
DBGvpp# sh int
              Name               Idx       State          Counter          Count
local0                            0        down
odp-enp0s8                        1         up       rx packets                     1
                                                     rx bytes                      60
                                                     drops                          1
DBGvpp# sh int addr
local0 (dn):
odp-enp0s8 (up):
  192.168.1.4/24
DBGvpp# sh int
              Name               Idx       State          Counter          Count
local0                            0        down      drops                          1
odp-enp0s8                        1         up       rx packets                    12
                                                     rx bytes                     902
                                                     tx packets                     5
                                                     tx bytes                     324
                                                     drops                          4
                                                     punts                          3
                                                     ip4                            7
DBGvpp# sh ip arp
    Time           IP4       Flags      Ethernet              Interface
    171.7151   192.168.1.1     D    c8:3a:35:19:ea:f0        odp-enp0s8
    185.0099   192.168.1.3     D    48:45:20:11:41:ad        odp-enp0s8
DBGvpp#

with odp-dpdk:

sreejith@sreejith-VirtualBox:~/vppdodp/vpp_odp_dpdk/dpdk$ sudo ./usertools/dpdk-devbind.py --status

Network devices using DPDK-compatible driver
============================================
0000:00:08.0 '82540EM Gigabit Ethernet Controller' drv=igb_uio unused=e1000
0000:00:09.0 '82540EM Gigabit Ethernet Controller' drv=igb_uio unused=e1000


DBGvpp# create pktio-interface name 0 hw-addr 08:00:27:1b:5e:48
odp-0
DBGvpp# sh int
              Name               Idx       State          Counter          Count
local0                            0        down
odp-0                             1        down

DBGvpp# set int ip address odp-0 192.168.1.4/24
DBGvpp# set int state odp-0 up
DBGvpp# sh int
              Name               Idx       State          Counter          Count
local0                            0        down
odp-0                             1         up       rx packets                    13
                                                     rx bytes                    1960
                                                     tx packets                     1
                                                     tx bytes                      42
                                                     drops                         13
                                                     ip4                            7
                                                     ip6                            4


