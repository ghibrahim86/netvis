                                NetVis (Beta)

                              Yujia Li, 12/2012

------------------------------------------------------------------------------

To run the program, copy pox_netvis.py and ext directory to $POX_HOME$,
where $POX_HOME$ is the root directory for pox.  Start NetVis in $POX_HOME$
using command

    ./pox_netvis.py --no_cli net_discovery

Then you can test the program on different network structures using Mininet.
For example, the following command will start a network with 3 switches
connected in a chain, and each switch has a host attached to it:

    sudo mn --topo linear,3

After the network is set up, you can see NetVis already detected all the
switches.  Then go back to the CLI interface of Mininet and do a pingall test.
Now NetVis should have detected all hosts and connections.

myminiedit is a nice tool to customize your own network in Mininet. You can
start it by
    
    sudo python myminiedit.py

In myminiedit, you can create your own network by adding switches, hosts and
links.  After you finished editing, you can run the network and start CLI by
clicking the 'Run' botton.  Then when the network is started up, you can do a
pingall test. NetVis should be able to detect all components in your network
by then.

Note that NetVis should be restarted before testing a new network. This
problem may be resolved in a future version.


