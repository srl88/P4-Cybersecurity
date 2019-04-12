# P4-Cybersecurity

To Install:
- Follow the instructions from the P4.org
link: https://p4.org/events/2018-06-06-p4-developer-day/

To Run:
- The code was tested from the following location: home/p4/tutorials/PD4D2_2018_East/exercises/_your_folder
  You can also modify the make me file 
- Copy and paste any folder along with the python script folder into the execrises directory.
- Open the terminal inside the folder and type: make run

To exit:
- From mininet: exit
- Delete folders: make clean

RATE FILES:
- Run mininet.
- xterm h1 to open the terminal for host 1 

|| IMPORTANT || 
The rates folders were only tested from h1 to h2. Also, the ping functionallity will not work since there is only one switch 
with two hosts.
||DONE IMPORTANT||

- Throughput was tested using Wireshark listening to the second interface of the swicth (tracffick from h1->h2)

- In the terminal for h1 run: ./send.py 10.0.1.2 <Number of packers for 10 procceses>

TOPOLOGY WITHOUT FIREWALL FILES:

- Run mininet and ping from h1 to any host

|| IMPORTANT || 
The ping was only tested from h1 to h2 (1 hop), h10 (5 hops), h23(10 hops)
||DONE IMPORTANT||

TOPOLOGY WITH FIREWALL FILES:

- Run mininet and ping from h1 to any host

|| IMPORTANT || 
The ping was only tested from h1 to h2 (1 hop), h10 (5 hops), h23(10 hops)
||DONE IMPORTANT||

FIREWALL CONCEPT FILE:

- Run mininet.
- Make sure wireshark is listening to the interface 2 of the swicth
- xterm h1
- ./python.py 10.0.1.2 <Number of packers for 10 procceses>.  (Same IP)
Or
- ./send_different.pu 10.0.1.2. (Different IP's)

|| IMPORTANT || 
If wireshark is not installed in your system you can use the receive.py file in the h2 terminal
||DONE IMPORTANT||
