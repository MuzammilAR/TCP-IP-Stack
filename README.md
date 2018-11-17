# TCP-IP Stack
#### Authors: Muzammil Abdul Rehman, Fangfan Li

##### Note: 
Our makefile requires root access.

## High Level Overview of the approach:
We developed a TCP-IP stack that allows you to send and recieve HTTP(200) packets and output them to a file.
A connection loss occurs after 3 minutes while a packect timeout occurs after 10 seconds. Each TCP and IP header is validated for checksum.
We use two sockets. The send and the recieve sockets generally run in separate threads and communicate using threading locks 
First our client initiates a TCP handshake and tries for 3 times(with exponential backoff interval) to connect to the server.
The server sends the client a Syn-Ack. We then send a Syn with the GET request of the requested filename and start recieving TCP packets.
We run in a promiscous mode. So all the packets from any other destination other than our requested server are discarded.
The packets are validated at IP level by using the checksum, as well as the source and the destination IP addresses.
These are then validated at the TCP layer by using SYN and ACK numbers, respective flags, port numbers and the hash of the psuedo headers. 
Duplicates are discarded. All the data from server to TCP layer is stored in a buffer and ordered. A temporary buffer at HTTP layer is also maintained for presentation
and writing the data to the file.
Due to randomized SYN and ACK numbers and randomized client ports, it's highly improbable for two connections intiated to interfere in each other's communication. 
When the server finishes sending the data it sends a FIN bit which is recieved by our recieve socket, we send a FIN bit and close after some time.
Then we read the data from the application buffer, remove http headers and handle chunks, then we write it to a file.

## TCP-Features Implemented:
* Handshake
* Graceful Closure
* Psuedo headers and checksum
* Dynamincally varying a congestion window depending timeout and one duplicate ACK(AIMB approach with no slow start phase)
* Decrease sending pace if the reciever window decreases.
* Timeouts and connection loss.
* The MSS is 1420 bytes, instead of the 1460 bytes sent by the server

## Main Problems Faced:
* Not being able to work with SOCKSTREAM/IPPROTO_IP since STREAM requires an established connection on the other end.
* Computing checksum for odd number of bytes.
* Figuring out the problems related to extremely large packets because of Checksum Offload
* Handling HTTP's chunked encoding.

## Notes
Q: When we are trying to do wget on 2MB, etc logs, and the Packet size is too big and wget doesn't drop those packets even when its checksum is incorrect from the server (as seen from wireshark traces). 
Should we drop the packets with incorrect checksums in our code too?

A: The problem is as pointed, "maybe caused by tcp checksum offload", you can refer to this website for solution.
https://wiki.wireshark.org/CaptureSetup/Offloading

sudo ethtool --offload eth0 rx off tx off

sudo ethtool -K eth0 gso off

sudo ethtool -K eth0 gro off
