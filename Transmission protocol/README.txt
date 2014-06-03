David Mather
ee122-he

Anthony Sun
ee122-jv

challenge:5

time: 6 hours

EC2: Selective Acknowledgement
Prevents resending of packets by acknowledging packets other than the next packet recieved.
The recieve sends an ack packet containing, first, the sequence number of the next expected packet (based on the original receiver), and then the sequence number of all received packets after that.

EC3: RTT based timeout
Adjusted the timeout based on the RTT.
The start time of each packet is recorded, and the RTT is measured when they are received. The average of the last few RTTs is averaged, and the timeout is set to RTT*2+10ms.