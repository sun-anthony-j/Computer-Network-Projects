import sys
import getopt
import time
import Checksum
import BasicSender
import random

'''
This is a skeleton sender class. Create a fantastic transport protocol here.
'''
class Sender(BasicSender.BasicSender):
    def __init__(self, dest, port, filename, debug=False):
        super(Sender, self).__init__(dest, port, filename, debug)
        self.timeout = 0.5
        self.window_size = 5


        # Handles a response from the receiver.
    def handle_response(self,response_packet):
        if Checksum.validate_checksum(response_packet):
            # print "recv: %s" % response_packet
        else:
            # print "recv: %s <--- CHECKSUM FAILED" % response_packet

    # Main sending loop.
    def start(self):

        rtt_history = []

        window = []

        dupes = {}

        seqno = 0

        msg_type = None
        breakout = False

        refill = self.window_size

        endFound = False

        # Main Loop
        while True:

            i = 0

            # If we haven't hit the EOF
            if not endFound:

                # Fill the window with all of the packets that it can fit
                while i < refill:

                    msg = self.infile.read(500)
                    if seqno == 0:
                        msg_type = 'start'
                    elif msg == "":
                        msg_type = 'end'
                    else:
                        msg_type = 'data'

                    window.append({"msg_type": msg_type, "seqno": seqno, "msg": msg, "ACK": False, "sent": False, "timeout": False, "send_time": -1})
                    seqno += 1
                    i += 1
                    if msg_type == 'end':
                        endFound = True
                        break

            refill = 0
            # For all of the messages to send
            for m in window:

                # Make a packet

                packet = self.make_packet(m["msg_type"],m["seqno"],m["msg"])

                # If current time - the time we sent it is > time out, it timed.
                if m["send_time"] is not -1:
                    if time.time() - m["send_time"] >= self.timeout:
                        m["timeout"] = True

                # If it hasen't been sent, or it timed out
                if not m["sent"] or m["timeout"]:
                    if random.random() > 0.0:
                        self.send(packet)

                        m["send_time"] = time.time()
                        m["timeout"] = False
                        m["sent"] = True

                        # print "sent: %s:%d" % (m["msg_type"], m["seqno"])
                    else:
                        # print "random dropped %s:%d" % (m["msg_type"], m["seqno"])
                        m["send_time"] = time.time()
                        m["timeout"] = False
                        m["sent"] = True

            # Recieve response
            response = self.receive(self.timeout)
            recv_time = time.time()

            # print "recvd: %s" % response

            if response != None:

                resp = []
                valid = True

                # Doesn't Checksum due to checksum implementation not working with Modified Reciever.

                if not Checksum.validate_checksum(response):
                    valid = False

                # print valid
                if valid:
                    j = 1

                    # Iterate throw selective ack
                    while j < len(response.split('|')) - 1:

                        x = response.split('|')[j]
                        # Not a nil space in Selective Ack
                        if x != '':

                            r_temp = {"ack": True, "ack_num": int(x), "response": response, "valid": valid, "recv_time": recv_time, "seen": 1}
                            
                            resp.append(r_temp)
                            if j == 1:
                                if not ((r_temp["ack_num"]) in dupes):
                                    dupes = {}
                                    dupes[r_temp["ack_num"]] = 1
                                else:
                                    dupes[r_temp["ack_num"]] += 1
                                    if dupes[r_temp["ack_num"]] == 3:
                                        for m in window:
                                            if m["seqno"] == dupes.keys()[0]:
                                                m["sent"] = False
                                                m["timeout"] = False
                                                m["send_time"] = -1
                                        dupes[r_temp["ack_num"]] = 0
                        
                        # Increment Loop
                        j += 1

                    for r in resp:
                        r_ack = r["ack_num"]
                        if resp.index(r) == 0:
                            r_ack -= 1
                        for m in window:
                            if r_ack == m["seqno"]:

                                # Packet is acknowledged
                                m["ACK"] = True

                                # Handle end
                                if m["msg_type"] == "end":
                                    breakout = True
                                window.remove(m)
                                refill += 1

                if breakout == True:
                    break

    # def handle_timeout(self):
        
    #     return True 

    # def handle_new_ack(self, ack):

    #     return True

    # def handle_dup_ack(self, ack):
    #     pass

    def log(self, msg):
        if self.debug:
            # print msg

'''
This will be run if you run this script from the command line. You should not
change any of this; the grader may rely on the behavior here to test your
submission.
'''
if __name__ == "__main__":
    def usage():
        # print "BEARS-TP Sender"
        # print "-f FILE | --file=FILE The file to transfer; if empty reads from STDIN"
        # print "-p PORT | --port=PORT The destination port, defaults to 33122"
        # print "-a ADDRESS | --address=ADDRESS The receiver address or hostname, defaults to localhost"
        # print "-d | --debug Print debug messages"
        # print "-h | --help Print this usage message"

    try:
        opts, args = getopt.getopt(sys.argv[1:],
                               "f:p:a:d", ["file=", "port=", "address=", "debug="])
    except:
        usage()
        exit()

    port = 33122
    dest = "localhost"
    filename = None
    debug = False

    for o,a in opts:
        if o in ("-f", "--file="):
            filename = a
        elif o in ("-p", "--port="):
            port = int(a)
        elif o in ("-a", "--address="):
            dest = a
        elif o in ("-d", "--debug="):
            debug = True

    s = Sender(dest,port,filename,debug)
    try:
        s.start()
    except (KeyboardInterrupt, SystemExit):
        exit()
