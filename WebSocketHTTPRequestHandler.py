#!/usr/bin/python2

import BaseHTTPServer
import base64
import hashlib
import logging
import struct
import threading

log = logging.getLogger(__name__)

class WebSocketError(Exception):
    pass

class ProtocolError(WebSocketError):
    def __init__(self, message):
        self.message = message
        self.code = 1002

class TextPayloadError(WebSocketError):
    def __init__(self, message):
        self.message = message
        self.code = 1007

class WebSocketHTTPRequestHandler(BaseHTTPServer.BaseHTTPRequestHandler):

    """WebSocket capable HTTP request handler.

    This is handler is normally acting as standard BaseHTTPRequestHandler,
    but is capable of handling HTTP upgrade to WebSocket (RFC 6455) requests.

    To switch the connection to WebSocket connection, one has to call
    ws_handshake() method in its own do_GET() implementation,
    most likely responding to a specific URL.

    Received messages should be handled by overloading ws_text_received()
    and/or ws_binary_received() methods.
    
    Send messages with ws_text_send() and ws_binary_send() methods."""
    
    def ws_handshake(self):
        log.debug('WS: awaiting handshake')
        try:
            connection = [v.strip().lower() for v in self.headers.get('Connection').split(',')]
            if 'upgrade' not in connection:
                raise RuntimeError
            if 'keep-alive' not in connection:
                log.warning('WS: expected keep-alive in connection header')
            if self.headers.get('Upgrade', '').lower() != 'websocket':
                raise RuntimeError
            key = self.headers.get('Sec-WebSocket-Key')
            hash = hashlib.sha1(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11').digest()
            accept = base64.b64encode(hash)
        except:
            self.send_error(400)
            return
        self.send_response(101)
        self.send_header('Upgrade', 'websocket')
        self.send_header('Connection', 'Upgrade')
        self.send_header('Sec-WebSocket-Accept', accept)
        self.end_headers()
        self.close_connection = 0
        self.ws_connection = True
        log.debug('WS: initiated connection')

    def ws_text_received(self, message):
        log.warning('WS: ignoring text message "%s"' % message)

    def ws_binary_received(self, message):
        log.warning('WS: ignoring binary message "%s"' % message)

    def ws_text_send(self, message):
        if not isinstance(message, str) and not isinstance(message, unicode):
            raise TypeError('String expected')
        payload = message.encode('utf-8')
        self.ws_send_frame(self.OPCODE_TEXT_FRAME, len(payload), payload)

    def ws_binary_send(self, message):
        if not isinstance(message, bytes):
            raise TypeError('Byte array expected')
        self.ws_send_frame(self.OPCODE_BINARY_FRAME, len(message), message)



    def ws_handle_one_message(self):
        try:
            log.debug('WS: awaiting message')
            (h1, h2) = struct.unpack('!BB', self.rfile.read(2))
            fin = h1 & self.FIN
            opcode = h1 & self.__OPCODE
            mask = h2 & self.MASK
            payload_len = h2 & self.__PAYLOAD_LEN
            if payload_len == self.PAYLOAD_EXTENDED_16:
                (payload_len, ) = struct.unpack('!H', self.rfile.read(2))
            elif payload_len == self.PAYLOAD_EXTENDED_64:
                (payload_len, ) = struct.unpack('!Q', self.rfile.read(8))
            if mask:
                masking_key = bytearray(self.rfile.read(4))
            else:
                raise ProtocolError('WS: received non masked frame from client')

            masked_payload = bytearray(self.rfile.read(payload_len))
            mask = (masking_key * ((payload_len + 4) / 4))[:payload_len]
            payload = bytearray(a ^ b for a, b in zip(masked_payload, mask))
            log.debug('WS: received%sframe opcode 0x%02x, payload length %d, payload "%s", masking key 0x%04x' % (' final ' if fin else ' ', opcode, payload_len, payload, struct.unpack('!I', masking_key)[0]))

            if opcode == self.OPCODE_CONTINUATION_FRAME:
                log.debug('WS: continuation frame received')
                self.ws_payload += payload
            elif opcode == self.OPCODE_TEXT_FRAME:
                log.debug('WS: text frame received')
                self.ws_text = True
                self.ws_payload = payload
            elif opcode == self.OPCODE_BINARY_FRAME:
                log.debug('WS: binary frame received')
                self.ws_text = False
                self.ws_payload = payload
            elif opcode == self.OPCODE_CONNECTION_CLOSE_FRAME:
                log.debug('WS: connection close frame received')
                code = None
                if payload_len > 0:
                    if payload_len >= 2:
                        (code, ) = struct.unpack('!H', payload[:2])
                        log.debug('WS: received connection close code %d' % code)
                    else:
                        raise ProtocolError('WS: connection close frame payload should contain code')
                if not fin:
                    raise ProtocolError('WS: fragmented connection close frame')
                if payload_len > 125:
                    raise ProtocolError('WS: connection close frame payload too long')
                self.ws_close_connection(code)
                return
            elif opcode == self.OPCODE_PING_FRAME:
                log.debug('WS: ping frame received')
                if not fin:
                    raise ProtocolError('WS: fragmented ping frame')
                if payload_len > 125:
                    raise ProtocolError('WS: ping frame payload too long')
                self.ws_send_frame(self.OPCODE_PONG_FRAME, payload_len, payload)
                return
            elif opcode == self.OPCODE_PONG_FRAME:
                log.debug('WS: pong frame received')
                if not fin:
                    raise ProtocolError('WS: fragmented pong frame')
                if payload_len > 125:
                    raise ProtocolError('WS: pong frame payload too long')
                return
            else:
                raise ProtocolError('WS: unknown opcode 0x%02x' % opcode)
 
            if fin:
                if self.ws_text:
                    try:
                        self.ws_text_received(self.ws_payload.decode('utf-8'))
                    except UnicodeDecodeError:
                        raise TextPayloadError('WS: non-UTF-8 text payload')
                else:
                    self.ws_binary_received(self.ws_payload)

        except WebSocketError as e:
            log.warning(e.message)
            self.ws_close_connection(e.code)
            return

    def ws_send_frame(self, opcode, payload_len, payload):
        log.debug('WS: sending frame opcode 0x%02x, payload length %d, payload "%s"' % (opcode, payload_len, payload))
        self.ws_send_lock.acquire(True)
        self.request.send(struct.pack('!B', self.FIN | (opcode & self.__OPCODE)))
        if payload_len <= 125:
            self.request.send(struct.pack('!B', payload_len & self.__PAYLOAD_LEN))
        elif payload_len <= 0xffff:
            self.request.send(struct.pack('!BH', self.PAYLOAD_EXTENDED_16, payload_len))
        else:
            if payload_len > 0xffffffffffffffff:
                log.warning('WS: payload longer than 2^64 bytes? forget it, mate!')
                payload_len &= 0xffffffffffffffff
                payload = payload[:payload_len]
            self.request.send(struct.pack('!BQ', self.PAYLOAD_EXTENDED_64, payload_len))
        if payload_len > 0:
            self.request.send(payload)
        self.ws_send_lock.release()

    def ws_close_connection(self, code=1000):
        log.debug('WS: closing connection with code %s' % ('%d' % code if code else 'undefined'))
        if code:
            self.ws_send_frame(self.OPCODE_CONNECTION_CLOSE_FRAME, 2, struct.pack('!H', code))
        else:
            self.ws_send_frame(self.OPCODE_CONNECTION_CLOSE_FRAME, 0, None)
        self.close_connection = 1



    def handle(self):
        """Handle multiple HTTP and WebSocket requests if necessary.""" 
        self.close_connection = 1
        self.ws_connection = False
        self.ws_send_lock = threading.Lock()

        self.handle_one_request()
        while not self.close_connection:
            if self.ws_connection:
                self.ws_handle_one_message()
            else:
                self.handle_one_request() 

    # Header byte 1
    FIN = 0x80 
    __OPCODE = 0x0f
    OPCODE_CONTINUATION_FRAME = 0x00
    OPCODE_TEXT_FRAME = 0x01
    OPCODE_BINARY_FRAME = 0x02
    OPCODE_CONNECTION_CLOSE_FRAME = 0x08
    OPCODE_PING_FRAME = 0x09
    OPCODE_PONG_FRAME = 0x0a
    # Header byte 2
    MASK = 0x80
    __PAYLOAD_LEN = 0x7f
    PAYLOAD_EXTENDED_16 = 126
    PAYLOAD_EXTENDED_64 = 127



class WebSocketHTTPRequestHandlerExample(WebSocketHTTPRequestHandler):

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write("""
<html>

<head>
    <title>WebSocketHTTPRequestHandlerExample</title>

    <script type="text/javascript">
        var ws;
    
        function connect()
        {
            ws = new WebSocket("ws://" + window.location.host + "/ws");

            ws.onopen = function()
            {
                log("opened connection to '" + ws.url + "'");
            };
      
            ws.onmessage = function(message)
            {
                log("received message '" + message.data + '"');
            };
      
            ws.onclose = function()
            {
                log("closed connection");
            };

            ws.onerror = function(message)
            {
                log("error '" + message + "'");
            };
            
            document.getElementById("connect").disabled = true;
            document.getElementById("disconnect").disabled = false;
            document.getElementById("send").disabled = false;
            document.getElementById("message").select();
        }
    
        function disconnect()
        {
            ws.close()

            document.getElementById("connect").disabled = false;
            document.getElementById("disconnect").disabled = true;
            document.getElementById("send").disabled = true;
        }

        function send()
        {
            var message = document.getElementById("message");
            log("sending message '" + message.value + "'");
            ws.send(message.value);
            message.select();
        }

        function log(message)
        {
            document.body.appendChild(document.createTextNode(message));
            document.body.appendChild(document.createElement("br"));
            window.scrollTo(0, document.body.scrollHeight + 20);
        }
    </script>
</head>

<body onLoad="connect()" style="padding-top: 150px">
    <div style="position: fixed; top: 0; padding: 20px; background: white; width: 100%">
        <button id="connect" onClick="connect()">connect</button>
        <button id="disconnect" onClick="disconnect()">disconnect</button>
        <br/>
        <br/>
        <input id="message" type="text" onkeydown="if (event.keyCode==13) send()">
        <button id="send" onClick="send()">send text message</button>
    </div>
</body>

</html>
""")
        elif self.path == '/ws':
            self.ws_handshake()
            print('Started WebSocket connection to the client')
        else:
            self.send_error(404)

    def ws_text_received(self, message):
        response = message.swapcase()
        print('Received text "%s" from the client, sending "%s" back' % (message, response))
        self.ws_text_send(response)

    def ws_binary_received(self, message):
        response = bytearray(a ^ 0xff for a in message)
        print('Received binary "%s" from the client, sending "%s" back' % (message, response))
        self.ws_binary_send(response)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    server = BaseHTTPServer.HTTPServer(('', 6767), WebSocketHTTPRequestHandlerExample)
    server.serve_forever()
