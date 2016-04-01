This handler is normally acting like a standard BaseHTTPRequestHandler, but is capable of handling HTTP upgrade to WebSocket (RFC 6455) requests. To switch the connection to WebSocket connection, one has to call ws_handshake() method in its own do_GET() implementation, most likely responding to a specific URL.

Received messages should be handled by overloading ws_text_received() and/or ws_binary_received() methods.

Send messages with ws_text_send() and ws_binary_send() methods.
