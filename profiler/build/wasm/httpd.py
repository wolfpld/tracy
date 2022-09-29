from http import server

class MyHTTPRequestHandler(server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_my_headers()
        server.SimpleHTTPRequestHandler.end_headers(self)

    def send_my_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        self.send_header("Pragma", "no-cache")
        self.send_header("Expires", "0")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp");
        self.send_header("Cross-Origin-Opener-Policy", "same-origin");


if __name__ == '__main__':
    server.test(HandlerClass=MyHTTPRequestHandler)
