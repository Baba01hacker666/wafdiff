import http.server
import socketserver

PORT = 8001

class MockWAFHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # Inconsistent behavior simulation
        # /api/ -> blocks SQLi with 403
        # /login -> blocks SQLi with 200 but different length
        # /search -> allows SQLi with 200
        
        import urllib.parse
        path = urllib.parse.unquote(self.path)
        if "1=1" in path:
            if "/api/" in path:
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"WAF Blocked")
            elif "/login" in path:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"WAF Blocked but 200 ok")
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"Normal Search Results" * 10)
        else:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"OK")
            
    def do_POST(self):
        self.do_GET()

with socketserver.TCPServer(("", PORT), MockWAFHandler) as httpd:
    print("serving at port", PORT)
    httpd.serve_forever()
