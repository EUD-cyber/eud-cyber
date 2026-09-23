#!/usr/bin/env python3

"""
Nordic Manufacturing A/S - Exfiltration Sink

Controlled HTTP receiver used by the CyberLab attack simulation.

Receives:
    POST /upload

Stores files in:
    /opt/nordic-attack/uploads/

This service is intended only for synthetic CyberLab data.
"""

import argparse
import hashlib
import os
import re
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


DEFAULT_PORT = 8088
DEFAULT_OUTPUT = "/opt/nordic-attack/uploads"
MAX_UPLOAD_SIZE = 50 * 1024 * 1024  # 50 MB


def safe_filename(name):
    """Remove unsafe characters from supplied filename."""

    name = os.path.basename(name)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", name)

    if not name:
        name = "upload.bin"

    return name


class UploadHandler(BaseHTTPRequestHandler):

    server_version = "NordicSink/1.0"

    def log_message(self, fmt, *args):
        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        print(
            f"{timestamp} | "
            f"{self.client_address[0]} | "
            f"{fmt % args}",
            flush=True,
        )

    def send_text(self, status, message):
        body = message.encode("utf-8")

        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

        self.wfile.write(body)

    def do_GET(self):

        if self.path == "/health":
            self.send_text(200, "Nordic exfiltration sink ready\n")
            return

        self.send_text(404, "Not found\n")

    def do_POST(self):

        if self.path != "/upload":
            self.send_text(404, "Not found\n")
            return

        # ----------------------------------------------------
        # Validate Content-Length
        # ----------------------------------------------------

        content_length = self.headers.get("Content-Length")

        if content_length is None:
            self.send_text(411, "Content-Length required\n")
            return

        try:
            content_length = int(content_length)
        except ValueError:
            self.send_text(400, "Invalid Content-Length\n")
            return

        if content_length <= 0:
            self.send_text(400, "Empty upload\n")
            return

        if content_length > MAX_UPLOAD_SIZE:
            self.send_text(413, "Upload too large\n")
            return

        # ----------------------------------------------------
        # Determine filename
        # ----------------------------------------------------

        supplied_name = self.headers.get(
            "X-Nordic-Filename",
            "upload.bin"
        )

        supplied_name = safe_filename(supplied_name)

        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")

        filename = f"{timestamp}-{supplied_name}"

        output_path = os.path.join(
            self.server.output_directory,
            filename
        )

        # ----------------------------------------------------
        # Receive data
        # ----------------------------------------------------

        sha256 = hashlib.sha256()
        remaining = content_length

        try:

            with open(output_path, "wb") as outfile:

                while remaining > 0:

                    chunk_size = min(65536, remaining)
                    chunk = self.rfile.read(chunk_size)

                    if not chunk:
                        raise ConnectionError(
                            "Connection closed before upload completed"
                        )

                    outfile.write(chunk)
                    sha256.update(chunk)

                    remaining -= len(chunk)

        except Exception as exc:

            try:
                os.remove(output_path)
            except OSError:
                pass

            print(
                f"UPLOAD FAILED | "
                f"source={self.client_address[0]} | "
                f"error={exc}",
                flush=True,
            )

            self.send_text(500, "Upload failed\n")
            return

        # ----------------------------------------------------
        # Successful upload
        # ----------------------------------------------------

        digest = sha256.hexdigest()

        print(
            "UPLOAD COMPLETE | "
            f"source={self.client_address[0]} | "
            f"file={output_path} | "
            f"bytes={content_length} | "
            f"sha256={digest}",
            flush=True,
        )

        response = (
            "UPLOAD COMPLETE\n"
            f"filename={filename}\n"
            f"bytes={content_length}\n"
            f"sha256={digest}\n"
        )

        self.send_text(200, response)


def main():

    parser = argparse.ArgumentParser(
        description="Nordic Manufacturing CyberLab exfiltration receiver"
    )

    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_PORT,
        help=f"TCP listening port (default: {DEFAULT_PORT})",
    )

    parser.add_argument(
        "--output",
        default=DEFAULT_OUTPUT,
        help=f"Upload directory (default: {DEFAULT_OUTPUT})",
    )

    args = parser.parse_args()

    if not 1 <= args.port <= 65535:
        raise SystemExit("Invalid TCP port")

    output_directory = os.path.abspath(args.output)

    os.makedirs(
        output_directory,
        mode=0o750,
        exist_ok=True
    )

    server = ThreadingHTTPServer(
        ("0.0.0.0", args.port),
        UploadHandler
    )

    server.output_directory = output_directory

    print("=" * 60)
    print(" Nordic Manufacturing - Exfiltration Sink")
    print("=" * 60)
    print()
    print(f"Listening: 0.0.0.0:{args.port}")
    print(f"Uploads:   {output_directory}")
    print(f"Max size:  {MAX_UPLOAD_SIZE // (1024 * 1024)} MB")
    print()
    print("Waiting for CyberLab upload...")
    print()

    try:
        server.serve_forever()

    except KeyboardInterrupt:
        pass

    finally:
        server.server_close()


if __name__ == "__main__":
    main()