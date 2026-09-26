"""Native nginx/mTLS/IPC capacity fixture in a private network namespace."""

import concurrent.futures
import http.client
import json
import os
import statistics
import subprocess
import time

from . import test_gateway_sustained_capacity as fixture_module


def main():
    assert os.geteuid() == 0
    assert os.readlink("/proc/self/ns/net") != os.readlink("/proc/1/ns/net")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    assert {x["ifname"] for x in json.loads(subprocess.check_output(["ip", "-j", "link"]))} == {
        "lo"
    }
    fixture = fixture_module.GatewayCapacity()
    fixture.setUp()
    report = {"scope": "synthetic IPC, real nginx and mutual TLS; private loopback namespace"}
    try:
        gateway = fixture.start(proxy=True)
        root = fixture.root
        config = root / "nginx.conf"

        def configure(identity="localhost", client_certificate=True):
            credentials = (
                f"proxy_ssl_certificate {root}/cert.pem; proxy_ssl_certificate_key {root}/key.pem;"
                if client_certificate
                else ""
            )
            config.write_text(f"""worker_processes 2;
                pid {root}/nginx.pid;
                error_log {root}/error.log warn;
                events {{worker_connections 256;}}
                http {{ access_log off;
                    upstream gateway {{server 127.0.0.1:{gateway.server_port}; keepalive 2;
                        keepalive_requests 16; keepalive_timeout 1s;}}
                    server {{listen 127.0.0.1:18081; client_max_body_size 16k;
                        location = /v1/work {{
                            proxy_pass https://gateway;
                            proxy_http_version 1.1;
                            proxy_set_header Connection keep-alive;
                            proxy_set_header X-Veld-Client-IP $remote_addr;
                            proxy_ssl_verify on;
                            proxy_ssl_verify_depth 2;
                            proxy_ssl_server_name on;
                            proxy_ssl_name {identity};
                            proxy_ssl_trusted_certificate {root}/cert.pem;
                            {credentials}
                            proxy_next_upstream off;
                            proxy_connect_timeout 5s;
                            proxy_read_timeout 10s;
                        }}
                    }}
                }}""")
            subprocess.run(
                ["nginx", "-t", "-p", str(root) + "/", "-c", str(config)],
                check=True,
                capture_output=True,
            )

        def request(client, forged="192.0.2.199"):
            connection = http.client.HTTPConnection(
                "127.0.0.1", 18081, timeout=15, source_address=(f"127.0.0.{client}", 0)
            )
            started = time.monotonic()
            try:
                connection.request(
                    "POST",
                    "/v1/work",
                    b"{}",
                    {
                        "Content-Type": "application/json",
                        "Connection": "close",
                        "X-Veld-Client-IP": forged,
                    },
                )
                response = connection.getresponse()
                response.read()
                return response.status, time.monotonic() - started
            finally:
                connection.close()

        for identity, certificate, expected in [
            ("localhost", True, 200),
            ("wrong.invalid", True, 502),
            ("localhost", False, 502),
        ]:
            configure(identity, certificate)
            with (root / "process.log").open("ab") as log:
                process = subprocess.Popen(
                    [
                        "nginx",
                        "-p",
                        str(root) + "/",
                        "-c",
                        str(config),
                        "-g",
                        "daemon off;",
                    ],
                    stdout=log,
                    stderr=log,
                )
                try:
                    for _ in range(100):
                        try:
                            result = request(250)
                            break
                        except OSError:
                            assert process.poll() is None
                            time.sleep(0.02)
                    else:
                        raise AssertionError("nginx did not start")
                    assert result[0] == expected, (identity, certificate, result)
                    if expected != 200:
                        report[
                            "wrong_server_identity_refused"
                            if certificate
                            else "missing_proxy_certificate_refused"
                        ] = True
                        continue
                    start = time.monotonic()

                    def client_run(client):
                        rows = []
                        for i in range(80):
                            deadline = start + i * 0.1
                            time.sleep(max(0, deadline - time.monotonic()))
                            rows.append(request(client))
                        return rows

                    with concurrent.futures.ThreadPoolExecutor(max_workers=40) as workers:
                        rows = [r for group in workers.map(client_run, range(2, 42)) for r in group]
                    elapsed = time.monotonic() - start
                    assert all(status == 200 for status, _ in rows), {status for status, _ in rows}
                    with gateway.rate_lock:
                        identities = {
                            address for address, action in gateway.rate if action == "work"
                        }
                    assert all(f"127.0.0.{i}" in identities for i in range(2, 42))
                    assert "192.0.2.199" not in identities
                    report.update(
                        requests=len(rows),
                        seconds=elapsed,
                        requests_per_second=len(rows) / elapsed,
                        p50_ms=statistics.median(r[1] for r in rows) * 1000,
                        p99_ms=sorted(r[1] for r in rows)[int(len(rows) * 0.99)] * 1000,
                        upstream_identity_overwrite_verified=True,
                        statuses={"200": len(rows)},
                    )
                finally:
                    process.terminate()
                    process.wait(timeout=10)
        report["status"] = "PASS"
        print(json.dumps(report), flush=True)
    finally:
        fixture.tearDown()


if __name__ == "__main__":
    main()
