#!/usr/bin/env python3
"""lagtest client: per-UDP-port packet loss tester for LACP links.

Usage: client.py [-b LOCALIP] HOST[:PORT] [send|recv] [LOCALPORT]   (default port 6300, mode send)
LOCALPORT binds the UDP sockets to consecutive local ports starting there,
making the flows (and thus LACP hashing) reproducible across runs.
-b LOCALIP binds the TCP and UDP sockets to that local address, selecting
which interface (and address family) the test runs over.
Password is taken from $LAGTEST_PW or prompted for.
"""
import getpass, hashlib, os, select, socket, sys, time

LOOPS, SLEEP, PKT = 100, 0.05, 1400


def die(msg):
    sys.exit("error: " + msg)


def report(lost, base, lports):  # lost[i] < 0 means the port could not be hole-punched
    tested = [n for n in lost if n >= 0]
    total, worst = sum(tested), len(tested) * LOOPS or 1
    print(f"\ntotal lost: {total}/{worst} packets ({100 * total / worst:.1f}%)")
    def line(i, n):
        p = f"lport {lports[i]} rport {base + i}"
        if n < 0:
            return f"  {p}: unreachable, hole punch failed"
        return f"  {p}: {n} lost ({100 * n / LOOPS:.1f}%)"
    ports = list(enumerate(lost))  # enumerate order is port order (base + i ascending)
    print("unreachable:")
    for i, n in ports:
        if n < 0:
            print(line(i, n))
    print("loss under 10%:")
    for i, n in ports:
        if 0 < n * 10 < LOOPS:
            print(line(i, n))
    print("loss 10% or above:")
    for i, n in ports:
        if n * 10 >= LOOPS:
            print(line(i, n))
    print()
    print("UDP Port Loss Map")
    print("     " + " ".join(f"{i:^3d}" for i in range(10)))
    for row in range(10):  # 10x10 map: green ok, yellow <=10%, red >10%, blue unpunched
        cells = f"+{row * 10:02d}  "
        for n in lost[row * 10:row * 10 + 10]:
            bg = 44 if n < 0 else 41 if n * 10 > LOOPS else 43 if n else 42
            style = f"{37 if n < 0 or n * 10 > LOOPS else 30};{bg}"
            text = "---" if n < 0 else "XXX" if n >= 100 else f"{n:>3d}" if n > 0 else " · "
            cells += f"\x1b[{style}m{text}\x1b[0m "
        print(cells)
    legend = f"remote port = {base} + row + column"
    if lports == list(range(lports[0], lports[0] + len(lports))):
        legend += f", local = {lports[0]} + row + column"
    print(legend)


def main():
    argv, bind = sys.argv[1:], ""
    if argv and argv[0] in ("-b", "--bind"):
        if len(argv) < 2:
            die("-b needs a local IP")
        bind, argv = argv[1], argv[2:]
    if not argv or argv[0] in ("-h", "--help"):
        die(__doc__)
    arg = argv[0]
    if arg.startswith("["):        # [ipv6] or [ipv6]:port
        host, _, port = arg[1:].partition("]")
        port = port.lstrip(":")
    elif arg.count(":") == 1:      # host:port or ipv4:port
        host, _, port = arg.partition(":")
    else:                          # bare hostname / bare ipv6 literal, default port
        host, port = arg, ""
    mode = argv[1] if len(argv) > 1 else "send"
    if mode not in ("send", "recv"):
        die("mode must be send or recv")
    lport = int(argv[2]) if len(argv) > 2 else 0  # 0 = ephemeral ports
    pw = os.environ.get("LAGTEST_PW") or getpass.getpass("password: ")

    print(f"connecting to {host}...")
    try:
        tcp = socket.create_connection((host, int(port or 6300)), timeout=30,
                                       source_address=(bind, 0) if bind else None)
    except OSError as e:
        die(f"cannot connect: {e}")
    family, peer = tcp.family, tcp.getpeername()  # reuse the resolved address for UDP
    def dst(p):                    # keep IPv6 flowinfo/scopeid if present
        return (peer[0], p) + peer[2:]
    def usock(p):                  # UDP socket, optionally bound to local IP/port
        s = socket.socket(family, socket.SOCK_DGRAM)
        try:
            if p or bind:
                s.bind((bind, p))  # bind "" works for both IPv4 and IPv6
        except OSError:
            die(f"cannot bind local address {bind or '*'}:{p}")
        return s
    ctl = tcp.makefile("rw")
    nonce = ctl.readline().split()[1]
    ctl.write(f"AUTH {hashlib.sha256((nonce + pw).encode()).hexdigest()}\n")
    ctl.flush()
    ok = ctl.readline().split()
    if not ok or ok[0] != "OK":
        die("authentication failed")
    token, base, nports = ok[1], int(ok[2]), int(ok[3])
    print(f"authenticated: token {token}, udp ports {base}-{base + nports - 1}")
    ctl.write(f"MODE {mode}\n")
    ctl.flush()
    if ctl.readline().split() != ["READY"]:
        die("server not ready")
    pkt = token.encode().ljust(PKT, b"\0")

    if mode == "send":
        udp = usock(lport)
        for loop in range(LOOPS):
            print(f"\rsending loop {loop + 1}/{LOOPS}", end="", flush=True)
            for i in range(nports):
                udp.sendto(pkt, dst(base + i))
            time.sleep(SLEEP)
        print("\nall packets sent, waiting 3s for stragglers...")
        time.sleep(3)
        ctl.write("DONE\n")
        ctl.flush()
        result = ctl.readline().split()
        if not result or result[0] != "RESULT":
            die("no result from server")
        lost = [LOOPS - int(n) for n in result[1:]]
        lports = [udp.getsockname()[1]] * nports
    else:
        socks = [usock(lport and lport + i) for i in range(nports)]
        index = {s: i for i, s in enumerate(socks)}
        # punch each port until the server confirms it knows all our addresses;
        # always punch for the first second, give up on missing ports after 5s
        missing, start = list(range(nports)), time.time()
        while (missing or time.time() - start < 1) and time.time() - start < 5:
            for i in (range(nports) if time.time() - start < 1 else missing):
                socks[i].sendto(pkt, dst(base + i))
            time.sleep(SLEEP)
            ctl.write("PUNCHED\n")
            ctl.flush()
            missing = [int(i) for i in ctl.readline().split()[1:]]
            print(f"\rpunched {nports - len(missing)}/{nports} ports", end="", flush=True)
        print()
        ctl.write("GO\n")
        ctl.flush()
        print("server sending...")
        counts, deadline, watch = [0] * nports, None, socks + [tcp]
        while deadline is None or time.time() < deadline:
            ready, _, _ = select.select(watch, [], [], 0.25)
            for s in ready:
                if s is tcp:  # only line the server sends now is SENT
                    ctl.readline()
                    print("\nserver done, waiting 3s for stragglers...")
                    deadline = time.time() + 3
                    watch.remove(tcp)
                elif s.recv(PKT + 100).startswith(token.encode()):
                    counts[index[s]] += 1
            print(f"\rreceived {sum(counts)} packets", end="", flush=True)
        lost = [-1 if i in missing else LOOPS - n for i, n in enumerate(counts)]
        lports = [s.getsockname()[1] for s in socks]
    report(lost, base, lports)


if __name__ == "__main__":
    main()
