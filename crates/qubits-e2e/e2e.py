#!/usr/bin/env python3
"""Whole-system test: real processes, real TCP/TLS, release binaries.

    cargo build --release -p qubits-node -p qubits-cli -p qubits-e2e
    python3 crates/qubits-e2e/e2e.py [phase,phase,...]

E2E_SOAK_SECONDS sets the length of the soak phase (default 90), E2E_BLOCK_INTERVAL_MS the block
interval (default 100).
"""
import collections
import concurrent.futures as cf
import json
import os
import queue
import random
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import urllib.error
import urllib.request

BACKEND = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BIN = f"{BACKEND}/target/release"
QUBITS, NODE, TOOL = f"{BIN}/qubits", f"{BIN}/qubits-node", f"{BIN}/qubits-e2e"
WORK = tempfile.mkdtemp(prefix="qubits-e2e-")
PASSWORD = "a long enough password"
PW = ("--password-file", "pw")
RPC, P2P, PROXY = 18600, 19600, 20600
SOAK_SECONDS = int(os.environ.get("E2E_SOAK_SECONDS", "90"))
INTERVAL_MS = os.environ.get("E2E_BLOCK_INTERVAL_MS", "100")

results = []
measurements = []
nodes = {}
validators = []
keys = {}
hexkeys = {}


def log(text):
    print(text, flush=True)


def check(name, ok, detail=""):
    results.append((name, bool(ok), str(detail)[:300]))
    suffix = f"  [{str(detail)[:200]}]" if detail != "" else ""
    log(f"  {'ok  ' if ok else 'FAIL'}  {name}{suffix}")
    return ok


def measure(text):
    measurements.append(text)
    log(f"  --    {text}")


def http(port, path, body=None, raw=None, timeout=15):
    data = raw if raw is not None else (None if body is None else json.dumps(body).encode())
    headers = {"content-type": "application/json"} if data is not None else {}
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read()
            try:
                return r.status, json.loads(text) if text else None
            except ValueError:
                return r.status, text.decode()
    except urllib.error.HTTPError as e:
        text = e.read()
        try:
            return e.code, json.loads(text)
        except ValueError:
            return e.code, {"error": text.decode(errors="replace")}
    except Exception as e:
        return 0, {"error": str(e)}


def cli(*args, port=RPC, ok=True):
    env = dict(os.environ, QUBITS_RPC=f"http://127.0.0.1:{port}")
    p = subprocess.run([QUBITS, *map(str, args)], cwd=WORK, env=env, capture_output=True, text=True, timeout=180)
    out = p.stdout + p.stderr
    if ok and p.returncode != 0:
        raise RuntimeError(f"qubits {' '.join(map(str, args))}: {out}")
    return p.returncode, out


def tool(*args):
    return subprocess.run([TOOL, *map(str, args)], capture_output=True, text=True, check=True).stdout.splitlines()


class Proc:
    def __init__(self, name, port, args):
        self.name, self.port, self.args = name, port, list(args)
        self.p = None
        self.log = f"{WORK}/{name}.log"

    def start(self):
        out = open(self.log, "a")
        # short eras, so the run produces complete era files; every node of a chain must agree
        cmd = [NODE, "run", "--data-dir", f"{WORK}/{self.name}", "--rpc-addr", f"127.0.0.1:{self.port}", "--era-length", "256", *self.args]
        self.p = subprocess.Popen(cmd, cwd=WORK, env=dict(os.environ, RUST_LOG="info"), stdout=out, stderr=subprocess.STDOUT)
        return self

    def alive(self):
        return self.p is not None and self.p.poll() is None

    def kill(self):
        if self.alive():
            self.p.send_signal(signal.SIGCONT)
            self.p.kill()
            self.p.wait()

    def interrupt(self):
        self.p.send_signal(signal.SIGINT)
        return self.p.wait(timeout=20)

    def pause(self, paused):
        self.p.send_signal(signal.SIGSTOP if paused else signal.SIGCONT)

    def rss_mb(self):
        out = subprocess.run(["ps", "-o", "rss=", "-p", str(self.p.pid)], capture_output=True, text=True).stdout
        return int(out.strip() or 0) // 1024


class Net:
    """TCP proxies between validators: adds delay, and cuts links to partition the network."""

    def __init__(self):
        self.delay = (0.0, 0.0)
        self.groups = {}
        self.links = []
        self.lock = threading.Lock()
        self.stopping = False
        self.servers = []
        for i in range(4):
            for j in range(4):
                if i != j:
                    threading.Thread(target=self.listen, args=(i, j), daemon=True).start()

    def allowed(self, i, j):
        return self.groups.get(i, 0) == self.groups.get(j, 0)

    def listen(self, i, j):
        server = socket.socket()
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", PROXY + i * 10 + j))
        server.listen(8)
        server.settimeout(0.2)
        self.servers.append(server)
        while not self.stopping:
            try:
                client, _ = server.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                if not self.allowed(i, j):
                    raise OSError("partitioned")
                target = socket.create_connection(("127.0.0.1", P2P + j))
            except OSError:
                client.close()
                continue
            with self.lock:
                self.links.append((i, j, client, target))
            self.pipe(client, target)
            self.pipe(target, client)

    def pipe(self, source, sink):
        pending = queue.Queue()

        def reader():
            while True:
                try:
                    data = source.recv(65536)
                except OSError:
                    data = b""
                pending.put((time.time() + random.uniform(*self.delay), data))
                if not data:
                    return

        def writer():
            while True:
                due, data = pending.get()
                time.sleep(max(0, due - time.time()))
                try:
                    if not data:
                        raise OSError
                    sink.sendall(data)
                except OSError:
                    for s in (source, sink):
                        try:
                            s.close()
                        except OSError:
                            pass
                    return

        threading.Thread(target=reader, daemon=True).start()
        threading.Thread(target=writer, daemon=True).start()

    def partition(self, *groups):
        self.groups = {member: g for g, group in enumerate(groups) for member in group}
        with self.lock:
            for i, j, a, b in self.links:
                if not self.allowed(i, j):
                    for s in (a, b):
                        try:
                            s.shutdown(socket.SHUT_RDWR)
                        except OSError:
                            pass

    def heal(self):
        self.groups = {}

    def close(self):
        self.stopping = True
        for server in self.servers:
            server.close()
        self.partition([0], [1], [2], [3])


def pub(name):
    return re.search(r"public key: *([0-9a-f]+)", cli("key", "show", "--key", f"{name}.json")[1]).group(1)


def addr(name):
    return re.search(r"qb1[0-9a-z]+", cli("address", "--key", f"{name}.json")[1]).group(0)


def new_key(name, scheme="ml-dsa-65"):
    cli("key", "new", "--out", f"{name}.json", "--scheme", scheme, *PW)
    keys[name] = addr(name)
    return keys[name]


def status(port=RPC):
    code, s = http(port, "/v1/status")
    return s if code == 200 else None


def height(port=RPC):
    s = status(port)
    return s["height"] if s else -1


def balance(a, port=RPC):
    code, acc = http(port, f"/v1/accounts/{a}")
    if code != 200:
        return -1
    return next((int(b["amount"]) for b in acc["balances"] if b["asset"] == 0), 0)


def account(a, port=RPC):
    return http(port, f"/v1/accounts/{a}")[1]


def metric(name, port=RPC):
    code, text = http(port, "/metrics")
    match = re.search(rf"^{name} (\d+)$", text, re.M) if code == 200 else None
    return int(match.group(1)) if match else -1


def wait(cond, timeout=30, every=0.1):
    end = time.time() + timeout
    while time.time() < end:
        try:
            if cond():
                return True
        except Exception:
            pass
        time.sleep(every)
    return False


def up(port, timeout=40):
    return wait(lambda: status(port) is not None, timeout)


def ports(names=None):
    return [nodes[n].port for n in (names or validators) if nodes[n].alive()]


def pay(frm, to, amount, port=RPC, waiting=True):
    args = ["transfer", "--key", f"{frm}.json", *PW, "--to", to, "--amount", amount]
    return cli(*args, *(["--wait"] if waiting else []), port=port)


def post_tx(port, hex_tx, timeout=15):
    return http(port, "/v1/transactions", {"transaction": hex_tx}, timeout=timeout)


def far_future():
    return int(time.time() * 1000) + 3_600_000


def load_transactions(first, count, each, to):
    s = status()
    lines = tool("gen", s["genesis_hash"], 1, to, far_future(), first, count, each)
    groups = {}
    for line in lines:
        sender, tx = line.split(" ", 1)
        groups.setdefault(sender, []).append(tx)
    return list(groups.values())


class Traffic:
    """Paced senders that behave like a real client: on `bad nonce` they continue from the nonce
    the chain expects, so whatever a failure lost is sent again."""

    def __init__(self, groups, per_second, targets):
        self.lost = 0
        self.accepted = 0
        self.targets = targets
        self.threads = [threading.Thread(target=self.send, args=(g, i, per_second), daemon=True)
                        for i, g in enumerate(groups)]
        for t in self.threads:
            t.start()

    def send(self, group, index, per_second):
        time.sleep(index * 0.01)
        turn = index
        i = 0
        taken = set()
        while i < len(group):
            code, body = post_tx(self.targets[turn % len(self.targets)], group[i], timeout=3)
            text = json.dumps(body)
            if code == 202:
                self.accepted += 1
                if i in taken:
                    self.lost += 1
                taken.add(i)
                i += 1
                time.sleep(1 / per_second)
            elif code == 409:
                i += 1
            elif code == 400 and "bad nonce" in text:
                expected = int(re.search(r"expected (\d+)", text).group(1))
                if expected != i:
                    i = expected
                else:
                    time.sleep(0.1)
            else:
                turn += 1
                time.sleep(0.1)

    def join(self, timeout=180):
        end = time.time() + timeout
        for t in self.threads:
            t.join(max(0, end - time.time()))
        return not any(t.is_alive() for t in self.threads)


def validator_args(i, proxied=False):
    args = ["--validator-key", f"v{i}.json", *PW, "--p2p-addr", f"127.0.0.1:{P2P + i}",
            "--block-interval-ms", INTERVAL_MS, "--round-timeout-ms", "1500"]
    for j in range(5):
        if j != i:
            port = PROXY + i * 10 + j if proxied and i < 4 and j < 4 else P2P + j
            args += ["--peer", f"{hexkeys[j]}=127.0.0.1:{port}"]
            args += ["--follow", f"http://127.0.0.1:{RPC + j}"]
    return args


def restart_all(proxied):
    for name in validators:
        nodes[name].kill()
    for name in validators:
        nodes[name].args = validator_args(int(name[1]), proxied)
        nodes[name].start()
    return all(up(nodes[n].port) for n in validators)


def setup():
    open(f"{WORK}/pw", "w").write(PASSWORD + "\n")
    for name in ("v0", "v1", "v2", "v3", "v4", "alice", "owner", "bob", "carol", "thief", "owner2", "m1", "m2", "sink", "live"):
        new_key(name)
    for name in ("rec", "m3", "slhuser"):
        new_key(name, "slh-dsa-sha2-192s")
    load = tool("addrs", 450)
    genesis = {
        "chain_id": "qubits-e2e",
        "timestamp_ms": int(time.time() * 1000) - 1000,
        "params": {"min_fee_per_byte": 1, "max_block_transactions": 1000},
        "validators": [{"key": pub(f"v{i}"), "payout": keys[f"v{i}"]} for i in range(4)],
        "accounts": [{"address": a, "balance": "1000000000000"} for a in [keys["alice"], keys["owner"], *load]],
    }
    json.dump(genesis, open(f"{WORK}/genesis.json", "w"))
    for i in range(5):
        hexkeys[i] = pub(f"v{i}")
    for name in ("v0", "v1", "v2", "v3", "v4", "api", "pruned", "spare", "trimmed", "joiner"):
        subprocess.run([NODE, "init", "--genesis", "genesis.json", "--data-dir", name], cwd=WORK, check=True, capture_output=True)
    for i in range(5):
        nodes[f"v{i}"] = Proc(f"v{i}", RPC + i, validator_args(i))
    validators.extend(["v0", "v1", "v2", "v3"])
    for name in validators:
        nodes[name].start()
    check("four validators came up", all(up(RPC + i) for i in range(4)))
    check("same genesis hash everywhere", len({status(RPC + i)["genesis_hash"] for i in range(4)}) == 1)
    check("each validator sees three peers", wait(lambda: all(metric("qubits_peers", RPC + i) >= 3 for i in range(4)), 25))
    code, text = http(RPC, "/health")
    check("/health answers", code == 200 and str(text).startswith("ok"), text)


def transfers():
    a, b = keys["alice"], keys["bob"]
    start = balance(a)
    _, out = pay("alice", b, 1_000_000)
    check("transfer reaches a block", "included in block" in out, out.strip().splitlines()[-1])
    check("all validators agree on the balance", wait(lambda: all(balance(b, p) == 1_000_000 for p in ports()), 15))
    txid = re.search(r"transaction ([0-9a-f]{64})", out).group(1)
    rc, status_out = cli("tx", "status", txid)
    check("tx status works", rc == 0 and "included" in status_out.lower())
    fee = start - balance(a) - 1_000_000
    check("fee is the minimum", 4_000 < fee < 7_000, fee)
    rc, out = cli("transfer", "--key", "carol.json", *PW, "--to", b, "--amount", 1, ok=False)
    check("unfunded account can't send", rc != 0 and "does not exist" in out, out.strip()[:80])
    rc, out = cli("transfer", "--key", "bob.json", *PW, "--to", a, "--amount", 10**12, ok=False)
    check("overdraft refused", rc != 0, out.strip()[:90])

    pay("alice", keys["slhuser"], 1_000_000)
    _, out = pay("slhuser", b, 5)
    check("SLH-DSA account sends", "included in block" in out)
    fee = 1_000_000 - 5 - balance(keys["slhuser"])
    check("SLH-DSA fee follows its size", 16_000 < fee < 18_000, fee)

    pay("alice", keys["carol"], 1_000_000)
    cli("key", "rotate", "--key", "carol.json", *PW, "--new-key", "thief.json", "--wait")
    rc, out = cli("transfer", "--key", "carol.json", *PW, "--to", b, "--amount", 1, ok=False)
    check("rotated key stops working", rc != 0, out.strip()[:90])
    rc, _ = cli("transfer", "--key", "thief.json", *PW, "--account", keys["carol"], "--to", b, "--amount", 1, "--wait", ok=False)
    check("new key sends from the same address", rc == 0)


def vault():
    o, thief = keys["owner"], keys["thief"]
    target = keys["slhuser"]
    cli("vault", "create", "--delay-secs", 3, "--recovery-key", "rec.json", "--key", "owner.json", *PW, "--wait")
    check("vault created", account(o)["vault"]["delay_ms"] == 3000)
    before = balance(target)
    cli("transfer", "--key", "owner.json", *PW, "--to", target, "--amount", 5000, "--wait")
    pending = account(o)["pending"]
    check("transfer waits, nothing moved", len(pending) == 1 and balance(target) == before)
    pid = pending[0]["id"]
    rc, out = cli("vault", "execute", "--vault", o, "--id", pid, "--key", "bob.json", *PW, ok=False)
    check("can't execute early", rc != 0 and "locked" in out, out.strip()[:90])
    time.sleep(3.2)
    cli("vault", "execute", "--vault", o, "--id", pid, "--key", "bob.json", *PW, "--wait")
    check("anyone can execute after the delay", balance(target) == before + 5000)
    cli("transfer", "--key", "owner.json", *PW, "--to", target, "--amount", 7000, "--wait")
    pid = account(o)["pending"][0]["id"]
    cli("vault", "cancel", "--id", pid, "--key", "owner.json", *PW, "--wait")
    check("owner cancels", account(o)["pending"] == [])

    everything = balance(o) - 1_000_000
    cli("transfer", "--key", "owner.json", *PW, "--account", o, "--to", thief, "--amount", everything, "--wait")
    cli("key", "rotate", "--key", "owner.json", *PW, "--new-key", "thief.json", "--wait")
    pending = account(o)["pending"]
    check("both of the thief's actions wait", len(pending) == 2)
    for action in pending:
        cli("vault", "cancel", "--id", action["id"], "--recovery", "--key", "rec.json", *PW, "--account", o, "--wait")
    check("SLH-DSA recovery key cancels them", account(o)["pending"] == [])
    cli("key", "rotate", "--new-key", "owner2.json", "--recovery", "--key", "rec.json", *PW, "--account", o, "--wait")
    rc, out = cli("transfer", "--key", "owner.json", *PW, "--account", o, "--to", thief, "--amount", 1, ok=False)
    check("stolen key is dead", rc != 0, out.strip()[:90])
    time.sleep(3.2)
    check("thief got nothing", balance(thief) <= 0)
    cli("transfer", "--key", "owner2.json", *PW, "--account", o, "--to", target, "--amount", 1, "--wait")
    check("new owner works", len(account(o)["pending"]) == 1)


def multisig():
    c = keys["bob"]
    _, out = cli("policy", "new", "--threshold", 2, "--key", "m1.json", "--key", "m2.json", "--key", "m3.json", "--out", "ms.json")
    ms = re.search(r"qb1[0-9a-z]+", out).group(0)
    pay("alice", ms, 10_000_000)
    before = balance(c)
    cli("transfer", "--account", ms, "--to", c, "--amount", 7, "--policy", "ms.json", "--unsigned-out", "t1.json")
    cli("tx", "sign", "--file", "t1.json", "--key", "m1.json", *PW)
    rc, out = cli("tx", "submit", "--file", "t1.json", ok=False)
    check("one signature is not enough", rc != 0, out.strip()[:80])
    rc, out = cli("tx", "sign", "--file", "t1.json", "--key", "m1.json", *PW, ok=False)
    check("same key can't sign twice", rc != 0, out.strip()[:80])
    rc, out = cli("tx", "sign", "--file", "t1.json", "--key", "bob.json", *PW, ok=False)
    check("outsider can't sign", rc != 0, out.strip()[:80])
    cli("tx", "sign", "--file", "t1.json", "--key", "m3.json", *PW)
    cli("tx", "submit", "--file", "t1.json", "--wait")
    check("mixed ML-DSA + SLH-DSA 2-of-3 goes through", balance(c) == before + 7)
    rc, out = cli("tx", "submit", "--file", "t1.json", ok=False)
    check("replay refused", rc != 0, out.strip()[:80])


def api_node():
    nodes["api"] = Proc("api", RPC + 10, ["--follow", f"http://127.0.0.1:{RPC}", "--follow", f"http://127.0.0.1:{RPC + 1}"])
    nodes["api"].start()
    check("API node came up", up(RPC + 10))
    top = height()
    check("API node verified its way to the tip", wait(lambda: height(RPC + 10) >= top, 30), f"height {top}")
    before = balance(keys["bob"], RPC + 10)
    pay("alice", keys["bob"], 3, port=RPC + 10, waiting=False)
    check("submission through the API node reaches validators", wait(lambda: balance(keys["bob"], RPC + 1) == before + 3, 20))
    check("API node sees the result", wait(lambda: balance(keys["bob"], RPC + 10) == before + 3, 20))
    code, proof = http(RPC + 10, f"/v1/proofs/accounts/{keys['bob']}")
    check("Merkle proof served", code == 200 and "proof" in json.dumps(proof), code)


def burst():
    senders, each = 30, 50
    groups = load_transactions(0, senders, each, keys["m2"])
    failures = []

    def send(batch, port):
        for tx in batch:
            for _ in range(600):
                code, body = post_tx(port, tx)
                if code == 202:
                    break
                if code == 503 or code == 0 or (code == 400 and "bad nonce" in json.dumps(body)):
                    time.sleep(0.05)
                    continue
                failures.append((code, body))
                break

    h0, base, total = height(), balance(keys["m2"]), senders * each
    t0 = time.time()
    with cf.ThreadPoolExecutor(senders) as pool:
        list(pool.map(lambda x: send(x[1], RPC + x[0] % 4), enumerate(groups)))
    done = wait(lambda: balance(keys["m2"]) == base + total, 120, 0.2)
    elapsed = time.time() - t0
    check(f"all {total} transactions included", done, f"refused {len(failures)} {failures[:1]}")
    measure(f"burst: {total / elapsed:.0f} tx/s over {elapsed:.1f} s, {height() - h0} blocks")
    check("validators converge", wait(lambda: len({balance(keys["m2"], p) for p in ports()}) == 1, 20))


def throughput():
    senders, each = 200, 60
    groups = load_transactions(200, senders, each, keys["m1"])
    total = senders * each
    base = balance(keys["m1"])
    h0 = height()
    rebuilt = metric("qubits_shards_rebuilt_total")
    refused = []

    def send(indexed):
        i, batch = indexed
        for tx in batch:
            for _ in range(2000):
                code, body = post_tx(RPC + i % 4, tx)
                if code == 202:
                    break
                if code == 409:
                    break
                if code in (0, 503) or (code == 400 and "bad nonce" in json.dumps(body)):
                    time.sleep(0.02)
                    continue
                refused.append((code, body))
                break

    t0 = time.time()
    with cf.ThreadPoolExecutor(senders) as pool:
        list(pool.map(send, enumerate(groups)))
    posted = time.time() - t0
    done = wait(lambda: balance(keys["m1"]) == base + total, 120, 0.1)
    check(f"all {total} transactions included", done, f"refused {len(refused)} {refused[:1]}")
    blocks = [http(RPC, f"/v1/blocks/{h}")[1] for h in range(h0 + 1, height() + 1)]
    full = [b for b in blocks if b["transaction_ids"]]
    span = (full[-1]["timestamp_ms"] - full[0]["timestamp_ms"]) / 1000
    count = sum(len(b["transaction_ids"]) for b in full)
    biggest = max(len(b["transaction_ids"]) for b in full)
    measure(f"throughput: {count / max(span, 0.001):.0f} tx/s in blocks over {span:.1f} s, "
            f"{len(full)} blocks, {1000 * span / max(len(full) - 1, 1):.0f} ms apart, largest {biggest} tx, "
            f"clients took {posted:.1f} s to post")
    if biggest >= 500:
        check("large blocks spread as shards", metric("qubits_shards_rebuilt_total") > rebuilt)
    check("validators converge", wait(lambda: len({balance(keys["m1"], p) for p in ports()}) == 1, 30))


def hostile():
    s = status()
    lines = dict(l.split(" ", 1) for l in tool("bad", s["genesis_hash"], 1, keys["bob"], far_future(), 39))
    expected = {
        "fee-too-high": "fee too high", "fee-too-low": "fee too low", "wrong-chain": "wrong chain",
        "expired": "expired", "future-nonce": "bad nonce", "tampered-amount": "unauthorized",
        "foreign-signature": "unauthorized", "no-signatures": "unauthorized",
    }
    for name, message in expected.items():
        code, body = post_tx(RPC, lines[name])
        check(f"refused: {name}", code == 400 and message in json.dumps(body), code)
    check("valid one accepted", post_tx(RPC, lines["good"])[0] == 202)
    check("second copy refused", post_tx(RPC, lines["good"])[0] == 409)
    cases = [
        ("broken JSON", lambda: http(RPC, "/v1/transactions", raw=b"{not json")),
        ("not hex", lambda: post_tx(RPC, "zz")),
        ("short transaction", lambda: post_tx(RPC, "00ff")),
        ("oversized body", lambda: http(RPC, "/v1/transactions", raw=b'{"transaction":"' + b"a" * 900_000 + b'"}')),
        ("bad address", lambda: http(RPC, "/v1/accounts/qb1hello")),
        ("missing block", lambda: http(RPC, "/v1/blocks/99999999")),
        ("overflowing height", lambda: http(RPC, "/v1/blocks/999999999999999999999999")),
        ("bad proof height", lambda: http(RPC, f"/v1/proofs/accounts/{keys['bob']}?height=abc")),
    ]
    for name, call in cases:
        check(f"clean error: {name}", 400 <= call()[0] < 500)
    with cf.ThreadPoolExecutor(32) as pool:
        codes = list(pool.map(lambda i: http(RPC, "/v1/transactions", raw=os.urandom(200))[0], range(800)))
    check("API survives 800 random POSTs", status() is not None and all(c >= 400 for c in codes), sorted(set(codes)))

    slow = []
    for _ in range(60):
        c = socket.create_connection(("127.0.0.1", RPC))
        c.sendall(b"POST /v1/transactions HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: 100000\r\n\r\n{")
        slow.append(c)
    t0 = time.time()
    _, out = pay("alice", keys["bob"], 1)
    check("transfer passes with 60 slow clients", "included" in out, f"{time.time() - t0:.1f} s")
    for c in slow:
        c.close()

    flood = []
    for i in range(400):
        c = socket.create_connection(("127.0.0.1", P2P))
        if i % 2:
            c.sendall(os.urandom(512))
        flood.append(c)
    t0 = time.time()
    _, out = pay("alice", keys["bob"], 1)
    check("chain runs with 400 strangers on the P2P port", "included" in out, f"{time.time() - t0:.1f} s")
    for c in flood:
        c.close()
    check("v0 still alive", nodes["v0"].alive())


def failures():
    b = keys["bob"]
    nodes["v3"].kill()
    pay("alice", b, 1)
    check("chain continues with one validator down", True)
    top = height()
    nodes["v3"].start()
    check("restarted validator catches up", up(RPC + 3) and wait(lambda: height(RPC + 3) >= top, 40), top)

    nodes["v2"].pause(True)
    pay("alice", b, 1)
    time.sleep(5)
    nodes["v2"].pause(False)
    target = balance(b)
    check("frozen validator catches up", wait(lambda: balance(b, RPC + 2) == target, 40))

    before = balance(b)
    nodes["v2"].kill()
    nodes["v3"].kill()
    h0 = height()
    pay("alice", b, 1, waiting=False)
    time.sleep(6)
    check("no quorum: nothing commits", balance(b) == before and height() == h0, f"height {h0}")
    nodes["v2"].start()
    nodes["v3"].start()
    check("quorum back: the transaction commits", wait(lambda: balance(b) == before + 1, 45))
    check("all four in step", wait(lambda: all(balance(b, p) == before + 1 for p in ports()), 30))

    check("Ctrl-C exits cleanly", nodes["v1"].interrupt() == 0)
    nodes["v1"].start()
    check("back after a clean exit", up(RPC + 1))

    open(f"{WORK}/wrongpw", "w").write("not the right password\n")
    wrong = subprocess.run([NODE, "run", "--data-dir", f"{WORK}/spare", "--validator-key", "v0.json", "--password-file", "wrongpw",
                            "--rpc-addr", "127.0.0.1:18690"], cwd=WORK, capture_output=True, text=True, timeout=30)
    check("wrong password won't start", wrong.returncode != 0 and "wrong password" in wrong.stdout + wrong.stderr)


def power_cuts():
    b = keys["m1"]
    senders, each = 8, 100
    base = balance(b)
    h0 = height()
    traffic = Traffic(load_transactions(30, senders, each, b), 3, ports())
    for cycle in range(3):
        time.sleep(7)
        before = max(height(p) for p in ports())
        mempool = sum(status(p)["mempool_size"] for p in ports())
        for name in validators:
            nodes[name].kill()
        for name in validators:
            nodes[name].start()
        ok = all(up(nodes[n].port) for n in validators)
        check(f"power cut {cycle + 1} under load: back and moving", ok and wait(lambda: height() > before, 30),
              f"height {before}, mempool {mempool}")
    traffic.join()
    total = senders * each
    settled = wait(lambda: balance(b) == base + total and len({balance(b, p) for p in ports()}) == 1, 60)
    check("every transaction applied exactly once", settled, f"{balance(b) - base}/{total}")
    measure(f"power cuts: {height() - h0} blocks, {traffic.lost} accepted transactions lost with a mempool and resent")


def network():
    net = Net()
    check("restarted behind delaying proxies", restart_all(True))
    net.delay = (0.02, 0.08)
    b = keys["bob"]
    check("peers reconnect through the proxies", wait(lambda: all(metric("qubits_peers", p) >= 3 for p in ports()), 30))
    t0 = time.time()
    pay("alice", b, 1)
    check("transfer with 20-80 ms link delay", True, f"{time.time() - t0:.1f} s")

    before = balance(b)
    net.partition([0, 1], [2, 3])
    pay("alice", b, 1, waiting=False)
    time.sleep(6)
    seen = [balance(b, p) for p in ports()]
    check("2/2 split: nothing commits on either side", max(seen) <= before, (before, seen))
    net.heal()
    check("healed: the transaction commits", wait(lambda: all(balance(b, p) == before + 1 for p in ports()), 40))

    net.partition([0, 1, 2], [3])
    h0 = height()
    for _ in range(3):
        pay("alice", b, 1)
    check("3/1 split: majority keeps committing", height() > h0, (h0, height()))
    h3 = height(RPC + 3)
    same = http(RPC, f"/v1/blocks/{h3}/raw")[1].get("block") == http(RPC + 3, f"/v1/blocks/{h3}/raw")[1].get("block")
    check("isolated validator built nothing of its own", 0 < h3 <= height() and same, h3)
    net.heal()
    top = height()
    check("isolated validator catches up", wait(lambda: height(RPC + 3) >= top, 40))

    target = keys["sink"]
    base = balance(target)
    senders, each = 8, 40
    traffic = Traffic(load_transactions(40, senders, each, target), 3, ports())
    rng = random.Random(7)
    for _ in range(6):
        members = [0, 1, 2, 3]
        rng.shuffle(members)
        cut = rng.choice([1, 2])
        net.partition(members[:cut], members[cut:])
        time.sleep(2)
        net.heal()
        time.sleep(2)
    traffic.join()
    total = senders * each
    settled = wait(lambda: balance(target) == base + total and len({balance(target, p) for p in ports()}) == 1, 60)
    check("flapping partitions under load: exactly once", settled, f"{balance(target) - base}/{total}")
    measure(f"partitions: {traffic.lost} accepted transactions lost and resent")
    net.close()
    check("back on direct links", restart_all(False))


def wide_area():
    net = Net()
    net.delay = (0.04, 0.04)
    for name in validators:
        nodes[name].kill()
    for name in validators:
        i = int(name[1])
        nodes[name].args = validator_args(i, True)
        nodes[name].start()
    check("restarted with 40 ms between validators", all(up(nodes[n].port) for n in validators))
    check("peers connect", wait(lambda: all(metric("qubits_peers", p) >= 3 for p in ports()), 30))

    txs = load_transactions(400, 1, 40, keys["carol"])[0]
    delays = []
    for tx in txs:
        t0 = time.time()
        code, body = post_tx(RPC, tx)
        if code != 202:
            check("transaction accepted", False, body)
            break
        wait(lambda: http(RPC, f"/v1/transactions/{body['id']}")[1].get("status") == "included", 20, 0.002)
        delays.append(time.time() - t0)
    delays.sort()
    measure(f"wide area, 40 ms one way: final {1000 * delays[len(delays) // 2]:.0f} ms median, "
            f"{1000 * delays[int(len(delays) * 0.9)]:.0f} ms p90, submission to included in a final block")
    check("all confirmed", len(delays) == len(txs), len(delays))

    target = keys["sink"]
    base = balance(target)
    senders, each = 40, 60
    h0 = height()
    traffic = Traffic(load_transactions(401, senders, each, target), 20, ports())
    done = traffic.join(120)
    settled = wait(lambda: balance(target) == base + senders * each, 60)
    check("load over the slow links: exactly once", done and settled)
    blocks = [http(RPC, f"/v1/blocks/{h}")[1] for h in range(h0 + 1, height() + 1)]
    busy = [b for b in blocks if b["transaction_ids"]]
    gaps = sorted(b["timestamp_ms"] - a["timestamp_ms"] for a, b in zip(busy, busy[1:]))
    if gaps:
        measure(f"wide area under load: blocks {gaps[len(gaps) // 2]} ms apart (median), {len(busy)} blocks")
    net.close()
    for name in validators:
        nodes[name].args = validator_args(int(name[1]), False)
    check("back on direct links", restart_all(False))


def byzantine():
    v3 = nodes["v3"]
    v3.kill()
    peers = [f"{hexkeys[j]}=127.0.0.1:{P2P + j}" for j in range(3)]
    out = open(f"{WORK}/byzantine.log", "w")
    attacker = subprocess.Popen([TOOL, "byzantine", f"{WORK}/v3", "v3.json", "pw", f"127.0.0.1:{P2P + 3}", "25", *peers],
                                cwd=WORK, stdout=out, stderr=subprocess.STDOUT)
    honest = [p for p in ports() if p != RPC + 3]
    received = metric("qubits_bytes_in_total")
    time.sleep(3)
    times = []
    for _ in range(8):
        t0 = time.time()
        pay("alice", keys["bob"], 1)
        times.append(time.time() - t0)
    check("chain runs next to a validator sending rubbish", True, f"slowest transfer {max(times):.1f} s")
    attacker.wait(timeout=60)
    sent = open(f"{WORK}/byzantine.log").read().strip().splitlines()[-1]
    measure(f"byzantine: {sent}; v0 took in {(metric('qubits_bytes_in_total') - received) // (1024 * 1024)} MiB; v0 uses {nodes['v0'].rss_mb()} MB")
    check("attacker really reached the validators", metric("qubits_bytes_in_total") - received > 10_000_000)
    check("honest validators stayed up", all(nodes[f"v{i}"].alive() for i in range(3)))
    v3.start()
    top = height()
    check("real v3 returns and catches up", up(RPC + 3) and wait(lambda: height(RPC + 3) >= top, 60))
    check("honest validators agree", len({status(p)["state_root"] for p in honest}) <= 2)


def soak():
    senders = 100
    each = SOAK_SECONDS
    target = keys["sink"]
    base = balance(target)
    groups = load_transactions(100, senders, each, target)
    v2 = nodes["v2"]
    h0 = height()
    t0 = time.time()
    traffic = Traffic(groups, 1, [RPC, RPC + 1, RPC + 3])
    clean = [nodes["v0"].rss_mb()]
    while time.time() - t0 < SOAK_SECONDS * 0.6:
        time.sleep(10)
        clean.append(nodes["v0"].rss_mb())
    v2.pause(True)
    frozen = []
    while time.time() - t0 < SOAK_SECONDS * 0.95:
        time.sleep(10)
        frozen.append(nodes["v0"].rss_mb())
    v2.pause(False)
    done = traffic.join(SOAK_SECONDS + 120)
    elapsed = time.time() - t0
    total = senders * each
    settled = wait(lambda: balance(target) == base + total, 60)
    check(f"soak: all {total} transactions applied exactly once", done and settled, f"{balance(target) - base}/{total}")
    top = height()
    check("frozen validator catches up", wait(lambda: height(RPC + 2) >= top, 120))
    check("memory stays bounded", max(clean + frozen) < 1500, clean + frozen)
    measure(f"soak: {total / elapsed:.0f} tx/s for {elapsed:.0f} s, {top - h0} blocks")
    measure(f"v0 memory MB, all up: {clean}; v2 frozen: {frozen}")


def governance():
    gov = json.loads(cli("validators", "show")[1])["governance"]
    pay("alice", gov, 10_000_000)
    nodes["v4"].start()
    check("standby v4 came up", up(RPC + 4))
    top = height()
    check("v4 follows the chain", wait(lambda: height(RPC + 4) >= top, 60))
    cli("validators", "propose", "--key", "v0.json", "--key", "v1.json", "--key", "v2.json", "--key", "v4.json", *[a for name in ("v0", "v1", "v2", "v4") for a in ("--payout", keys[name])], "--out", "change.json")
    cli("tx", "sign", "--file", "change.json", "--key", "v0.json", *PW)
    rc, out = cli("tx", "submit", "--file", "change.json", ok=False)
    check("too few signatures change nothing", rc != 0, out.strip()[:80])
    cli("tx", "sign", "--file", "change.json", "--key", "v1.json", *PW)
    cli("tx", "sign", "--file", "change.json", "--key", "v2.json", *PW)
    cli("tx", "submit", "--file", "change.json", "--wait")
    epoch = lambda p: http(p, "/v1/validators")[1]["epoch"]
    check("new epoch", wait(lambda: epoch(RPC) == 1, 30))
    members = [v["key"] for v in http(RPC, "/v1/validators")[1]["validators"]]
    check("the set is v0, v1, v2, v4", hexkeys[4] in members and hexkeys[3] not in members)
    check("v4 reached the new epoch", wait(lambda: epoch(RPC + 4) == 1, 40))
    validators.remove("v3")
    validators.append("v4")
    before = balance(keys["bob"], RPC + 4)
    pay("alice", keys["bob"], 2, port=RPC + 4)
    check("transfers work through v4", wait(lambda: all(balance(keys["bob"], p) == before + 2 for p in ports()), 30))
    check("v4 really joined", wait(lambda: "joined the validator set" in open(f"{WORK}/v4.log").read(), 10))
    check("API node crossed the epoch", wait(lambda: epoch(RPC + 10) == 1, 40))
    rewards = lambda who: int(http(RPC, f"/v1/rewards/{keys[who]}")[1]["claimable"])
    check("v3 left with what it earned", rewards("v3") > 0)
    earned = rewards("v3")
    cli("validators", "claim", "--payout", keys["v3"], "--key", "alice.json", *PW, "--wait")
    check("a claim pays the old validator", balance(keys["v3"]) == earned and rewards("v3") == 0)
    top = height()
    check("removed v3 keeps following", wait(lambda: height(RPC + 3) >= top, 30), (height(RPC + 3), top))

    nodes["pruned"] = Proc("pruned", RPC + 11, ["--follow", f"http://127.0.0.1:{RPC}", "--prune-keep", "100"])
    nodes["pruned"].start()
    check("pruning node came up", up(RPC + 11))
    top = height()
    check("pruning node synced the whole chain", wait(lambda: height(RPC + 11) >= top, 120), f"height {top}")
    old, _ = http(RPC + 11, f"/v1/proofs/accounts/{keys['bob']}?height=1")
    new, _ = http(RPC + 11, f"/v1/proofs/accounts/{keys['bob']}")
    check("old state pruned, new state kept", top > 150 and old >= 400 and new == 200, (top, old, new))

    for name in validators:
        nodes[name].kill()
    for name in validators:
        nodes[name].start()
    check("back from a power cut in the new epoch", all(up(nodes[n].port) for n in validators))
    before = balance(keys["bob"], RPC + 4)
    pay("alice", keys["bob"], 2, port=RPC + 4)
    check("the new set still works", wait(lambda: all(balance(keys["bob"], p) == before + 2 for p in ports()), 30))


def wallet():
    pay("alice", keys["live"], 50_000_000)
    cli("vault", "create", "--delay-secs", 60, "--recovery-key", "rec.json", "--key", "live.json", *PW, "--wait")
    env = dict(os.environ, QUBITS_LIVE_RPC=f"http://127.0.0.1:{RPC}", QUBITS_LIVE_KEY=f"{WORK}/bob.json",
               QUBITS_LIVE_VAULT_KEY=f"{WORK}/live.json", QUBITS_LIVE_PASSWORD=PASSWORD)
    p = subprocess.run(["npx", "vitest", "run", "tests/live.test.ts"], cwd=f"{os.path.dirname(BACKEND)}/extension",
                       env=env, capture_output=True, text=True, timeout=120)
    out = re.sub(r"\x1b\[[0-9;]*m", "", p.stdout + p.stderr)
    line = re.search(r"Tests\s+.*", out)
    summary = line.group(0) if line else out[-200:]
    check("wallet live tests", p.returncode == 0 and "skipped" not in summary and "passed" in summary, summary if p.returncode == 0 else out[-1500:])


def snapshot():
    nodes["spare"] = Proc("spare", RPC + 12, ["--follow", f"http://127.0.0.1:{RPC}", "--snapshot-if-behind", "10"])
    t0 = time.time()
    nodes["spare"].start()
    check("snapshot node came up", up(RPC + 12))
    top = height()
    check("caught up", wait(lambda: height(RPC + 12) >= top, 90), f"height {top}")
    elapsed = time.time() - t0
    check("took the state, not the history", metric("qubits_snapshot_syncs_total", RPC + 12) == 1 and http(RPC + 12, "/v1/blocks/1")[0] == 404)
    mine, theirs = http(RPC + 12, "/v1/epochs")[1], http(RPC, "/v1/epochs")[1]
    check("walked the epochs", mine == theirs and len(mine["epochs"]) >= 2, mine)
    h = height(RPC + 12)
    same_root = http(RPC + 12, f"/v1/blocks/{h}")[1]["state_root"] == http(RPC, f"/v1/blocks/{h}")[1]["state_root"]
    check("same state as the validators", same_root and balance(keys["sink"], RPC + 12) == balance(keys["sink"]))
    code, proof = http(RPC + 12, f"/v1/proofs/accounts/{keys['sink']}")
    check("proves accounts from the restored state", code == 200 and "proof" in json.dumps(proof), code)
    before = balance(keys["bob"])
    pay("alice", keys["bob"], 1, port=RPC + 12, waiting=False)
    check("forwards transactions", wait(lambda: balance(keys["bob"]) == before + 1, 20))
    check("and follows on", wait(lambda: balance(keys["bob"], RPC + 12) == before + 1, 20))
    measure(f"snapshot: a new node joined at height {top} in {elapsed:.1f} s")


def history():
    nodes["trimmed"] = Proc("trimmed", RPC + 13, ["--follow", f"http://127.0.0.1:{RPC}", "--snapshot-if-behind", "10", "--history-keep", "15s"])
    nodes["trimmed"].start()
    check("trimmed node came up", up(RPC + 13))
    check("caught up", wait(lambda: height(RPC + 13) >= height(), 60))
    start = status(RPC + 13)["blocks_from"]
    target = keys["carol"]
    # the pruner keeps 128 blocks below the head whatever their age, so get well past the pivot
    traffic = Traffic(load_transactions(441, 4, 120, target), 4, [RPC])
    traffic.join(90)
    check("old blocks dropped", wait(lambda: status(RPC + 13)["blocks_from"] > start, 60), (start, status(RPC + 13)["blocks_from"]))
    frm = status(RPC + 13)["blocks_from"]
    code, body = http(RPC + 13, f"/v1/blocks/{frm - 1}")
    check("dropped block answers 404 with the window", code == 404 and "not kept" in json.dumps(body), (code, body))
    check("recent block still served", http(RPC + 13, f"/v1/blocks/{height(RPC + 13)}")[0] == 200)
    check("recent blocks kept", height(RPC + 13) - frm >= 128, height(RPC + 13) - frm)
    check("same state as the validators", wait(lambda: balance(target, RPC + 13) == balance(target), 20))
    check("epochs intact", http(RPC + 13, "/v1/epochs")[1] == http(RPC, "/v1/epochs")[1])
    nodes["joiner"] = Proc("joiner", RPC + 14, ["--follow", f"http://127.0.0.1:{RPC + 13}", "--snapshot-if-behind", "10"])
    nodes["joiner"].start()
    check("a fresh node joins from the trimmed one", up(RPC + 14) and wait(lambda: height(RPC + 14) >= height(RPC + 13) - 2, 60))
    check("by snapshot", metric("qubits_snapshot_syncs_total", RPC + 14) == 1)
    check("with the same state", wait(lambda: balance(target, RPC + 14) == balance(target), 30))
    measure(f"history: trimmed node holds blocks from {frm} of {height(RPC + 13)}")


def eras():
    offered = http(RPC, "/v1/eras")[1]
    check("archive validator offers complete eras", offered["length"] == 256 and len(offered["eras"]) >= 3, offered)
    got = [l for l in cli_node("era", "fetch", "--from", f"http://127.0.0.1:{RPC}", "--out", "eras") if ".era" in l]
    files = sorted(f for f in os.listdir(f"{WORK}/eras") if f.endswith(".era"))
    check("fetched them", len(files) == len(offered["eras"]), (len(files), got[:2]))
    verified = cli_node("era", "verify", "--genesis", "genesis.json", *[f"eras/{f}" for f in files])
    check("they verify against the genesis file", all(": ok," in l for l in verified) and len(verified) == len(files), verified[:2])
    bad = bytearray(open(f"{WORK}/eras/{files[1]}", "rb").read())
    bad[len(bad) // 2] ^= 1
    open(f"{WORK}/eras/bad.era", "wb").write(bad)
    rc, out = subprocess.run([NODE, "era", "verify", "--genesis", "genesis.json", "eras/bad.era"], cwd=WORK, capture_output=True, text=True), None
    check("a corrupted one is refused", rc.returncode != 0 and "INVALID" in rc.stdout, rc.stdout.strip()[-80:])
    # the joiner started from a snapshot: give it the history back, newest era first
    joiner = nodes["joiner"]
    early = http(RPC, "/v1/blocks/1")[1]["transaction_ids"]
    before = status(joiner.port)["blocks_from"]
    joiner.kill()
    cli_node("era", "fetch", "--from", f"http://127.0.0.1:{RPC}", "--out", "eras-joiner", "--to", before)
    needed = sorted(os.listdir(f"{WORK}/eras-joiner"), key=lambda f: int(re.search(r"-(\d{5})(?:-to-\d+)?\.era$", f).group(1)), reverse=True)
    check("fetched the part of the current era and the eras below", "-to-" in needed[0] and len(needed) == (before - 1) // 256 + 1, needed)
    imported = cli_node("era", "import", "--data-dir", "joiner", *[f"eras-joiner/{f}" for f in needed])
    check("put back below the snapshot", sum("put back" in l for l in imported) == len(needed) and "blocks held from 1" in imported[-1], imported[-1:])
    joiner.start()
    check("joiner back up", up(joiner.port))
    check("serves the old blocks", http(joiner.port, "/v1/blocks/1")[0] == 200 and status(joiner.port)["blocks_from"] == 1)
    check("finds old transactions", not early or http(joiner.port, f"/v1/transactions/{early[0]}")[0] == 200)
    check("and offers eras itself", http(joiner.port, "/v1/eras")[1]["eras"] == offered["eras"])
    # a brand new node built from the files alone, executing every block
    subprocess.run([NODE, "init", "--genesis", "genesis.json", "--data-dir", "rebuilt"], cwd=WORK, check=True, capture_output=True)
    rebuilt = cli_node("era", "import", "--data-dir", "rebuilt", *[f"eras/{f}" for f in files])
    check("a node rebuilt from era files executes them all", sum("executed blocks" in l for l in rebuilt) == len(files) and f"height {len(files) * 256}" in rebuilt[-1], rebuilt)
    nodes["rebuilt"] = Proc("rebuilt", RPC + 15, ["--follow", f"http://127.0.0.1:{RPC}"])
    nodes["rebuilt"].start()
    check("and catches up from there", up(RPC + 15) and wait(lambda: height(RPC + 15) >= height() - 2, 60))
    h = len(offered["eras"]) * 256
    check("with the validators' state", http(RPC + 15, f"/v1/blocks/{h}")[1]["state_root"] == http(RPC, f"/v1/blocks/{h}")[1]["state_root"])
    measure(f"eras: {len(files)} files of 256 blocks, {sum(os.path.getsize(f'{WORK}/eras/{f}') for f in files) // 1_000_000} MB")


def cli_node(*args):
    p = subprocess.run([NODE, *map(str, args)], cwd=WORK, capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError(f"qubits-node {' '.join(map(str, args))}: {p.stdout}{p.stderr}")
    return p.stdout.splitlines()


def agreement():
    names = [n for n in ("v0", "v1", "v2", "v3", "v4", "api", "spare", "joiner", "rebuilt") if n in nodes and nodes[n].alive()]
    wait(lambda: len({height(nodes[n].port) for n in names}) == 1, 60)
    tops = {n: height(nodes[n].port) for n in names}
    check("everyone at the same height", len(set(tops.values())) == 1, tops)
    top = min(tops.values())
    # a node that joined from a snapshot has no blocks below it
    starts = {n: status(nodes[n].port)["blocks_from"] for n in names}

    def compare(h):
        holders = [n for n in names if starts[n] <= h]
        blocks = {http(nodes[n].port, f"/v1/blocks/{h}/raw")[1].get("block") for n in holders}
        return h if len(blocks) != 1 else None

    with cf.ThreadPoolExecutor(16) as pool:
        diverged = [h for h in pool.map(compare, range(1, top + 1)) if h]
    check(f"blocks 1..{top} identical on {len(names)} nodes", not diverged, diverged[:5])
    check("same state root", len({status(nodes[n].port)["state_root"] for n in names}) == 1)


def logs():
    bad = {}
    for name in nodes:
        text = open(nodes[name].log).read()
        hits = re.findall(r".*(?:panicked|safety violation|fatal:| ERROR ).*", text)
        if hits:
            bad[name] = hits[:2]
    check("no panics, safety violations or errors in the logs", not bad, bad)
    for name, proc in nodes.items():
        check(f"{name} running", proc.alive())


PHASES = [
    ("setup", setup), ("transfers", transfers), ("vault", vault), ("multisig", multisig), ("api", api_node),
    ("burst", burst), ("throughput", throughput), ("hostile", hostile), ("failures", failures),
    ("power", power_cuts), ("network", network), ("wide-area", wide_area), ("byzantine", byzantine), ("soak", soak), ("governance", governance), ("snapshot", snapshot), ("history", history), ("eras", eras), ("wallet", wallet),
    ("agreement", agreement), ("logs", logs),
]


def main():
    only = set(sys.argv[1].split(",")) | {"setup"} if len(sys.argv) > 1 else None
    started = time.time()
    log(f"working in {WORK}")
    try:
        for name, phase in PHASES:
            if only and name not in only:
                continue
            log(f"\n{name}")
            t0 = time.time()
            try:
                phase()
            except Exception as e:
                check(f"{name} finished", False, e)
                traceback.print_exc()
            log(f"  ({time.time() - t0:.0f} s)")
    finally:
        for proc in nodes.values():
            proc.kill()
    failed = [r for r in results if not r[1]]
    log(f"\n{len(results) - len(failed)} passed, {len(failed)} failed, {time.time() - started:.0f} s")
    for text in measurements:
        log(f"  {text}")
    for name, _, detail in failed:
        log(f"  FAILED {name}: {detail}")
    sys.exit(1 if failed else 0)


main()
