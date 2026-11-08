"""A chain run by one validator, with the node features around it: an API node joining from a
snapshot and trimming history, era files rebuilding a node, and a validator restart. Needs the
release binaries, like e2e.py. About two minutes.

    python3 crates/qubits-e2e/solo.py
"""
import json, os, subprocess, sys, time
HERE = os.path.dirname(os.path.abspath(__file__))
src = open(f'{HERE}/e2e.py').read().rsplit('\nmain()', 1)[0]
g = {'__name__': 'e2e', '__file__': f'{HERE}/e2e.py'}
exec(compile(src, 'e2e.py', 'exec'), g)
WORK, RPC, NODE, Proc, tool, http, post_tx, up, height, wait, metric, status, balance, keys, pub, new_key, cli, check, log = [g[k] for k in
    ('WORK', 'RPC', 'NODE', 'Proc', 'tool', 'http', 'post_tx', 'up', 'height', 'wait', 'metric', 'status', 'balance', 'keys', 'pub', 'new_key', 'cli', 'check', 'log')]
open(f"{WORK}/pw", "w").write(g['PASSWORD'] + "\n")
for name in ("v0", "alice", "sink"):
    new_key(name)
load = tool("addrs", 110)
governance = tool("governance")[0]
genesis = {"chain_id": "qubits-solo", "timestamp_ms": int(time.time() * 1000) - 1000,
           "params": {"min_fee_per_byte": 1, "max_block_transactions": 1000},
           "validators": [{"key": pub("v0"), "payout": keys["v0"]}], "accounts": [{"address": a, "balance": "1000000000000"} for a in [keys["alice"], governance, *load]]}
json.dump(genesis, open(f"{WORK}/genesis.json", "w"))
for name in ("v0", "api", "rebuilt"):
    subprocess.run([NODE, "init", "--genesis", "genesis.json", "--data-dir", name], cwd=WORK, check=True, capture_output=True)
g['nodes']["v0"] = Proc("v0", RPC, ["--validator-key", "v0.json", *g['PW']]).start()
check("single validator up", up(RPC))
# a token contract, deployed through governance
token_wasm = os.path.abspath(f"{HERE}/../../contracts/out/token.wasm")
cli("contract", "deploy", token_wasm, "--arg", keys["alice"], "--arg", "1000000", "--arg", '"Solo Dollar"', "--arg", '"SOLO"', "--arg", "u64:6", "--out", "token.json")
cli("tx", "sign", "--file", "token.json", "--key", "v0.json", *g['PW'])
deployed = cli("tx", "submit", "--file", "token.json", "--wait")[1]
token = next(l.split()[1] for l in deployed.splitlines() if l.startswith("contract "))
check("contract deployed by governance", token.startswith("qb1"), token)
def held(who, port=RPC):
    return cli("contract", "view", f"{token}.balance_of({who})", "--as", "u128", port=port)[1].strip()
sent = cli("contract", "call", f"{token}.transfer({keys['sink']}, 2500)", "--key", "alice.json", *g['PW'], "--wait")[1]
check("contract called by address and function", held(keys["sink"]) == "2500" and "event transfer" in sent, sent)
code, refused = cli("contract", "call", f"{token}.mint({keys['alice']}, 5)", "--key", "alice.json", *g['PW'], "--wait", ok=False)
check("owner can mint", code == 0, refused)
code, refused = cli("contract", "call", f"{token}.transfer({keys['sink']}, 999999999)", "--key", "alice.json", *g['PW'], "--wait", ok=False)
check("a revert is reported and included", code != 0 and "reverted: balance too low" in refused, refused)
# an AMM pool against the native token, and a trade
amm_wasm = os.path.abspath(f"{HERE}/../../contracts/out/amm.wasm")
cli("contract", "deploy", amm_wasm, "--out", "amm.json")
cli("tx", "sign", "--file", "amm.json", "--key", "v0.json", *g['PW'])
amm = next(l.split()[1] for l in cli("tx", "submit", "--file", "amm.json", "--wait")[1].splitlines() if l.startswith("contract "))
cli("contract", "call", f"{token}.approve({amm}, 100000)", "--key", "alice.json", *g['PW'], "--wait")
cli("contract", "call", f"{amm}.add_liquidity({token}, native, 100000, 400000, 0, 0, deadline:600)", "--amount", "400000", "--key", "alice.json", *g['PW'], "--wait")
def pool(port=RPC):
    return cli("contract", "view", f"{amm}.pool({token}, native)", "--as", "u128s", port=port)[1].strip()
check("a pool opened", pool() == "100000 400000 200000", pool())
traded = cli("contract", "call", f"{amm}.swap(native, {token}, 40000, 8000, deadline:600)", "--amount", "40000", "--key", "alice.json", *g['PW'], "--wait")[1]
check("a swap went through the market and the token", pool() == "90934 440000 200000" and "event swap" in traded, pool())
h0 = height()
t0 = time.time()
sender_groups = g['load_transactions'](0, 50, 40, keys["sink"])
traffic = g['Traffic'](sender_groups, 1, [RPC])  # slow, so the chain grows block by block
done = traffic.join(120)
settled = wait(lambda: balance(keys["sink"]) == 2000, 60)
check("2000 transfers included by one validator", done and settled, f"{balance(keys['sink'])} in {time.time() - t0:.1f} s, {height() - h0} blocks")
earned = int(http(RPC, f"/v1/rewards/{keys['v0']}")[1]["claimable"])
check("fees wait for the validator", earned > 0, str(earned))
cli("validators", "claim", "--payout", keys["v0"], "--key", "alice.json", *g['PW'], "--wait")
check("a claim pays its payout address", balance(keys["v0"]) >= earned, str(balance(keys["v0"])))
blocks = [http(RPC, f"/v1/blocks/{h}")[1] for h in range(h0 + 1, height() + 1)]
gaps = sorted(b["timestamp_ms"] - a["timestamp_ms"] for a, b in zip(blocks, blocks[1:]))
log(f"  --    blocks {gaps[len(gaps)//2]} ms apart (median), min {gaps[0]}, max {gaps[-1]}")
check("snapshot offered", http(RPC, "/v1/state/snapshot")[0] == 200)
g['nodes']["api"] = Proc("api", RPC + 10, ["--follow", f"http://127.0.0.1:{RPC}", "--snapshot-if-behind", "10", "--history-keep", "15s"]).start()
check("api node up", up(RPC + 10))
check("api node joined from a snapshot", wait(lambda: height(RPC + 10) >= height(), 60) and metric("qubits_snapshot_syncs_total", RPC + 10) == 1)
check("same state", balance(keys["sink"], RPC + 10) == 2000)
check("contract state came with the snapshot", held(keys["sink"], RPC + 10) == "2500" and pool(RPC + 10) == pool())
check("and so did the list of contracts", http(RPC + 10, "/v1/contracts")[1]["contracts"] == [token, amm])
offered = http(RPC, "/v1/eras")[1]
check("validator offers eras", len(offered["eras"]) >= 1, offered)
files = [l for l in g['cli_node']("era", "fetch", "--from", f"http://127.0.0.1:{RPC}", "--out", "eras") if ".era" in l]
names = sorted(f for f in os.listdir(f"{WORK}/eras") if f.endswith(".era"))
verified = g['cli_node']("era", "verify", "--genesis", "genesis.json", *[f"eras/{f}" for f in names])
check("eras verify", all(": ok," in l for l in verified), verified)
rebuilt = g['cli_node']("era", "import", "--data-dir", "rebuilt", *[f"eras/{f}" for f in names])
check("rebuilt from era files", sum("executed" in l for l in rebuilt) == len(names), rebuilt[-1:])
g['nodes']["rebuilt"] = Proc("rebuilt", RPC + 15, ["--follow", f"http://127.0.0.1:{RPC}"]).start()
check("rebuilt node catches up", up(RPC + 15) and wait(lambda: height(RPC + 15) >= height(), 60))
check("eras replayed the contract to the same state", held(keys["sink"], RPC + 15) == "2500" and pool(RPC + 15) == pool())
traffic2 = g['Traffic'](g['load_transactions'](50, 60, 20, keys["sink"]), 1, [RPC])
traffic2.join(120)
check("more traffic while the api node trims history", wait(lambda: balance(keys["sink"]) == 3200, 60), balance(keys["sink"]))
check("api node dropped old blocks", wait(lambda: status(RPC + 10)["blocks_from"] > 1 + 64, 60), status(RPC + 10)["blocks_from"])
# restart the validator: it must resume on its own chain
g['nodes']["v0"].kill(); g['nodes']["v0"].start()
check("validator restarts", up(RPC))
before = balance(keys["sink"])
g['pay']("alice", keys["sink"], 1)
check("and commits again after the restart", balance(keys["sink"]) == before + 1)
cli("contract", "call", f"{token}.transfer({keys['sink']}, 500)", "--key", "alice.json", *g['PW'], "--wait")
check("contracts survive the restart", held(keys["sink"]) == "3000")
check("every node agrees on the contract", wait(lambda: held(keys["sink"], RPC + 10) == "3000" and held(keys["sink"], RPC + 15) == "3000", 30))
for n in g['nodes'].values(): n.kill()
failed = [r for r in g['results'] if not r[1]]
log(f"\n{len(g['results']) - len(failed)} passed, {len(failed)} failed")
sys.exit(1 if failed else 0)
