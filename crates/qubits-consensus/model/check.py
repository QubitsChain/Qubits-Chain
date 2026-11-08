#!/usr/bin/env python3
"""Asks an SMT solver whether the voting rules of `Engine::vote_kind` allow a fork.

Chaos tests run the real engine but rarely reach the orderings an attack needs. Here every
ordering is covered at once: a run is a set of event times, the protocol is constraints on them,
and "unsat" means no schedule of any length produces two conflicting final blocks, within R rounds
and n validators.

The model favours the attacker. Every leader is Byzantine, so any block on any block exists. The
f Byzantine validators vote for everything and report any lock. The network delivers certificates
to whoever it likes at any time, or never. Honest validators may enter any round at any time, which
they can't really do without a certificate. Only the voting rules protect the chain.

Two blocks per round are enough: a fork is two chains, and any other vote only ties its voter's
hands. "Final" is what a FinalityProof shows: a certified child in the very next round.

Each rule can be switched off, and then a fork must appear. That shows both that the rule is needed
and that the model can see the attack.

    pip install z3-solver
    python3 crates/qubits-consensus/model/check.py            # n=4, up to 6 rounds, every rule
    python3 crates/qubits-consensus/model/check.py 7 5        # n=7, 5 rounds
"""

import sys
import time

from z3 import And, Bool, Distinct, If, Implies, Int, Not, Or, PbGe, Solver, Sum, sat, unsat

KINDS = ("optimistic", "normal", "fallback")
RULES = (
    "optimistic needs a clean past",
    "optimistic needs the lock",
    "one vote before optimistic",
    "normal respects optimistic",
    "one normal or fallback vote",
    "fallback needs the rank",
    "no vote after timing out",
    "timeouts report the lock",
    "votes need the parent's certificate",
    "final needs consecutive rounds",
    "certificates hold one kind",
)


def build(n, rounds, off=frozenset()):
    f = (n - 1) // 3
    honest = range(n - f)
    needed = n - f - f  # honest votes in a quorum, the Byzantine ones count for everything
    on = lambda rule: rule not in off

    s = Solver()
    blocks = [(r, i) for r in range(1, rounds + 1) for i in (0, 1)]
    genesis = (0, 0)
    everything = [genesis] + blocks
    index = {b: i for i, b in enumerate(everything)}

    parent = {b: Int(f"parent_{b[0]}_{b[1]}") for b in blocks}
    for b in blocks:
        s.add(Or([parent[b] == index[p] for p in everything if p[0] < b[0]]))

    def round_of_parent(b):
        return Sum([If(parent[b] == index[p], p[0], 0) for p in everything if p[0] < b[0]])

    def is_parent(b, p):
        return parent[b] == index[p]

    voted = {}
    vote_time = {}
    for h in honest:
        for b in blocks:
            for k in KINDS:
                voted[h, b, k] = Bool(f"voted_{h}_{b[0]}_{b[1]}_{k}")
                vote_time[h, b, k] = Int(f"vote_time_{h}_{b[0]}_{b[1]}_{k}")

    cert = {genesis: True}
    cert_time = {genesis: 0}
    for b in blocks:
        cert[b] = Bool(f"cert_{b[0]}_{b[1]}")
        cert_time[b] = Int(f"cert_time_{b[0]}_{b[1]}")
        quorum = lambda kinds: PbGe(
            [
                (And(Or([voted[h, b, k] for k in kinds]),
                     *[Implies(voted[h, b, k], vote_time[h, b, k] < cert_time[b]) for k in kinds]), 1)
                for h in honest
            ],
            needed,
        )
        if on("certificates hold one kind"):
            s.add(Implies(cert[b], Or([quorum((k,)) for k in KINDS])))
        else:
            s.add(Implies(cert[b], quorum(KINDS)))
        s.add(cert_time[b] > 0)

    learned = {}
    learn_time = {}
    for h in honest:
        for b in everything:
            learned[h, b] = Bool(f"learned_{h}_{b[0]}_{b[1]}")
            learn_time[h, b] = Int(f"learn_time_{h}_{b[0]}_{b[1]}")
            s.add(Implies(learned[h, b], And(cert[b] if b != genesis else True,
                                             learn_time[h, b] > cert_time[b])))
        s.add(learned[h, genesis], learn_time[h, genesis] == 1)

    timed_out = {}
    timeout_time = {}
    rank = {}
    enter = {}
    for h in honest:
        for r in range(0, rounds + 2):
            enter[h, r] = Int(f"enter_{h}_{r}")
            s.add(enter[h, r] >= 0)
        for r in range(0, rounds + 1):
            s.add(enter[h, r] <= enter[h, r + 1])
        for r in range(1, rounds + 1):
            timed_out[h, r] = Bool(f"timed_out_{h}_{r}")
            timeout_time[h, r] = Int(f"timeout_time_{h}_{r}")
            rank[h, r] = Int(f"rank_{h}_{r}")
            t = timeout_time[h, r]
            s.add(Implies(timed_out[h, r], And(enter[h, r] <= t, t < enter[h, r + 1])))
            # learning a certificate moves a validator past that round
            if on("timeouts report the lock"):
                for b in everything:
                    s.add(Implies(And(timed_out[h, r], learned[h, b], learn_time[h, b] < t),
                                  rank[h, r] >= b[0]))
            s.add(rank[h, r] >= 0)
        for b in blocks:
            s.add(Implies(learned[h, b], learn_time[h, b] >= enter[h, b[0] + 1]))

    # a validator does one thing at a time
    for h in honest:
        events = [vote_time[h, b, k] for b in blocks for k in KINDS]
        events += [timeout_time[h, r] for r in range(1, rounds + 1)]
        s.add(Distinct(events))

    def timed_out_before(h, first, t):
        return Or([And(timed_out[h, r], timeout_time[h, r] < t)
                   for r in range(max(first, 1), rounds + 1)] or [False])

    def has_voted_before(h, first, t, kinds):
        return Or([And(voted[h, b, k], vote_time[h, b, k] < t)
                   for b in blocks if b[0] >= first for k in kinds] or [False])

    for h in honest:
        for b in blocks:
            v = b[0]
            for k in KINDS:
                t = vote_time[h, b, k]
                s.add(Implies(voted[h, b, k], And(enter[h, v] <= t, t < enter[h, v + 1])))
                if on("no vote after timing out"):
                    s.add(Implies(voted[h, b, k], Not(timed_out_before(h, v, t))))

            # optimistic
            t = vote_time[h, b, "optimistic"]
            need = []
            if on("optimistic needs a clean past"):
                need.append(Not(timed_out_before(h, v - 1, t)))
            if on("optimistic needs the lock"):
                for p in everything:
                    if p[0] != v - 1:
                        need.append(Not(is_parent(b, p)))
                        continue
                    need.append(Implies(is_parent(b, p),
                                        And(learned[h, p], learn_time[h, p] < t)))
                    for other in everything:
                        if other[0] >= v:
                            need.append(Not(And(learned[h, other], learn_time[h, other] < t)))
                        elif other[0] == v - 1 and other != p:
                            need.append(Implies(is_parent(b, p), Not(And(
                                learned[h, other],
                                learn_time[h, other] < learn_time[h, p]))))
            elif on("votes need the parent's certificate"):
                need.append(Or([And(is_parent(b, p), cert[p]) for p in everything if p[0] < v]))
            if on("one vote before optimistic"):
                need.append(Not(has_voted_before(h, v, t, ("normal", "fallback", "optimistic"))))
            s.add(Implies(voted[h, b, "optimistic"], And(need)))

            # normal: arrives with the certificate of the round before
            t = vote_time[h, b, "normal"]
            need = [round_of_parent(b) == v - 1]
            for p in everything:
                if p[0] < v:
                    certified = And(cert[p], cert_time[p] < t,
                                    learned[h, p], learn_time[h, p] <= t)
                    if on("votes need the parent's certificate"):
                        need.append(Implies(is_parent(b, p), certified))
            if on("one normal or fallback vote"):
                need.append(Not(has_voted_before(h, v, t, ("normal", "fallback"))))
            if on("normal respects optimistic"):
                for other in blocks:
                    if other[0] == v and other != b:
                        need.append(Not(And(voted[h, other, "optimistic"],
                                            vote_time[h, other, "optimistic"] < t)))
            s.add(Implies(voted[h, b, "normal"], And(need)))

            # fallback: arrives with a TC for the round before and the parent's certificate
            t = vote_time[h, b, "fallback"]
            need = []
            for p in everything:
                if p[0] >= v:
                    continue
                certified = And(cert[p], cert_time[p] < t, learned[h, p], learn_time[h, p] <= t)
                if on("votes need the parent's certificate"):
                    need.append(Implies(is_parent(b, p), certified))
                if v >= 2 and on("fallback needs the rank"):
                    # n-f timeouts, whose highest reported lock is at most the parent's round
                    low = [(And(timed_out[w, v - 1], timeout_time[w, v - 1] < t,
                                rank[w, v - 1] <= p[0]), 1) for w in honest]
                    need.append(Implies(is_parent(b, p), PbGe(low, needed)))
            if v < 2:
                need.append(False)
            if on("one normal or fallback vote"):
                need.append(Not(has_voted_before(h, v, t, ("normal", "fallback"))))
            s.add(Implies(voted[h, b, "fallback"], And(need)))

    # two conflicting final blocks
    descends = {}
    for b in everything:
        for a in everything:
            if b == a:
                descends[b, a] = True
            elif b == genesis or b[0] <= a[0]:
                descends[b, a] = False
            else:
                descends[b, a] = Or([And(is_parent(b, p), descends[p, a])
                                     for p in everything if p[0] < b[0]])

    def final(x):
        if on("final needs consecutive rounds"):
            children = [c for c in blocks if c[0] == x[0] + 1]
        else:
            children = [c for c in blocks if c[0] > x[0]]
        return Or([And(is_parent(c, x), cert[c]) for c in children] or [False])

    conflicts = []
    for x in blocks:
        for y in blocks:
            if x[0] <= y[0] and x != y:
                conflicts.append(And(final(x), final(y), Not(descends[y, x])))
    s.add(Or(conflicts))
    return s


def run(n, rounds, off=frozenset()):
    started = time.time()
    answer = build(n, rounds, off).check()
    return answer, time.time() - started


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 4
    rounds = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    failed = False
    for r in range(3, rounds + 1):
        answer, took = run(n, r)
        print(f"n={n} rounds={r}: {'no fork possible' if answer == unsat else answer} ({took:.1f} s)",
              flush=True)
        failed |= answer != unsat
    attack_rounds = min(rounds, 5)
    for rule in RULES:
        answer, took = run(n, attack_rounds, frozenset([rule]))
        found = answer == sat
        print(f"without '{rule}': {'fork found' if found else answer} ({took:.1f} s)", flush=True)
        failed |= not found
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
