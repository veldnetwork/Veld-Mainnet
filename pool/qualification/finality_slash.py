"""Funded equivocation through real peer intake and canonical settlement.

Only disposable lab keys deliberately sign conflicting claims. The ordinary
managed validator's commitment journal is not bypassed or modified. This is
called after the seven-bond finality/independent pool-carrier exercise.
"""

from fractions import Fraction
import json
import subprocess
import time
from ..protocol import encode, Refused
from .progress import ValidationProgress


def exercise(
    *,
    rpc,
    independent,
    node,
    observer,
    members,
    snapshot,
    target,
    block,
    state,
    build,
    out,
    mine,
    sign,
    check,
    report,
    save,
):
    offender = members[-1]
    address = offender['address']
    reporter = members[-2]

    def units(value):
        amount = Fraction(str(value)) * 100000000
        assert amount.denominator == 1
        return int(amount)

    def balance(who, chain=rpc):
        return units(chain.call('getbalance', who)['balance_veld'])

    def record(chain=rpc):
        return next(
            row for row in chain.call('getbondvaultinfo')['validators'] if row['address'] == address
        )

    def wait_chain():
        tip = rpc.call('getbestblockhash')
        progress = ValidationProgress(
            independent.call('getblockcount'), rpc.call('getblockcount'), time.monotonic()
        )
        while independent.call('getbestblockhash') != tip:
            assert node.poll() is None and observer.poll() is None
            progress.observe(independent.call('getblockcount'), time.monotonic())
            time.sleep(2)
        assert independent.call('getstatedigest') == rpc.call('getstatedigest')

    def relay(wire):
        observer.stdin.write('relayvote ' + wire + '\n')
        observer.stdin.flush()

    def evidence():
        return [
            row
            for row in rpc.call('listfinalityevidence', '0', '100')['evidence']
            if row['pubkey_hex'] == offender['pubkey']
        ]

    # The already funded sixth member has unused ordinary change for the
    # reporter fee. Its active bond and yield remain independently accounted.
    check(
        'equivocation reporter fee has separate spendable funding',
        balance(reporter['address']) >= 100000,
    )
    original = record()
    offender_before = balance(address)
    reporter_before = balance(reporter['address'])
    check(
        'equivocation target has the genuine full individual bond',
        original['principal_held'] and units(original['bond_veld']) == 10000 * 100000000,
    )
    claims = []
    sibling = ('1' if block[0] != '1' else '2') + block[1:]
    for destination in (block, sibling):
        intent = dict(
            epoch=str(snapshot['epoch']),
            set_root=snapshot['set_root'],
            phase='1',
            target_height=str(target),
            target_hash=destination,
            source_height='0',
            source_hash='0' * 64,
        )
        wire = (
            subprocess.run(
                [str(build / 'pool-lab-sign'), str(offender['key']), 'finality'],
                input=encode(intent) + b'\n',
                capture_output=True,
                check=True,
                timeout=120,
            )
            .stdout.decode()
            .strip()
        )
        claims.append(wire)
    relay(claims[0])
    relay(claims[0])
    time.sleep(2)
    check('retransmitting the identical genuine finality vote is not slashable', not evidence())
    relay(claims[1])
    deadline = time.monotonic() + 60
    while not evidence():
        assert node.poll() is None and observer.poll() is None
        if time.monotonic() >= deadline:
            raise TimeoutError('real P2P equivocation evidence intake')
        time.sleep(0.1)
    rows = evidence()
    check('real authenticated peer intake stores one conflicting-vote proof', len(rows) == 1)
    evidence_id = rows[0]['evidence_id']
    pair = rpc.call('getfinalityevidence', evidence_id)
    check(
        'durable proof binds both exact signed votes',
        {pair['vote_a_hex'], pair['vote_b_hex']} == set(claims),
    )
    (out / 'equivocation-evidence.json').write_text(json.dumps(pair, indent=2) + '\n')
    prepared = rpc.call('preparefinalityslash', reporter['address'], evidence_id)
    txid = sign(prepared, reporter['key'])
    slashed = record()
    check(
        'funded canonical slash removes only the equivocal member',
        slashed['slashed_equivocation']
        and slashed['slashed']
        and sum(bool(v['slashed']) for v in rpc.call('getbondvaultinfo')['validators']) == 1,
    )
    try:
        rpc.call('preparefinalityslash', reporter['address'], evidence_id)
    except Refused:
        pass
    else:
        raise AssertionError('same equivocation must not incur a second slash')
    check(
        'equivocation reporter paid only the canonical transaction fee',
        reporter_before - balance(reporter['address']) == 100000,
    )
    boundary = slashed['settlement_boundary']
    assert boundary > rpc.call('getblockcount')
    unvested = units(slashed['yield_accrued_veld'])
    settlement_events = []
    burned = 0
    tag = b'VELD_BURN|FINALITY_EQUIVOCATION|v1'
    expected_burn_script = (bytes([0x6A, len(tag)]) + tag).hex()

    def capture_settlement():
        nonlocal burned
        height = rpc.call('getblockcount')
        if height % 480:
            return
        current = rpc.call('getblock', rpc.call('getbestblockhash'))
        transactions = [rpc.call('gettransaction', tx, str(height)) for tx in current['tx']]
        burned += sum(
            int(output['value_units'])
            for tx in transactions
            for output in tx['vout']
            if output['script_pubkey'] == expected_burn_script
        )
        settlement_events.append(dict(height=height, transactions=transactions))

    while rpc.call('getblockcount') < boundary - 1:
        height = mine()
        capture_settlement()
        if height % 120 == 0:
            report['equivocation_progress'] = dict(height=height, settlement_boundary=boundary)
            save()
    check(
        'equivocation principal remains held until canonical settlement',
        record()['principal_held'] and balance(address) == offender_before,
    )
    mine()
    capture_settlement()
    check(
        'equivocation returns no principal or unvested yield to the offender',
        not record()['principal_held']
        and balance(address) == offender_before
        and units(record()['yield_accrued_veld']) == 0,
    )
    # The native boundary plan combines this offender's confiscated tranches
    # into one yield settlement. Principal and yield round separately.
    (out / 'equivocation-settlement.json').write_text(
        json.dumps(settlement_events, indent=2) + '\n'
    )
    bounty = balance(reporter['address']) - (reporter_before - 100000)
    check(
        'equivocation bounty exactly matches principal and confiscated yield',
        bounty == 2500 * 100000000 + unvested // 4,
    )
    check(
        'equivocation burn plus bounty exactly accounts for all forfeited funds',
        burned + bounty == 10000 * 100000000 + unvested,
    )
    wait_chain()
    check(
        'independent native node agrees on equivocation balances and custody',
        independent.call('getbondvaultinfo') == rpc.call('getbondvaultinfo')
        and balance(address, independent) == balance(address)
        and balance(reporter['address'], independent) == balance(reporter['address']),
    )
    report['equivocation'] = dict(
        evidence_id=evidence_id,
        slash_txid=txid,
        settlement_height=boundary,
        offender=address,
        reporter=reporter['address'],
        reporter_bounty_units=str(bounty),
        forfeited_yield_units=str(unvested),
        burned_units=str(burned),
        independent_state_match=True,
        actual_p2p_intake=True,
    )
    save()
