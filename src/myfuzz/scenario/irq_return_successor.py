"""Pure field rules for the first architectural successor of an ISR return.

Two retirement authorities are admitted, declared by the registered CPU IRQ
receipt contract (a missing declaration keeps the legacy full-RVFI rule):

* ``full_rvfi``: the successor retires with ``intr`` observed as zero and a
  retirement serial observation that is present, observed and zero.  Callers
  still authenticate the actual observations and instruction response/versions.
  MRET pc_wdata has no return-target authority in the pinned Ibex implementation.
* ``pc_insn_order_only``: the CPU retirement stream is PC/order/insn only.  The
  successor must carry no ``intr`` field at all and no observed serial
  observation; trap/intr/retirement-serial stay unobservable rather than zero.

Both authorities require the immediately following retirement order, an
in-range aligned PC, a strictly later parsed receipt sequence in the same
execution and a strictly later local tick.
"""

FULL_RVFI_AUTHORITY = 'full_rvfi'
PC_INSN_ORDER_ONLY_AUTHORITY = 'pc_insn_order_only'
RETIREMENT_AUTHORITIES = (FULL_RVFI_AUTHORITY, PC_INSN_ORDER_ONLY_AUTHORITY)


def retirement_authority(contract):
    """Read the registered authority; an absent declaration means full RVFI."""
    if contract is None:
        return FULL_RVFI_AUTHORITY
    if type(contract) is not dict:
        raise ValueError('unregistered-retirement-authority')
    authority = contract.get('retirement_authority', FULL_RVFI_AUTHORITY)
    if authority is None:
        return FULL_RVFI_AUTHORITY
    if authority not in RETIREMENT_AUTHORITIES:
        raise ValueError('unregistered-retirement-authority')
    return authority


def retirement_serial_unobservable(successor):
    """True only when the successor carries no observed retirement serial.

    An absent observation is unobservable. An explicitly unobservable
    observation is unobservable. An observed token (including a zero token) is
    a claim this authority cannot make.
    """
    observation = successor.get('irq_serial_observation')
    if observation is None:
        return True
    if type(observation) is not dict:
        return False
    retirement = observation.get('retirement')
    if retirement is None:
        return True
    return (type(retirement) is dict and retirement.get('status') == 'unobservable'
            and retirement.get('value') is None)


def validate_return_successor(mret, successor, *, start, end,
                              authority=FULL_RVFI_AUTHORITY):
    """Return the actual successor PC or refuse the claimed first successor."""
    if authority is None:
        authority = FULL_RVFI_AUTHORITY
    if authority not in RETIREMENT_AUTHORITIES:
        raise ValueError('native-ISR-first-successor-unknown-retirement-authority')
    before = mret.get('receipt_id', {})
    after = successor.get('receipt_id', {})
    pc = successor.get('pc_rdata')
    order = successor.get('order')
    common = (type(order) is not int or type(mret.get('order')) is not int
              or order != mret['order']+1
              or type(pc) is not int or pc % 4 or not start <= pc < end
              or type(before.get('sequence')) is not int or type(after.get('sequence')) is not int
              or after['sequence'] <= before['sequence'] or not before.get('execution')
              or after.get('execution') != before['execution']
              or type(mret.get('local_tick')) is not int or type(successor.get('local_tick')) is not int
              or successor['local_tick'] <= mret['local_tick'])
    if common:
        raise ValueError('native-ISR-first-successor-not-current-dynamic-return')
    if authority == PC_INSN_ORDER_ONLY_AUTHORITY:
        # intr is not driven on this CPU: a zero would be a fabricated claim.
        if 'intr' in successor or not retirement_serial_unobservable(successor):
            raise ValueError('native-ISR-first-successor-not-current-dynamic-return')
        return pc
    role = successor.get('irq_serial_observation', {}).get('retirement', {})
    if successor.get('intr') != 0 or role.get('status') != 'observed' or role.get('value') != 0:
        raise ValueError('native-ISR-first-successor-not-current-dynamic-return')
    return pc
