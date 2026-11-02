"""Case adapter for the existing atomic R1 GPIO runtime."""


class GpioCaseAdapter:
    def __init__(self, assembly, credit):
        self.assembly, self.credit = assembly, credit

    def current_state(self):
        return self.assembly.field_state()

    def execute(self, decision, context):
        if context.on_prepared is not None:
            context.on_prepared(decision)
        kwargs = {'case_id': context.case_id}
        if context.deadline_ns is not None:
            kwargs['deadline_ns'] = context.deadline_ns
        if context.replay_advance_count is not None:
            kwargs['replay_advance_count'] = context.replay_advance_count
        return self.assembly.submit(decision, **kwargs)

    def settle(self, decision, context, receipt, current, features, cost_ns):
        return self.credit.observe(decision, context.case_id, current, features, cost_ns)
