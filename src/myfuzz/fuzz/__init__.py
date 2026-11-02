"""Closed-loop, profile-driven in-process fuzzing.

This package holds the pieces the unified in-process executor needs to run a
real execute -> observe -> mutate loop inside one model lifetime: the declared
input space, the mutation operators, the feature feedback, a bounded corpus and
the session driver that speaks the ``NEED_RECORD``/``CASE`` protocol of the
single-process host.
"""
