"""Private bounded views of live issuance; contains no proof enrollment API."""
from copy import deepcopy


class MemoryAuthorityDistribution:
    def __init__(self):
        self._consumers = {'default'}
        self._remaining_consumers = {}

    def register_consumer(self, name):
        """Register a one-shot recipient before any actual callback issuance."""
        self.validate_consumer_registration(name)
        self._consumers.add(name)

    def validate_consumer_registration(self, name):
        """Preflight paired registries without partially registering either."""
        if self._next_token != 1 or self._bad:
            raise ValueError('memory authority consumers require startup registration')
        if (type(name) is not str or not name.strip() or len(name) > 64
                or name in self._consumers):
            raise ValueError('invalid or duplicate memory authority consumer')
        if len(self._consumers) >= 16:
            raise ValueError('memory authority consumer capacity exceeded')

    def _pin_consumers(self, token):
        self._remaining_consumers[token] = set(self._consumers)

    def resolve(self, token, *, consumer='default'):
        """Each registered recipient gets one detached view of one issuance."""
        if type(token) is not int or token < 1 or type(consumer) is not str:
            return None
        remaining = self._remaining_consumers.get(token)
        if remaining is None or consumer not in remaining:
            return None
        remaining.remove(consumer)
        record = self._pending.get(token)
        if not remaining:
            self._remaining_consumers.pop(token)
            self._pending.pop(token, None)
        return deepcopy(record) if record is not None and not self._bad else None
