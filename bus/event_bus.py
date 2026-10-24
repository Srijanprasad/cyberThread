"""
Message Bus for SIH 2026 PS 26145.
Provides bounded queues and back-pressure to guarantee reliable real-time operation.
Topics:
- events.flow
- events.dns
- features.<detector>
- alerts.raw
- alerts.final
Under overload: drops and counts, never crashes or exceeds memory bounds.
"""

from collections import deque, defaultdict
from typing import Callable, Dict, List, Any
import threading


class EventBus:
    def __init__(self, max_queue_size: int = 50000):
        self.max_queue_size = max_queue_size
        self._subscribers: Dict[str, List[Callable[[Any], None]]] = defaultdict(list)
        self._queues: Dict[str, deque] = defaultdict(lambda: deque(maxlen=self.max_queue_size))
        self.dropped_events: Dict[str, int] = defaultdict(int)
        self.total_published: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()

    def subscribe(self, topic: str, handler: Callable[[Any], None]):
        """Registers a callback subscriber for a topic."""
        with self._lock:
            self._subscribers[topic].append(handler)

    def publish(self, topic: str, message: Any):
        """Publishes an event to a topic. Enforces back-pressure limits."""
        with self._lock:
            q = self._queues[topic]
            if len(q) >= self.max_queue_size:
                self.dropped_events[topic] += 1
                q.popleft()  # Evict oldest event to respect memory bounds

            q.append(message)
            self.total_published[topic] += 1
            handlers = list(self._subscribers.get(topic, []))

        # Invoke handlers outside lock
        for handler in handlers:
            try:
                handler(message)
            except Exception as e:
                # Catch handler exception so bus remains resilient
                pass

    def get_queue_size(self, topic: str) -> int:
        with self._lock:
            return len(self._queues[topic])

    def clear(self):
        with self._lock:
            self._queues.clear()
            self.dropped_events.clear()
            self.total_published.clear()
