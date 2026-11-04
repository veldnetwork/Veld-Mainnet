"""Bounded waits for real validation; never changes consensus or PoW budgets."""


class ValidationProgress:
    """Allow slow canonical catch-up but fail a stall and an absolute deadline.

    The old 20-minute deadline could not cover 1,867 external PoW checks at
    the node's unchanged 32-per-minute global admission limit. Twelve seconds
    per missing block also allows transport/refill overhead observed in the
    isolated diagnostic. Bulk block responses also have an unchanged 600-second
    per-source byte/work window. A five-minute no-progress deadline could end
    the test before that legitimate window refilled. Allow one full window and
    five minutes for transport/validation, without extending the absolute cap.
    Six hours is a hard qualification limit, not a promise about production
    synchronization throughput.
    """

    def __init__(self, start_height, target_height, now):
        for height in (start_height, target_height):
            if type(height) is not int or not 0 <= height < 2**63:
                raise ValueError("invalid validation height")
        self.best_height = start_height
        self.target_height = target_height
        self.started = self.last_progress = now
        self.budget_seconds = min(21600, max(900, 900 + 12 * max(0, target_height - start_height)))

    def observe(self, height, now):
        if type(height) is not int or not 0 <= height < 2**63:
            raise ValueError("invalid validation height")
        if height > self.best_height:
            self.best_height = height
            self.last_progress = now
        if now - self.started >= self.budget_seconds:
            raise TimeoutError("independent validation exceeded its absolute time budget")
        if now - self.last_progress >= 900:
            raise TimeoutError("independent validation made no new height progress for 900 seconds")
