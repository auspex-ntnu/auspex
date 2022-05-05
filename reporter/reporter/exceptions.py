class NoScoresException(Exception):
    pass


class SingleDocRetrievalError(Exception):
    pass


class MultiDocRetrievalError(Exception):
    pass


class InvalidBackend(Exception):
    pass


class LogReportError(Exception):
    pass


def combine_exception_messages(exceptions: list[Exception]) -> str:
    return "\n".join([str(e) for e in exceptions])
