import re

class Helpers:
    @staticmethod
    def duration_to_seconds(duration):
        duration = duration.split(':')

        # Raise a ValueError if any of the duration parts are a blank string, e.g. ':15' should be invalid.
        if '' in duration:
            raise ValueError(f'Invalid duration format for \'{":".join(duration)}\'.')

        if len(duration) == 2:
            return int(duration[0]) * 60 + int(duration[1])
        elif len(duration) == 3:
            return int(duration[0]) * 3600 + int(duration[1]) * 60 + int(duration[2])
        else:
            raise ValueError(f'Invalid duration format for \'{":".join(duration)}\'.')

    # Normalize a QID to an integer.
    @staticmethod
    def normalize_qid(qid: str) -> int | None:
        if qid == None or qid == '':
            return None

        if not re.match('Q?\d+', qid):
            raise ValueError('Invalid QID format, must be in a format like "Q123" or "123".')

        if qid.startswith('Q'):
            return int(qid[1:])
        else:
            return int(qid)
