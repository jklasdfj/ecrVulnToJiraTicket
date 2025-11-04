from Severity import Severity
import datetime

# a vulnerable repository e.g. badge api for a specific vulnerability CVE-2023-1234 or ALAS2-23094823
class VulnerableRepository:
    severity: Severity  # critical is highest, low is lowest, keep most severe seen
    name: str
    image_pushed_at: datetime.datetime
    vulnerable_image_id: str

    def __repr__(self):
        return f'\n  {self.name} \n severity:{self.severity} \n vulnerable image {self.vulnerable_image_id} \n  pushed at time {self.image_pushed_at}'

    def __init__(self, severity: Severity, name: str, image_pushed_at, image_id):
        self.severity = severity
        self.name = name
        self.image_pushed_at = image_pushed_at
        self.vulnerable_image_id = image_id

    # same vulnerability can show multiple time son image
    def keep_highest_severity(self, severity: Severity):
        if self.severity < severity:
            self.severity = severity
