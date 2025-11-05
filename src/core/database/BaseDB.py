import os


class BaseDB:
    def __init__(self):
        self.basepath = "data"
        self.filepath = os.path.join(self.basepath, self.filename)
