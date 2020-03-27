import json
import os

class IGDB(object):

    def __init__(self, path):
        super().__init__()
        self.path = os.path.expanduser(path)
        self.load(self.path)
    
    def load(self, path):
        if os.path.exists(path):
            self._load()
        else:
            self.db = {}
        
        return True
    
    def _load(self):
        self.db = json.load(open(self.path, 'r'))
    
    def writedb(self):
        try:
            json.dump(self.db, open(self.path, 'w+'))
            return True
        except:
            return False
    
    def setd(self, key, value):
        try:
            self.db[str(key)] = value
            if self.writedb():
                return True
            else:
                return False
        except Exception as e:
            print('Error Saving Data to database...'+ str(e))
            return False
    
    def getd(self, key):
        try:
            return self.db[key]
        except KeyError:
            print(f'No Value related to key {key}')
            return None
    
    def deld(self, key):
        if key not in self.db:
            return False
        del self.db[key]
        if self.writedb():
            return True
        else:
            return False
    
    def resetdb(self):
        self.db = {}
        if self.writedb():
            return True
        else:
            return False