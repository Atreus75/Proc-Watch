from sklearn.ensemble import IsolationForest
from datetime import date, datetime
from os import path
import pickle

class ModelSave:
    def __init__(self, model, timestamp, train_duration):
        '''
            model: IsolationForest model
            timestamp: dd-mm-yyyy. Example: 20-05-2026
            train_duration: hours.seconds Example: 43.5  
        '''
        self.model = model
        self.timestamp = date.fromisoformat(timestamp.replace('\n', ''))
        self.train_duration = train_duration

class ProcessInfo:
    def __init__(self, name='', bin_path='', command_line='', pid=0, opening_time='', user='', parent_path='', parent_command_line='', ppid=0, event_id=1):
        self.eid = event_id
        self.name = name
        self.bin_path = bin_path
        self.bin_dir = ''
        self.extractBinDir()
        self.pid = int(pid)
        self.parent_path = parent_path
        self.parent_pid = int(ppid)
        self.command_line = command_line
        self.parent_command_line = parent_command_line
        self.parent_name = ''
        self.extractParentName()
        self.opening_time = opening_time
        self.user = user[user.find('\\')+1:]
        self.is_priviledged = False
        self.flags = []

    def extractBinDir(self):
        for c in range(len(self.bin_path)-1, -1, -1):
            if self.bin_path[c] == '\\':
                self.bin_dir = self.bin_path[0:c]

    def extractParentName(self):
        for char in self.parent_path[::-1]:
            if char == '\\':
                break
            self.parent_name += char
        self.parent_name = self.parent_name[::-1]

class Trainer:
    def __init__(self):
        pass

    def extractProcessFeature(self, process=ProcessInfo()):
        '''Extracts features from a single ProcessInfo object based on its name, parent process name, hour of creation, privilege level, directory execution and command line flags.'''
        event_id = process.eid
        name = self.hashStr(process.name)
        parent_name = self.hashStr(process.parent_name)
        hour = self.hashStr(process.opening_time[11:16].replace(':', ''))
        bin_dir = self.hashStr(process.bin_dir)
        flags = self.hashStr(''.join(process.flags))
        
        feature = [
            event_id,
            name,
            parent_name,
            hour,
            1 if process.is_priviledged else 0,
            bin_dir,
            flags
        ]
        return feature

    def extractFileFeatures(self, file_path='training_data.txt'):
        '''Extracts a list of features containing information of diferent processes, saved in a file.'''
        features = []
        return_list = []
        with open(file_path, 'r') as feature_file:
            feature_file_lines = feature_file.readlines()
            return_list.append(feature_file_lines[0])
            return_list.append(feature_file_lines[1])
            for line in feature_file_lines[2:]:
                features.append([float(x) for x in line.strip().split(',')])
            return_list.append(features)
        return return_list

    def hashStr(self, string=''):
        '''Hashes strings using SipHash, with a 10.000 digit size limitation of the result'''
        return abs(hash(string)) % 10_000
    
    def trainAndSave(self):
        '''Trains the Isolation Forest model and saves it inside a file named model.pkl, in the current directory.'''
        train_data = self.extractFileFeatures()
        timestamp = train_data[0]
        train_duration = train_data[1]
        features = train_data[2]
        model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        model_save = ModelSave(model, timestamp, train_duration)

        model_save.model.fit(features)
        with open('model.pkl', 'wb+') as file:
            pickle.dump(model_save, file)

    def saveTrainingData(self, features=[], duration=0.0):
        past_duration = 0.0
        past_content = []
        if path.exists('train_data.txt'):
            with open('train_data.txt', 'r') as f:
                past_content = f.readlines()
                past_duration = float(past_content[1])
            past_content = past_content[2:]

        for c in range(0, len(features)):
            features[c] = ','.join([str(item) for item in features[c]]) + '\n'
        now = datetime.now()
        day = '0' + str(now.day) if now.day < 10 else str(now.day) 
        month = '0' + str(now.month) if now.month < 10 else str(now.month) 

        current_date = f'{now.year}-{month}-{day}\n'
        current_duration = f'{past_duration+duration/(60*60):.3f}\n'
        full_content = [current_date, current_duration]+past_content+features

        with open('training_data.txt', 'a+') as f:
            f.writelines(full_content)

if __name__ == '__main__':
    try:
        open('training_data.txt', 'r')
    except:
        print('[-] Error opening training_data.txt')

    print('[+] Training machine learning model...')
    Trainer().trainAndSave()
    print('[+] Model saved in model.pkl')
