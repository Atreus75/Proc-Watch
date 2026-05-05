from sklearn.ensemble import IsolationForest
import pickle

class ProcessInfo:
    def __init__(self, name='', bin_path='', current_directory='', command_line='', pid=0, opening_time='', user='', parent_path='', parent_command_line='', ppid=0):
        self.name = name
        self.bin_path = bin_path
        self.current_directory = current_directory
        self.pid = int(pid)
        self.parent_path = parent_path
        self.parent_pid = int(ppid)
        self.command_line = command_line
        self.parent_command_line = parent_command_line
        self.parent_name = ''
        for char in parent_path[::-1]:
            if char == '\\':
                break
            self.parent_name += char
        self.parent_name = self.parent_name[::-1]
        self.opening_time = opening_time
        self.user = user[user.find('\\')+1:]
        self.is_priviledged = False
        self.flags = []

class Trainer:
    def __init__(self):
        pass

    def extractProcessFeature(self, process=ProcessInfo()):
        '''Extracts features from a single ProcessInfo object based on its name, parent process name, hour of creation, privilege level, directory execution and command line flags.'''
        name = self.hashStr(process.name)
        parent_name = self.hashStr(process.parent_name)
        hour = self.hashStr(process.opening_time[11:16].replace(':', ''))
        current_dir = self.hashStr(process.current_directory)
        flags = self.hashStr(''.join(process.flags))
        feature = [
            name,
            parent_name,
            hour,
            1 if process.is_priviledged else 0,
            current_dir,
            flags
        ]
        return feature

    def extractFileFeatures(self, file_path='training_data.txt'):
        '''Extracts a list of features containing information of diferent processes, saved in a file'''
        features = []
        with open(file_path, 'r') as feature_file:
            feature_file_lines = feature_file.readlines()
            for line in feature_file_lines:
                features.append([float(x) for x in line.strip().split(',')])
        return features

    def hashStr(self, string=''):
        '''Hashes strings using SipHash, with a 10.000 digit size limitation of the result'''
        return abs(hash(string)) % 10_000
    
    def trainAndSave(self):
        '''Trains the Isolation Forest model and saves it inside a file named model.pkl, in the current directory.'''
        features = self.extractFileFeatures()

        model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42
        )
        model.fit(features)
        with open('model.pkl', 'wb+') as file:
            model = pickle.dump(model, file)

    def saveTrainingData(self, feature=[]):
        feature = [str(item) for item in feature]
        with open('training_data.txt', 'a+') as f:
            f.write(','.join(feature)+'\n')

if __name__ == '__main__':
    try:
        open('training_data.txt', 'r')
    except:
        print('[-] Error opening training_data.txt')

    print('[+] Training machine learning model...')
    Trainer().trainAndSave()
    print('[+] Model saved in model.pkl')
