import win32evtlog
import xmltodict
import time
import pickle
from train_model import Trainer, ProcessInfo
from json import load
from subprocess import run
from argparse import ArgumentParser
from os import getpid

class SysmonMonitor:
    def __init__(self, report_path='', train_model=False, activate_model=False):
        self.report_path = report_path
        self.event_ids = {
            1: 'Process Create',
            2: 'File Creation Time Modification',
            5: 'Process Terminated'
        }
        self.query = "*"
        self.current_pid = getpid()
        self.activate_model = activate_model
        self.train_model = train_model

        # Opening rule files
        parents_file = open('./rules/parents.json', 'r')
        flags_file = open('./rules/flags.json', 'r')
        programs_file = open('./rules/programs.json', 'r')
        users_and_groups_file = open('./rules/users_and_groups.json')
        self.parents_dict = load(parents_file)
        self.flags_dict = load(flags_file)
        self.programs_dict = load(programs_file)
        self.users_and_groups_dict = load(users_and_groups_file)
        parents_file.close()
        flags_file.close()
        programs_file.close()
        users_and_groups_file.close()

        # Loading ML model
        if self.activate_model:
            with open('model.pkl', 'rb') as f:
                self.model = pickle.load(f)

        # Event subscribing SysmonMonitor.callback as the callback function to the Sysmon event log
        self.subscription = win32evtlog.EvtSubscribe(
            ChannelPath="Microsoft-Windows-Sysmon/Operational",
            Flags=win32evtlog.EvtSubscribeToFutureEvents,
            Query=self.query,
            Callback=self.callback
        )


    def callback(self, action, context, event):
        if action == win32evtlog.EvtSubscribeActionDeliver:
            event_str_xml = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            event_dict = xmltodict.parse(event_str_xml)
            self.treatEvent(event_dict)
    
    def treatEvent(self, event_dict=dict()):
        event_id = int(event_dict['Event']['System']['EventID'])
        if event_id in self.event_ids.keys():
            event_time = event_dict['Event']['System']['TimeCreated']['@SystemTime']
            print(f'[+] New Event: {self.event_ids[event_id]} at {event_time[:19]}')
            match event_id:
                case 1:
                    process = ProcessInfo(
                        name=event_dict['Event']['EventData']['Data'][9]['#text'].lower(),
                        bin_path=event_dict['Event']['EventData']['Data'][4]['#text'],
                        current_directory=event_dict['Event']['EventData']['Data'][11]['#text'],
                        command_line=event_dict['Event']['EventData']['Data'][10]['#text'],
                        pid=event_dict['Event']['EventData']['Data'][3]['#text'],
                        opening_time=event_dict['Event']['EventData']['Data'][1]['#text'],
                        user=event_dict['Event']['EventData']['Data'][12]['#text'],
                        parent_path=event_dict['Event']['EventData']['Data'][20]['#text'],
                        parent_command_line=event_dict['Event']['EventData']['Data'][21]['#text'],
                        ppid=event_dict['Event']['EventData']['Data'][19]['#text']
                    )
                    # Skip processes created by ProcWatch, in order to keep the report as cleaner as possible
                    if self.current_pid != process.pid and self.current_pid != process.parent_pid:
                        # Proceeds to use SOC rules to detect a malicious context in a process creation
                        self.processCreationChecks(process)
                        
                        # Printing general logs
                        print(f'    Binary Path: {event_dict["Event"]["EventData"]["Data"][4]["#text"]}')
                        print(f'    PID: {event_dict["Event"]["EventData"]["Data"][3]["#text"]}')
                        if self.train_model:
                            Trainer().saveTrainingData(Trainer().extractProcessFeature(process))
                case 5:
                    process = ProcessInfo(
                        bin_path=event_dict['Event']['EventData']['Data'][4]['#text']
                    )
                    self.processTerminationChecks(process)
                    if self.train_model:
                        Trainer().saveTrainingData(Trainer().extractProcessFeature(process))
                    print(f'    Binary Path: {event_dict["Event"]["EventData"]["Data"][4]["#text"]}')
                    print(f'    PID: {event_dict["Event"]["EventData"]["Data"][3]["#text"]}')
                    
                case _:
                    print(f'[!] Not Identified Event ID: {event_id}')
            

    def processCreationChecks(self, process=ProcessInfo()):
        report_lines = list()
        risk_score = 0 

        # Executes checks for dangerous executables
        all_suspicious_programs = self.programs_dict['Names']['Suspicious']+self.programs_dict['Names']['MostSuspicious']['Terminals']+self.programs_dict['Names']['MostSuspicious']['Network']
        most_suspicious_programs = self.programs_dict['Names']['MostSuspicious']['Terminals']+self.programs_dict['Names']['MostSuspicious']['Network']
        if process.name in all_suspicious_programs:
            risk_score += 3
            report_lines.append(f'* **Suspicious Executable**: ')
            report_lines.append(f'  * **{process.name}**: {self.programs_dict["Explainings"][process.name]}')
            # Checks if its a known attack tool
            if process.name in most_suspicious_programs:
                risk_score += 3
                # Detects suspicious flags in the commandline (Ex: encryption, http request, port opening etc)
                flags = list()
                for flag in self.flags_dict['Flags'][process.name]:
                    if flag in process.command_line:
                        flags.append(flag)
                if flags:
                    risk_score += 3
                    report_lines.append('* **Attack Convenient Flags**: ')
                    for flag in flags:
                        report_lines.append(f'  * **{flag}**: {self.flags_dict["Explainings"][process.name][flag]}')
            
            # Detects if the process was started by a high-priviledged user
            user_groups = run(
                [
                    "powershell", 
                    "-Command", 
                    "Get-LocalGroup | ForEach-Object { $group = $_; Get-LocalGroupMember -Group $group.Name -ErrorAction SilentlyContinue | Where-Object { $_.Name -like '*\\" + process.user + "' } | ForEach-Object { $group.Name } } | Select-Object -Unique"
                ],
                capture_output=True, text=True
            ).stdout
            priviledged_groups = []
            for group in self.users_and_groups_dict['Groups']['Privileged']:
                if group.capitalize() in user_groups:
                    priviledged_groups.append(group)
                    break
            if priviledged_groups:
                risk_score += 3
                report_lines.append('* **Highly Privileged User Groups**: ')
                for group in priviledged_groups:
                    report_lines.append(f'  * {group.capitalize()}')
                    process.is_priviledged = True

        # Detects strange parent-child relations (Ex: Microsoft Word starting a Powershell process)
        check_parents_dict = self.parents_dict['SuspiciousForTerminal'] if process.name in self.programs_dict['Names']['MostSuspicious']['Terminals'] else self.parents_dict['GeneralSuspicious']
        for parent in check_parents_dict:
            if parent.lower() == process.parent_name.lower():
                risk_score += 3
                report_lines.append('* **Strange Parent-Child Relation**: The process was started by a dangerous parent. It is possible that a malware can be trying to seem a legitim program.')
                report_lines.append(f'  * **Executable**: {parent}')
                report_lines.append(f'  * **PPID**: {process.parent_pid}')
                report_lines.append(f'  * **Command Line**: {process.parent_command_line}')
                break

        # Calculates risk score and risk level classification
        
        if risk_score > 0:
            anomalous_behavior = False

            if self.activate_model:
                # Decreases the risk score if the event is a part of the system common routine, and increses it if the event is considered anomalous
                features = Trainer().extractProcessFeature(process)
                prediction = self.model.predict([features])[0]
                anomalous_behavior = prediction == -1
                if 1 < risk_score < 4:
                    risk_score += 3 if prediction == -1 else -risk_score
                elif 3 < risk_score < 10:
                    risk_score += 3 if prediction == -1 else -3
                # Does not decreases a risk score bigger than 9

            self.riskScoreAvaliate(risk_score, report_lines, anomalous_behavior)
            if risk_score > 0:
                # Does not include the event in the final report if the risk score is less than 1
                report_lines.insert(0, f'## Suspicious Activity')
                report_lines.insert(0, f'**Creation Time**: {process.opening_time}')
                report_lines.insert(0, f'**PID**: {process.pid}')
                report_lines.insert(0, f'**Command Line**: {process.command_line}')
                report_lines.insert(0, f'**Executable:** {process.name}')
                report_lines.insert(0, f'## Main Information:')
                report_lines.insert(0, f'# Process Creation')
                with open(self.report_path, 'a+') as report_file:
                    report_file.write('\r\n'.join(report_lines) + '\r\n')
    
    def processTerminationChecks(self, process):
        risk_score = 0
        report_lines = list()
        for char in process.bin_path[::-1]:
            if char == '\\':
                break
            process.name += char
        process.name = process.name[::-1]
        # Checks weather the process is a security critical one
        if process.name.lower() in self.programs_dict['Names']['SecurityCritical']:
            risk_score += 7
            report_lines.append('# Process Termination')
            report_lines.append('## Main Information')
            report_lines.append(f'* Executable: {process.name.lower()}')
            report_lines.append(f'* Executable Path: {process.bin_path}')
            report_lines.append(f'* Criticality: {self.programs_dict["Explainings"][process.name.lower()]}')            
        if risk_score > 0:
            # If -a is True, proceeds to use the machine learning model to improve risk score avaliation and report    
            self.riskScoreAvaliate(risk_score, report_lines)
            with open(self.report_path, 'a+') as report_file:
                report_file.write('\r\n'.join(report_lines) + '\r\n')

    def riskScoreAvaliate(self, risk_score=0, report_lines=[], ml_detection=False):
        report_lines.append('## Conclusion')
        if ml_detection:
            report_lines.append('  * Anomalous Behavior Detected! Risk score was revaluated. (Machine Learning)')
        report_lines.append(f'* **Score**: {risk_score}. ')
        if risk_score < 4:
            report_lines.append('Low risk. Classified as uncommon (but not necessairily malicious) activity. Alone, this event may not require further investigation.')
        elif risk_score < 7:
            report_lines.append('Medium risk event. Classified as potential malicious activity. It requires attention to future event correlations.')
        elif risk_score < 10:
            report_lines.append('High risk. Classified as attack indicator. This event requires imediate investigation.')
        else:
            report_lines.append('Very high risk. Classified as **strong** attack indicator. Requires imediate investigation and system hardening.')
        report_lines.append('')


if __name__ == '__main__':
    parser = ArgumentParser(
        description='A system security monitor prototype',
        prog='procwatch.py',
        epilog='They won\'t go far unnoticed',
        add_help=True
    )
    parser.add_argument('-r', '--reportPath', default='./report.md', help='The path to write the complete report markdown file. Ex: C:\\....\\report.md')
    parser.add_argument('-t', '--train-model', default=False, action='store_true', help='Genetares training data and trains the local machine learning model, in order to improve the report results.')
    parser.add_argument('-a', '--activate-model', default=False, action='store_true', help='Activates detection and report improvement by a local machine learning model previously saved. OBS: the model needs to be in a "procwatch.pkl" file inside the current folder.')
    args = parser.parse_args()

    try:
        report_file = open(args.reportPath, 'a+')
        report_file.close()
    except:
        print(f'[-] Error while writing the report at {args.reportPath}')
        print('Check your permissions and the existence of the directory.')
        exit()

    print('''
    They won't go far unnoticed
    ██████╗ ██████╗   ██████╗   ██████╗ ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
    ██╔══██╗██╔══██╗ ██╔═══██╗ ██╔════╝ ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
    ██████╔╝██████╔╝ ██║   ██║ ██║      ██║ █╗ ██║███████║   ██║   ██║     ███████║
    ██╔═══╝ ██╔══██╗ ██║   ██║ ██║      ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
    ██║     ██║  ██║ ╚██████╔╝ ╚██████╗ ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
    ╚═╝     ╚═╝  ╚═╝  ╚═════╝   ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
                                                        by Rodrigo Soares Ferreira
    ''')
    if args.activate_model:
        try:
            # Checks if the training_data.txt file exists and is readable in the current folder
            a = open('training_data.txt', 'r')
            a.close()
        except:
            print('[-] training_data.txt was not found in the current folder. You need to train the model first (recommended at least for 1 day).')
    
    sm = SysmonMonitor(args.reportPath, args.train_model, args.activate_model)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        if args.train_model:
            print('\n\n[+] Training ML model. Please, wait.')
            Trainer().trainAndSave()
            print('[+] Model saved in model.pkl')
        print('[+] Terminating.')
