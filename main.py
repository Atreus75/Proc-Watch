import win32evtlog
import xmltodict
from json import load
import time
from subprocess import run
from argparse import ArgumentParser
from os import getpid, listdir


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
        self.flags = []


class SysmonMonitor:
    def __init__(self, report_path=''):
        self.report_path = report_path
        self.event_ids = {
            1: 'Process Create',
            2: 'File Creation Time Modification',
            5: 'Process Terminated'
        }
        self.query = "*"
        self.current_pid = getpid()
        
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

                case 5:
                    process = ProcessInfo(
                        bin_path=event_dict['Event']['EventData']['Data'][4]['#text']
                    )
                    self.processTerminationChecks(process)

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
            self.riskScoreAvaliate(risk_score, report_lines)

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
            risk_score += 4
            report_lines.append('# Process Termination')
            report_lines.append('## Main Information')
            report_lines.append(f'* Executable: {process.name.lower()}')
            report_lines.append(f'* Executable Path: {process.bin_path}')
            report_lines.append(f'* Criticality: {self.programs_dict["Explainings"][process.name.lower()]}')            
        if risk_score > 0:
            self.riskScoreAvaliate(risk_score, report_lines)
            with open(self.report_path, 'a+') as report_file:
                report_file.write('\r\n'.join(report_lines) + '\r\n')

    def riskScoreAvaliate(self, risk_score=0, report_lines=[]):
        report_lines.append('## Conclusion')
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
    
    sm = SysmonMonitor(args.reportPath)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('[+] Terminating.')
