import win32evtlog
import xmltodict
from json import load
import time


class ProcessInfo:
    def __init__(self, name='', bin_path='', current_directory='', command_line='', pid=0, opening_time='', parent_path='', parent_command_line='', ppid=0):
        self.name = name
        self.bin_path = bin_path
        self.current_directory = current_directory
        self.pid = pid
        self.parent_path = parent_path
        self.parent_pid = ppid
        self.command_line = command_line
        self.parent_command_line = parent_command_line
        self.opening_time = opening_time

        self.flags = []
        
            
class SysmonMonitor:
    def __init__(self):
        self.event_ids = {
            1: 'Process Create',
            2: 'File Creation Time Modification',
            5: 'Process Terminated'
        }
        self.query = "*"
        # Opening rule files
        suspicious_parents_file = open('./rules/suspicious_parents.json', 'r')
        suspicious_flags_file = open('./rules/suspicious_flags.json', 'r')
        suspicious_programs_file = open('./rules/suspicious_programs.json', 'r')
        self.suspicious_parents_dict = load(suspicious_parents_file)
        self.suspicious_flags_dict = load(suspicious_flags_file)
        self.suspicious_programs_dict = load(suspicious_programs_file)
        suspicious_parents_file.close()
        suspicious_flags_file.close()
        suspicious_programs_file.close()

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
            print(f'[+] New Event: {self.event_ids[event_id]} at {event_time}')
            match event_id:
                case 1:
                    process = ProcessInfo(
                        name=event_dict['Event']['EventData']['Data'][9]['#text'].lower(),
                        bin_path=event_dict['Event']['EventData']['Data'][4]['#text'],
                        current_directory=event_dict['Event']['EventData']['Data'][11]['#text'],
                        command_line=event_dict['Event']['EventData']['Data'][10]['#text'],
                        pid=event_dict['Event']['EventData']['Data'][3]['#text'],
                        opening_time=event_dict['Event']['EventData']['Data'][1]['#text'],
                        parent_path=event_dict['Event']['EventData']['Data'][20]['#text'],
                        parent_command_line=event_dict['Event']['EventData']['Data'][21]['#text'],
                        ppid=event_dict['Event']['EventData']['Data'][19]['#text']
                    )

                    # Proceeds to use SOC rules to detect a malicious context in a process creation
                    self.processCreationChecks(process)
                    
                    # Printing general logs
                    print(f'    Binary Path: {event_dict["Event"]["EventData"]["Data"][4]["#text"]}')
                    print(f'    PID: {event_dict["Event"]["EventData"]["Data"][3]["#text"]}')
                case 5:
                    print(event_dict)
                    print(f'    Binary Path: {event_dict["Event"]["EventData"]["Data"][4]["#text"]}')
                    print(f'    PID: {event_dict["Event"]["EventData"]["Data"][3]["#text"]}')
                case _:
                    print(f'[!] Not Identified Event ID: {event_id}')
            

    def processCreationChecks(self, process=ProcessInfo()):
        report_file = open('report.md', 'a+')
        report_lines = list()
        
        risk_score = 0 

        # Checks if its a known risky tool
        all_suspicious = self.suspicious_programs_dict['Names']['Suspicious']+self.suspicious_programs_dict['Names']['MostSuspicious']['Terminals']+self.suspicious_programs_dict['Names']['MostSuspicious']['Network']
        most_suspicious = self.suspicious_programs_dict['Names']['MostSuspicious']['Terminals']+self.suspicious_programs_dict['Names']['MostSuspicious']['Network']
        if process.name in all_suspicious:
            risk_score += 3
            report_lines.append(f'* **Suspicious Executable**: \n')
            report_lines.append(f'* * **{process.name}**: {self.suspicious_programs_dict["Explainings"][process.name]}\n')
            # Checks if its a known attack tool
            if process.name in most_suspicious:
                risk_score += 3
                # Detects suspicious flags in the commandline (Ex: encryption, http request, port opening etc)
                flags = list()
                for flag in self.suspicious_flags_dict['Flags'][process.name]:
                    if flag in process.command_line:
                        flags.append(flag)
                if flags:
                    risk_score += 3
                    report_lines.append('* **Attack Convenient Flags**: \n')
                    for flag in flags:
                        report_lines.append(f'  * **{flag}**: {self.suspicious_flags_dict["Explainings"][process.name][flag]}\n')

            # Detects strange parent-child relations (Ex: Microsoft Word starting a Powershell process)
            for parent in self.suspicious_parents_dict['SuspiciousParents'] + self.suspicious_parents_dict['MostSuspiciousParents']:
                if parent.lower() in process.parent_path.lower():
                    risk_score += 3
                    report_lines.append('* **Strange Parent-Child Relation**: The process was started by an unexpected parent. A malware can be trying to seem a legitim program.\n')
                    report_lines.append(f'  * **Executable**: {parent}\n')
                    report_lines.append(f'  * **PPID**: {process.parent_pid}\n')
                    report_lines.append(f'  * **Command Line**: {process.parent_command_line}\n')
                    break
        else:
            # Detects strange parent-child relations (Ex: Microsoft Word starting a Powershell process)
            for parent in self.suspicious_parents_dict['MostSuspiciousParents']:
                if parent in process.parent_path:
                    risk_score += 3
                    report_lines.append('* **Suspicious Parent-Child Relation**: The process was started by an unexpected parent. A malware can be trying to seem a legitim program.\n')
                    report_lines.append(f'  * **Executable**: {parent}\n')
                    report_lines.append(f'  * **PPID**: {process.parent_pid}\n')
                    report_lines.append(f'  * **Command Line**: {process.parent_command_line}\n')
                    break
        if risk_score > 0:
            report_lines.append('## Conclusion\n')
            report_lines.append(f'* **Score**: {risk_score}\n')
            if risk_score < 4:
                report_lines.append('Low risk. Classified as uncommon (but not necessairily malicious) activity. Alone, this event may not require further investigation.\n')
            elif risk_score < 7:
                report_lines.append('Medium risk event. Classified as potential malicious activity. It requires attention to future event correlations.\n')
            elif risk_score < 10:
                report_lines.append('High risk. Classified as malicious activity. This event requires imediate investigation.\n')
            else:
                report_lines.append('Very high risk. Classified as attack trail. Requires imediate investigation and system hardening.\n')
            


            report_lines.insert(0, f'## Suspicious Activity\n')
            report_lines.insert(0, f'**Creation Time**: {process.opening_time}\n')
            report_lines.insert(0, f'**PID**: {process.pid}\n')
            report_lines.insert(0, f'**Command Line**: {process.command_line}\n')
            report_lines.insert(0, f'**Executable:** {process.name}\n')
            report_lines.insert(0, f'## Main Information:\n')
            report_lines.insert(0, f'# Process Creation\n')
            report_file.writelines(report_lines)
            report_file.close()
        report_file.close()
    
    def processTerminationChecks(self, process):
        pass


if __name__ == 'main':
    print('''
    ██████╗ ██████╗   ██████╗   ██████╗      ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
    ██╔══██╗██╔══██╗ ██╔═══██╗ ██╔════╝      ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
    ██████╔╝██████╔╝ ██║   ██║ ██║           ██║ █╗ ██║███████║   ██║   ██║     ███████║
    ██╔═══╝ ██╔══██╗ ██║   ██║ ██║           ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
    ██║     ██║  ██║ ╚██████╔╝ ╚██████╗      ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
    ╚═╝     ╚═╝  ╚═╝  ╚═════╝   ╚═════╝       ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
    ''')
    sm = SysmonMonitor()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print('[+] Terminating.\n\n')
