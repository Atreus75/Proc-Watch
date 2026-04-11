import win32evtlog
import xmltodict
from json import load
import time

# Opening rule files
suspicious_parents_file = open('./rules/suspicious_parents.json', 'r')
suspicious_flags_file = open('./rules/suspicious_flags.json', 'r')
suspicious_programs_file = open('./rules/suspicious_programs.json', 'r')
suspicious_parents_dict = load(suspicious_parents_file)
suspicious_flags_dict = load(suspicious_flags_file)
suspicious_programs_dict = load(suspicious_programs_file)
suspicious_parents_file.close()
suspicious_flags_file.close()
suspicious_programs_file.close()

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
        self.suspicious_processes = []

        self.query = "*"
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
                        name=event_dict['Event']['EventData']['Data'][9]['#text'],
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
                    self.riskChecks(process)
                    
                    # Printing general logs
                    print(f'    Binary Path: {event_dict["Event"]["EventData"]["Data"][4]["#text"]}')
                    print(f'    PID: {event_dict["Event"]["EventData"]["Data"][3]["#text"]}')
                case 5:
                    print(f'    Binary Path: {event_dict["Event"]["EventData"]["Data"][4]["#text"]}')
                    print(f'    PID: {event_dict["Event"]["EventData"]["Data"][3]["#text"]}')
                case _:
                    print(f'[!] Not Identified Event ID: {event_id}')
            

    def riskChecks(self, process=ProcessInfo()):
        report_file = open('report.md', 'a+')
        report_lines = list()
        
        risk_score = 0 

        # Checks if its a known risky tool
        if process.name in suspicious_programs_dict['Names']['Suspicious']+suspicious_programs_dict['Names']['MostSuspicious']['Terminals']+suspicious_programs_dict['Names']['MostSuspicious']['Network']:
            risk_score += 3
            report_lines.append(f'* **Suspicious Executable**: \n')
            report_lines.append(f'* * **{process.name}**: {suspicious_programs_dict["Explainings"][process.name]}\n')
            # Checks if its a known attack tool
            if process.name in suspicious_programs_dict['Names']['MostSuspicious']['Terminals'] + suspicious_programs_dict['Names']['MostSuspicious']['Network']:
                risk_score += 3
                # Detects suspicious flags in the commandline (Ex: encryption, http request, port opening etc)
                flags = list()
                for flag in suspicious_flags_dict['Flags'][process.name]:
                    if flag in process.command_line:
                        flags.append(flag)
                if flags:
                    risk_score += 3
                    print('* **Attack Convenient Flags**: ')
                    for flag in flags:
                        print(f'* * **{flag}**: {suspicious_flags_dict["Explainings"][process.name][flag]}\n')

            # Detects strange parent-child relations (Ex: Microsoft Word starting a Powershell process)
            for parent in suspicious_parents_dict['SuspiciousParents'] + suspicious_parents_dict['MostSuspiciousParents']:
                if parent in process.parent_path:
                    risk_score += 3
                    report_lines.append('* **Strange Parent-Child Relation**: The process was started by an unexpected parent. A malware can be trying to seem a legitim program.\n')
                    report_lines.append(f'* * **Executable**: {parent}\n')
                    report_lines.append(f'* * **PPID**: {process.parent_pid}\n')
                    report_lines.append(f'* * **Command Line**: {process.parent_command_line}')
                    break
        else:
            # Detects strange parent-child relations (Ex: Microsoft Word starting a Powershell process)
            for parent in suspicious_parents_dict['MostSuspiciousParents']:
                if parent in process.parent_path:
                    risk_score += 3
                    report_lines.append('* **Suspicious Parent-Child Relation**: The process was started by an unexpected parent. A malware can be trying to seem a legitim program.\n')
                    report_lines.append(f'* * **Executable**: {parent}\n')
                    report_lines.append(f'* * **PPID**: {process.parent_pid}\n')
                    report_lines.append(f'* * **Command Line**: {process.parent_command_line}')
                    break
        if risk_score > 0:
            report_lines.append('## Conclusion')
            report_lines.append(f'* **Score**: {risk_score}\n')
            if risk_score < 4:
                report_lines.append('Low risk event. It may or not cause real problems.')
            elif risk_score >= 4:
                report_lines.append('Medium risk event. It worths a detailed look.')
            elif risk_score >= 7:
                report_lines.append('High risk event. This event is very probably an attack trail.')
            else:
                report_lines.append('Very high event. It will cause serious problems if ignored. An attack is certainly ocurring right now.')
            


            report_lines.insert(0, f'## Suspicious Activity\n')
            report_lines.insert(0, f'**Creation Time**: {process.opening_time}\n')
            report_lines.insert(0, f'**PID**: {process.pid}\n')
            report_lines.insert(0, f'**Executable:** {process.name}\n')
            report_lines.insert(0, f'## Main Information:** {process.name}\n')
            report_lines.insert(0, f'# ⚠️ Suspicious Process Creation\n-------------\n')
            report_file.writelines(report_lines)
            report_file.close()
            

print('''
██████╗ ██████╗   ██████╗   ██████╗      ██╗    ██╗ █████╗ ████████╗ ██████╗██╗  ██╗
██╔══██╗██╔══██╗ ██╔═══██╗ ██╔════╝      ██║    ██║██╔══██╗╚══██╔══╝██╔════╝██║  ██║
██████╔╝██████╔╝ ██║   ██║ ██║           ██║ █╗ ██║███████║   ██║   ██║     ███████║
██╔═══╝ ██╔══██╗ ██║   ██║ ██║           ██║███╗██║██╔══██║   ██║   ██║     ██╔══██║
██║     ██║  ██║ ╚██████╔╝ ╚██████╗      ╚███╔███╔╝██║  ██║   ██║   ╚██████╗██║  ██║
╚═╝     ╚═╝  ╚═╝  ╚═════╝   ╚═════╝       ╚══╝╚══╝ ╚═╝  ╚═╝   ╚═╝    ╚═════╝╚═╝  ╚═╝
''')
sm = SysmonMonitor()

while True:
    time.sleep(1)
