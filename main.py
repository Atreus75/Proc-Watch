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
    def __init__(self, name='', bin_path='', command_line='', pid=0, opening_time='', parent_path='', parent_command_line='', ppid=0):
        self.name = name
        self.bin_path = bin_path
        self.pid = pid
        self.parent_path = parent_path
        self.parent_pid = ppid
        self.command_line = command_line
        self.parent_command_line = parent_command_line

        self.suspicious_name = False
        self.suspicious_parent = False
        self.suspicious_flags = []

    def checkSuspicious(self):
        if self.name in suspicious_programs_dict['SuspiciousTerminalParents']:
            if self.name in suspicious_programs_dict['Most_suspicious']:
                if self.name in suspicious_programs_dict['MostSuspicious']['Terminals']:
                    # Detects phishing and macros (Ex: Microsoft Word starting a Powershell process)
                    for parent in suspicious_parents_dict['SuspiciousTerminalParents']:
                        self.suspicious_parent = parent if parent in self.parent_path else False
                    # Detects suspicious flags in the commandline (Ex: encryption, http requests etc)
                    for flag in suspicious_flags_dict[self.name]:
                        if flag in self.command_line:
                            flag.append(flag)
        elif any([parent in self.parent_path for parent in suspicious_parents_dict['GeneralSuspiciousParents']]):
            # Checking apparently not-suspicious processes starting by strange parents
            pass
            

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
            print(f'[+] New Event: {self.event_ids[event_id]} {event_time}')
            match event_id:
                case 1:
                    process = ProcessInfo(
                        name=event_dict['Event']['EventData']['Data'][9]['#text'],
                        bin_path=event_dict['Event']['EventData']['Data'][4]['#text'],
                        command_line=event_dict['Event']['EventData']['Data'][10]['#text'],
                        pid=event_dict['Event']['EventData']['Data'][10]['#text'],
                        opening_time=event_dict['Event']['EventData']['Data'][1]['#text'],
                        parent_path=event_dict['Event']['EventData']['Data'][20]['#text'],
                        parent_command_line=event_dict['Event']['EventData']['Data'][21]['#text'],
                        ppid=event_dict['Event']['EventData']['Data'][19]['#text']
                    )

                    # Proceeds to use SOC rules to detect a malicious context in a process creation
                    # code here
                    # Printing general logs
                    print(f'    Binary Path: {event_dict["Event"]["EventData"]["Data"][4]["#text"]}')
                    print(f'    PID: {event_dict["Event"]["EventData"]["Data"][3]["#text"]}')
                case 5:
                    print(f'    Binary Path: {event_dict["Event"]["EventData"]["Data"][4]["#text"]}')
                    print(f'    PID: {event_dict["Event"]["EventData"]["Data"][3]["#text"]}')
                case _:
                    print(f'[!] Not Identified Event ID: {event_id}')

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
