import win32evtlog
import xmltodict
import time

class SysmonMonitor:
    def __init__(self):
        self.event_ids = {
            1: 'Process Create',
            2: 'File Creation Time Modification',
            5: 'Process Terminated'
        }
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
            print(f'[+] New Event: {self.event_ids[event_id]}')
            match event_id:
                case 1:
                    print(f'    Binary Path: {event_dict["Event"]["EventData"]["Data"][4]["#text"]}')
                    print(f'    PID: {event_dict["Event"]["EventData"]["Data"][3]["#text"]}')
                    print(f'    Parent Binary Path: {event_dict["Event"]["EventData"]["Data"][20]["#text"]}')
                    print(f'    Parent PID: {event_dict["Event"]["EventData"]["Data"][19]["#text"]}')
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