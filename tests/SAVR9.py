import re
import json

class SAVR9:
    name = "SAVR9"

    def __init__(self, cfg, agents, sysinfo):
        self.sysinfo = sysinfo
        self.entries = self.sysinfo.get("agent_process_info", [])
        self.expected_agents = cfg.get("expected_agents", [])
        self.results = []
    
    def offer(self, line, i, window):
        pass  # data comes from sysinfo, not the log

    def resolve(self):
        if not self.expected_agents or len(self.entries) == 0:
            self.results.append((
                "agent detection",
                "sysinfo.jsonl entries in window",
                "0",
                "INCONCLUSIVE",
                "no agents in window",
            ))
            return

        proc_dict = {}

        for entry in self.entries:
            name_proc = entry.get("agent_process_name")

            #Check if user_sid is recorded, i.e. not empty string
            user_sid = entry.get("agent_process_user_sid")
            #Check if Primary
            token_type = entry.get("agent_process_token_type")
            #Check if non-empty
            privileges = entry.get("agent_process_privileges")
            #Check from roster if right level
            integrity_level = entry.get("agent_process_integrity_level")
            #Check from roster elevated level
            is_elevated = entry.get("agent_process_is_elevated")

            proc_dict[name_proc] = [user_sid, token_type, privileges, integrity_level, is_elevated]


        for ea in self.expected_agents:
            pname     = ea["process_name"]
            integrity_level = ea["agent_process_integrity_level"]
            is_elevated = ea["agent_process_is_elevated"]

            #finding matching proc in proc_dict
            properties = proc_dict.get(pname, [])
            
            if not properties:
                self.results.append((
                    f"{pname}",
                    f"present in sysinfo.jsonl with expected values",
                    "absent in sysinfo.jsonl",
                    "NOT_DETECTED",
                    f"{pname} not in sysinfo.jsonl this window -- "
                    f"process not detected",
                ))
                continue
            
            local_result = [f"{pname}", f"user_sid, privileges->not empty, type->primary, integrity->{integrity_level}, is_elevated->{is_elevated}",
            "", "", ""]
            grade = 3
            sp_grade = 2
            if not properties[0]: #user_sid
                local_result[2] = local_result[2] + "user_sid is empty,"
                grade = grade - 1
            else:
                local_result[2] = local_result[2] + "user_sid is present,"

            if not properties[2]: #privileges
                local_result[2] = local_result[2] + " privileges is empty,"
                grade = grade - 1
            else:
                local_result[2] = local_result[2] + " privileges are present,"

            if properties[1] == "Primary": #token type
                local_result[2] = local_result[2] + " token type is primary,"
            else:
                local_result[2] = local_result[2] + " token type is not primary,"
                grade = grade - 1

            if properties[3] != integrity_level: 
                sp_grade = sp_grade - 1
            
            local_result[2] = local_result[2] + f" integrity level is {properties[3]},"

            if properties[4] != is_elevated: 
                sp_grade = sp_grade - 1
            
            local_result[2] = local_result[2] + f" is_elevated is {properties[4]}"
            
            if (sp_grade == 0):
                local_result[3] = "FAIL"
                if (grade == 0):
                    local_result[4] = "All 5 properties inaccurate"
                else:
                    local_result[4] = "Both integrity level and is_elevated are wrong values"
            
            elif (sp_grade == 1) or (sp_grade == 2 and grade < 3):
                local_result[3] = "PARTIAL"
                local_result[4] = "Not all fields match"
            
            elif sp_grade == 2 and grade == 3:
                local_result[3] = "PASS"
                local_result[4] = "All fields match"

            self.results.append(tuple(local_result))
    
    def rows(self):
        for subject, expected, actual, result, comment in self.results:
            yield (self.name, subject, expected, actual, result, comment)

            


            

        

        

