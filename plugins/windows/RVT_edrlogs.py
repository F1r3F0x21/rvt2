# Copyright (C) INCIDE Digital Data S.L.
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.


import lzma
import os
import re
import shlex
import subprocess
import pytz
import base.job
import binascii
import xmltodict
from datetime import datetime, timedelta
from plistlib import InvalidFileException

class CortexLogs(base.job.BaseModule):
    
    """ Extract the Logfile

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.

    Configuration:
        - **logname**:  (String): Logfile name of Cortex logs
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('logname', 'cortex-xdr-payload')


    def run(self, path=None):
        
        if self.myconfig('logname') == "cortex-xdr-payload":
            pattern = r'(.*)\|(.*)\|(.*)\|(.*)\|(.*)\|(.*)'
            prog = re.compile(pattern)
            filename = os.path.basename(path)
            count_lines = 0
            prev_line_dict = {}

            for line in self.from_module.run(path):
                match = prog.match(line)
                if match:

                    if count_lines != 0:
                        count_lines = 0
                        yield prev_line_dict

                    count_lines = 1
                    timestamp, type, process, action, thread, message = match.groups()

                    log_entry_dict = {
                        "Time": timestamp.strip(),
                        "Message": message.strip(),
                        "type": type.strip(),
                        "ProcessId": process.strip(),
                        "action": action.strip(),
                        "thread": thread.strip(),
                        "LogFilename": filename.strip()
                    }

                    prev_line_dict = log_entry_dict
                else:
                    prev_line_dict["Message"] = prev_line_dict["Message"] + line

            if len(prev_line_dict) != 0:
                yield prev_line_dict
        
        elif self.myconfig('logname') == "trapsd":
            pattern = r'^(\S*)\s<(\S*)>\s(\S*)\s\[(\S*\s?\S*)\]\s*({[^}]*})(.*)$'
            prog = re.compile(pattern)

            filename = os.path.basename(path)
            count_lines = 0
            prev_line_dict = {}

            for line in self.from_module.run(path):
                match = prog.match(line)
                if match:

                    if count_lines != 0:
                        count_lines = 0
                        yield prev_line_dict

                    count_lines = 1
                    timestamp, severity, hostname, thread, context, message = match.groups(default='')

                    log_entry_dict = {
                        "Time": timestamp.strip(),
                        "Message": message.strip(),
                        "Level": severity.strip(),
                        "hostname": hostname.strip(),
                        "thread": thread.strip(),
                        "context": context.strip().strip('{}'),
                        "LogFilename": filename.strip()
                    }
                    prev_line_dict = log_entry_dict
                
                else:
                    prev_line_dict["Message"] = prev_line_dict["Message"] + line

            if len(prev_line_dict) != 0:
                yield prev_line_dict
 
        else:
            self.logger().warning("Log file" + self.myconfig('logtemplate') + " Not supported yet")


class ESETLogs(base.job.BaseModule):

    """ Parser the ESETLogs

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        rvthome = self.myconfig('rvthome')
        command = f"python3 {rvthome}/plugins/external/ESETLogParser/EsetLogParser.py '{path}'"
        args = shlex.split(command)
        process = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output_string = process.stdout.read().split('\n')
        for line in output_string:
            yield line


class McAfeeEndpointSecurityLogs(base.job.BaseModule):

    """ Parser the McAfeeEndpointSecurityLogs

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()
    
    def run(self, path=None):
        pattern = r'(\d+\/\d+\/\d+\s\d+:\d+:\d+\.?\d*\s(?:AM|PM))\s*([\w.]+\(?\d+\.\d+\)?)\s*<([\w\d-]+)>\s*(?:\(([^)]+)\))?\s*([\w.]+)\s*\:?\s*(.+)'
        prog = re.compile(pattern)
        filename = f"{os.path.basename(os.path.dirname(path))}/{os.path.basename(path)}"
        count_lines = 0
        prev_line_dict = {}

        for line in self.from_module.run(path):
            match = prog.search(line.strip())
            if match:

                if count_lines != 0:
                    count_lines = 0
                    yield prev_line_dict

                count_lines = 1

                timestamp, process, user, session, context, message = match.groups(default='')
                log_entry_dict = {
                    "Time": timestamp.strip(),
                    "Message": message.strip(),
                    "User": user.strip(),
                    "Process": process.strip(),
                    "LogFilename": filename,
                    "Session": session.strip(),
                    "Context": context.strip()
                }
                prev_line_dict = log_entry_dict
                
            else:
                if (line.strip() != "" and count_lines != 0):
                        prev_line_dict["Message"] = prev_line_dict["Message"] + line

        if len(prev_line_dict) != 0:
            yield prev_line_dict


class BitdefenderLogs(base.job.BaseModule):
    
    """ Parser the BitdefenderLogs Logfile

    Module description:
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):
        with open(path, 'r') as f:
            xml_content = f.read()

        # Parse the XML content into a dictionary
        parsed_dict = xmltodict.parse(xml_content)
        if "ScanSession" in parsed_dict:
            parsed_dict = parsed_dict["ScanSession"]
            parsed_dict["Time"] = parsed_dict.pop("@creationDate","")
            parsed_dict["LogFilename"] = parsed_dict.pop("@originalPath","")
            parsed_dict["Message"] = parsed_dict.pop("@name","")


            yield parsed_dict
        else:
            self.logger().warning(f"No ScanSession xml file found. This file: {path} need to be parsered.")


class McAfeeDesktopProtectionLogs(base.job.BaseModule):

    """ Parser the McAfee Logfile

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()
    
    def run(self, path=None):
        pattern = r'(\d+\/\d+\/\d+\s\d+:\d+:\d+\.?\d*)\s*(.*)'
        prog = re.compile(pattern)
        would_blocked = r'(Would\sbe\sblocked\sby\sAccess\sProtection\srule\s*\(.*?\))\s*(\S*)\s(.*?\.\S*)\s(.*?\.\S*).*(Action\sblocked\s:\s\w+)'
        prog_would_blocked = re.compile(would_blocked)
        blocked_by = r'Blocked by Access Protection rule\s+([^\s]+)\s+(.*?\.\S+).*(Action\sblocked\s:\s\w+)'
        prog_blocked_by = re.compile(blocked_by)
        filename = os.path.basename(path)
        count_lines = 0
        prev_line_dict = {}

        for line in self.from_module.run(path):
            match = prog.search(line.strip())
            if match:

                if count_lines != 0:
                    count_lines = 0
                    yield prev_line_dict

                count_lines = 1

                timestamp, message = match.groups(default='')
                log_entry_dict = {
                    "Time": timestamp.strip(),
                    "Message": message.strip(), 
                    "LogFilename": filename
                }

                match_would_blocked = prog_would_blocked.search(log_entry_dict["Message"])
                if match_would_blocked:
                    message_aux, user, process, object, action = match_would_blocked.groups(default='')
                    log_entry_dict["Message"] = message_aux
                    log_entry_dict["Object"] = object
                    log_entry_dict["User"] = user
                    log_entry_dict["Process"] = process
                    log_entry_dict["Action"] = action
                
                match_blocked_by = prog_blocked_by.search(log_entry_dict["Message"])
                if match_blocked_by:
                    user, object, action = match_blocked_by.groups(default='')
                    log_entry_dict["Object"] = object
                    log_entry_dict["User"] = user
                    log_entry_dict["Action"] = action

                prev_line_dict = log_entry_dict
                
            else:
                if (line.strip() != "" and count_lines != 0):
                        prev_line_dict["Message"] = prev_line_dict["Message"] + line

        if len(prev_line_dict) != 0:
            yield prev_line_dict


class DefenderLogs(base.job.BaseModule):
    
    """ Parser the Defender Logfile

    Module description:
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()

    def run(self, path=None):

        line_dict = self.parse_detection_history(path)
        line_dict["object"] = line_dict.pop("file","")
        line_dict["hash"] = line_dict.pop("ThreatTrackingSha256","")

        yield line_dict

    def byte_swap_to_int(self, hexval, str_flag=False):
        # ---------------------------------------------------------------------------------------
        # Code extracted from: https://github.com/jklepsercyber/defender-detectionhistory-parser/
        # ---------------------------------------------------------------------------------------
        # Reads in bytes, swaps endianness, and converts to an integer if needed.
        # str_flag gives us the value to return an endian-swapped, hex-string representation of a value. For some fields, this is more appropriate.
        
        hex_int = 0
        hexval = [hexval[i:i+2] for i in range(0, len(hexval), 2)] # need to swap endianness of filetime
        hexval.reverse()
        hexval = b''.join(hexval)
        if str_flag: # stopping point if only hex-string needed
            return hexval.decode('utf-8')
        hexval = [int("0x"+(hexval[i:i+1].decode('utf-8')),16) for i in range(0, len(hexval), 1)]
        exponent = len(hexval)-1
        while exponent>=0:
            hex_int += hexval[abs((len(hexval)-1)-exponent)]*(pow(16,exponent))
            exponent += -1

        return hex_int

    def parse_header_and_guid(self, file):
        # ---------------------------------------------------------------------------------------
        # Code extracted from: https://github.com/jklepsercyber/defender-detectionhistory-parser/
        # ---------------------------------------------------------------------------------------        
        # Validates that file is a proper DetectionHistory file, and returns parsed GUID value located directly after header.

        header = file.read(6) # 6 = known DetectionHistory header size
        if header != b'\x08\x00\x00\x00\x08\x00': # check file header against known valid DetectionHistory file header
            #Invalid DetectionHistory file!
            raise(InvalidFileException)
        file.read(18) # skipping over some zeroes, and an unknown 3-byte sequence between offset 08-0A
        guid_oct = list()
        guid_oct.append(binascii.hexlify(file.read(4)))
        guid_oct.append(binascii.hexlify(file.read(2)))
        guid_oct.append(binascii.hexlify(file.read(2)))
        guid_oct.append(binascii.hexlify(file.read(2))) # this hex is not flipped in file data
        guid_oct.append(binascii.hexlify(file.read(6))) # this hex is not flipped in file data
        
        oct_count = 0
        while oct_count<=2:
            oct = guid_oct[oct_count]
            newlist = [oct[i:i+2] for i in range(0, len(oct), 2)]
            newlist.reverse()
            guid_oct[oct_count] = b''.join(newlist)
            oct_count += 1

        guid_final = (guid_oct[0].decode('utf-8')+"-"
            +guid_oct[1].decode('utf-8')+"-"
            +guid_oct[2].decode('utf-8')+"-"
            +guid_oct[3].decode('utf-8')+"-"
            +guid_oct[4].decode('utf-8'))

        return guid_final


    def parse_filetime(self, file):
        # ---------------------------------------------------------------------------------------
        # Code extracted from: https://github.com/jklepsercyber/defender-detectionhistory-parser/
        # ---------------------------------------------------------------------------------------
        # Parse known filetime hex string to a readable timestamp.

        filetime = ""
        filetime_nanoseconds = 0
        file.read(4) # skip ahead known distance between "Time" field and FILETIME timestamp
        filetime = binascii.hexlify(file.read(8))
        filetime_nanoseconds = self.byte_swap_to_int(filetime)
        filetime_epoch = timedelta(microseconds=float(filetime_nanoseconds/10)) # time represented in hundreds of nanoseconds
        filetime_date = datetime(1601, 1, 1)+filetime_epoch # FILETIME begins on Jan 1, 1601
        return filetime_date.strftime("%m-%d-%Y %H:%M:%S")


    def parse_unmapped_value(self, file):
        # ---------------------------------------------------------------------------------------
        # Code extracted from: https://github.com/jklepsercyber/defender-detectionhistory-parser/
        # ---------------------------------------------------------------------------------------
        # Decoding bytes of high hex vals can result in unmapped chars. Returns bytes of some unknown hex string.
        # Based on Windows specs, ThreatID should be an Int64, though this does not always seem to be the case.
        # https://docs.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection?view=windowsserver2022-ps
        # https://www.windows-security.org/c328023496d244ced5d0c4445e4f1806/threat-id-exclusions

        unmapped_val = ""
        chunk = file.read(1) # initial byte to perform checks off of in loop
        while True: # loop that checks for beginning of unmapped value
            if chunk==b'\x00': 
                chunk = chunk+file.read(1)
                if chunk==b'\x00\x00': 
                    chunk = chunk+file.read(1)
                    if chunk==b'\x00\x00\x00': 
                        break
            else:
                chunk = file.read(1) # go to next byte

        caution_sequences = [b'\x00', b'\x32', b'\x24', b'\x04', b'\x06'] # hex bytes observed in file which are known to delimit data from empty bytes
        unmapped_val = file.read(3) # Windows should always allocate at least this much for an unknown hex string in this file.
        chunk = file.read(1)
        while True: # loop to read in rest of unmapped value, as well as check for ending point
            while chunk in caution_sequences:
                next_chunk = file.read(1)
                if next_chunk==b'\x00':
                    return binascii.hexlify(unmapped_val)
                chunk = next_chunk
            # progress to this code if chunk not in 'caution_sequences'            
            unmapped_val += chunk
            chunk = file.read(1)
        
        return 0 # should never get to this point


    def parse_detection_history(self, filepath):
        # ---------------------------------------------------------------------------------------
        # Code adapted from: https://github.com/jklepsercyber/defender-detectionhistory-parser/
        # ---------------------------------------------------------------------------------------
        # Main function to parse given DetectionHistory file and write output fields to a readable file.

        parsed_value_dict = dict()

        # DEFINE MODES
        KEY_READ_MODE = b'\x00'
        VALUE_READ_MODE = b'\x01'
        NULL_DATA_MODE = b'\x02'
        CURRENT_MODE = KEY_READ_MODE
        LAST_READ_MODE = b'\xFF'
        # DEFINE SECTIONS
        MAGIC_VERSION_SECTION = b'\x04'
        GENERAL_SECTION = b'\x05'
        NEAREST_EOF_SECTION = b'\x06'
        # EXTRA NEEDED VARIABLES
        EOF_SECTION_KEYS = ["User","SpawningProcessName","SecurityGroup"] # Fields in this section not explicity defined in file, so fields named off based off current knowledge
        CURRENT_EOF_SECTION_KEY = -1

        with open(filepath, 'rb') as f:
            parsed_value_dict["GUID"] = self.parse_header_and_guid(f)
            f.read(8) # skipping over some empty space
            temp_key = ""

            while True:
                while MAGIC_VERSION_SECTION:
                    chunk = f.read(2)
                    if not chunk:
                        # End of section or file detected. Moving on...
                        MAGIC_VERSION_SECTION = 0 # break out of this section
                        break
                    if CURRENT_MODE==KEY_READ_MODE: 
                        if chunk==b'\x3A\x00': # first few sections are delimited by a Windows-1252 colon rather than multiple \x00 bytes
                            temp_key = re.sub("\x00", "", temp_key)
                            parsed_value_dict[temp_key] = "" # we will reset temp_key after setting the value
                            CURRENT_MODE = VALUE_READ_MODE 
                        else:
                            temp_key = temp_key+chunk.decode('windows-1252')
                            if "f\x00i\x00l\x00e" in temp_key: # file key/value pair signifies end of values delimited by colons (or \x3A)
                                # End of Magic Version section!
                                temp_key = re.sub("\x00", "", temp_key)
                                parsed_value_dict[temp_key] = "" # make sure "file" key gets assigned
                                CURRENT_MODE = VALUE_READ_MODE
                                MAGIC_VERSION_SECTION = 0 # break out of this section
                                f.read(16) # skip some zeroes to next section
                    elif CURRENT_MODE==VALUE_READ_MODE:
                        if chunk==b'\x00\x00': # if chunk to be read is empty
                            if f.read(2)==b'\x00\x00': # if next chunk empty as well
                                parsed_value_dict[temp_key] = re.sub("\x00", "", parsed_value_dict[temp_key]) # finalize value
                                temp_key = "" # reset temp key for next run
                                CURRENT_MODE=NULL_DATA_MODE
                        else:
                            parsed_value_dict[temp_key] += chunk.decode('windows-1252')
                    elif CURRENT_MODE==NULL_DATA_MODE:
                        if f.tell()==242:
                            parsed_value_dict["ThreatStatusID"] = self.byte_swap_to_int(binascii.hexlify(chunk))
                        if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=1: # regex function removes all non-alphanum characters
                            chunk = chunk+f.read(2) # double check if there are 2 alphanum chars in sequence. sometimes there are isolated, irrelevant hex values in file which are encodable chars
                            if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=2: 
                                temp_key += chunk.decode('windows-1252')
                                CURRENT_MODE = KEY_READ_MODE

                while GENERAL_SECTION:
                    chunk = f.read(2)
                    if not chunk:
                        # End of section or file detected. Moving on...
                        GENERAL_SECTION = 0 # break out of this section
                        break
                    elif CURRENT_MODE==NULL_DATA_MODE:
                        if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=1: # regex function removes all non-alphanum characters
                            chunk = chunk+f.read(2) # double check if there are 2 alphanum chars in sequence. sometimes there are isolated, irrelevant hex values in file which are encodable chars
                            if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=2: 
                                if LAST_READ_MODE==KEY_READ_MODE: # we need to switch back and forth between key and value reading
                                    parsed_value_dict[temp_key] += chunk.decode('windows-1252')
                                    CURRENT_MODE=VALUE_READ_MODE
                                else:
                                    temp_key += chunk.decode('windows-1252')
                                    CURRENT_MODE=KEY_READ_MODE
                        elif chunk==b'\x0A\x00' or chunk==b'\x00\x0A':
                            f.read(2)
                            chunk = f.read(4)
                            if chunk==b'\x15\x00\x00\x00' or chunk==chunk==b'\x00\x15\x00\x00': # false positives
                                continue
                            # End of General Section!
                            f.read(4) # skip over unneeded section of hex
                            GENERAL_SECTION = 0 # break out of this section
                    else: # Applies to KEY_READ or VALUE_READ mode
                        if chunk==b'\x00\x00': # Check to switch to NULL_MODE must happen in either KEY_READ or VALUE_READ mode          
                            if CURRENT_MODE==KEY_READ_MODE:
                                temp_key = re.sub("\x00", "", temp_key)
                                if "Magic." in temp_key[0:6]:
                                    # WARNING: Extraneous \"Magic Version\" key detected! Continuing...
                                    temp_key = "" # reset for next KEY_READ_MODE run
                                    LAST_READ_MODE = VALUE_READ_MODE # skip over this key, read in next key
                                elif "Time" in temp_key:
                                    parsed_value_dict[temp_key] = self.parse_filetime(f)
                                    temp_key = "" # reset for next KEY_READ_MODE run
                                    LAST_READ_MODE = VALUE_READ_MODE # value just set, read in next key
                                elif "ThreatTrackingThreatId" in temp_key or "ThreatTrackingSize" in temp_key:
                                    parsed_value_dict[temp_key] = self.byte_swap_to_int(self.parse_unmapped_value(f))   
                                    temp_key = "" # reset for next KEY_READ_MODE run
                                    LAST_READ_MODE = VALUE_READ_MODE # value just set, read in next key         
                                elif "ThreatTrackingSigSeq" in temp_key:
                                    parsed_value_dict[temp_key] = "0x0000"+self.byte_swap_to_int(self.parse_unmapped_value(f), str_flag=True)   
                                    temp_key = "" # reset for next KEY_READ_MODE run
                                    LAST_READ_MODE = VALUE_READ_MODE # value just set, read in next key                   
                                else:
                                    parsed_value_dict[temp_key] = "" # we will reset temp_key after setting the value in VALUE_READ_MODE
                                    LAST_READ_MODE = KEY_READ_MODE
                                CURRENT_MODE = NULL_DATA_MODE
                            elif CURRENT_MODE==VALUE_READ_MODE:
                                final_value = re.sub("\x00", "", parsed_value_dict[temp_key])
                                if "Threat" in final_value[0:6] or "regkey" in final_value[0:6]: # check for values that should be keys
                                    # WARNING: Irregularity in file/empty value caused skip in parsing for keys \"{temp_key}\" and \"{final_value}\". Configuring...
                                    parsed_value_dict[temp_key] = "" # reset extraneous value for temp_key
                                    parsed_value_dict[final_value] = "" # this value containing "Threat" or "regkey" should have been a key
                                    temp_key = final_value # set the final_value to the new key
                                    LAST_READ_MODE = KEY_READ_MODE # for that key, collect the next value
                                    if "ThreatTrackingThreatId" in temp_key or "ThreatTrackingSize" in temp_key:
                                        parsed_value_dict[temp_key] = self.byte_swap_to_int(self.parse_unmapped_value(f))  
                                        temp_key = "" # reset for next KEY_READ_MODE run
                                        LAST_READ_MODE = VALUE_READ_MODE
                                else: # when working as intended
                                    parsed_value_dict[temp_key] = final_value # finalize value
                                    LAST_READ_MODE = VALUE_READ_MODE 
                                    temp_key = "" # reset temp key for next KEY_READ_MODE
                                CURRENT_MODE = NULL_DATA_MODE
                        elif CURRENT_MODE==KEY_READ_MODE:
                            temp_key += chunk.decode('windows-1252')
                        elif CURRENT_MODE==VALUE_READ_MODE:
                            parsed_value_dict[temp_key] += chunk.decode('windows-1252')

                while NEAREST_EOF_SECTION:
                    chunk = f.read(2)
                    if not chunk: # indicates EOF
                        NEAREST_EOF_SECTION = 0 # break out of this section
                        break
                    elif CURRENT_MODE==NULL_DATA_MODE:
                        if chunk==b'\x0A\x00' or chunk==b'\x00\x0A': # track lines with "\x0A" bytes. This byte delimits an unknown hex sequence that (for now) we can skip
                            f.read(10)
                            continue
                        try:
                            if len(re.sub(r'\W+', '', chunk.decode('windows-1252')))>=1 and b'\x00' in chunk: # regex function removes all non-alphanum characters
                                chunk_extra = f.read(2) # we'll want to make sure these are windows-1252 valid bytes as well
                                chunk += chunk_extra # double check if there are 2 alphanum chars in sequence. sometimes there are isolated, irrelevant hex values in file which are encodable chars
                                if len(re.sub(r':(?=..(?<!\d:\d\d))|[^a-zA-Z0-9 ](?<!:)', '', chunk.decode('windows-1252')))>=2 and b'\x00' in chunk_extra: # ensure colons are treated as alphanum chars with regex
                                    CURRENT_EOF_SECTION_KEY=CURRENT_EOF_SECTION_KEY+1 
                                    parsed_value_dict[EOF_SECTION_KEYS[CURRENT_EOF_SECTION_KEY]] = chunk.decode('windows-1252')
                                    CURRENT_MODE=VALUE_READ_MODE
                        except UnicodeDecodeError as e:
                            self.logger().error(f"WARNING: ||{e}|| caught for bytes {chunk} : Unreadable hex pattern identified. Continuing...")
                    elif CURRENT_MODE==VALUE_READ_MODE:                  
                        if chunk==b'\x00\x00': # Check to switch to NULL_MODE 
                            parsed_value_dict[EOF_SECTION_KEYS[CURRENT_EOF_SECTION_KEY]] = re.sub("\x00", "", parsed_value_dict[EOF_SECTION_KEYS[CURRENT_EOF_SECTION_KEY]])       
                            CURRENT_MODE=NULL_DATA_MODE
                        else:
                            parsed_value_dict[EOF_SECTION_KEYS[CURRENT_EOF_SECTION_KEY]] += chunk.decode('windows-1252')
                
                break 

            return parsed_value_dict


class SophosEndpointLogs(base.job.BaseModule):
    
    """ Parser the SophosEndpointLogs Logfile

    Module description:
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()
        self.set_default_config('logname', 'default')
        
    def run(self, path=None):
        logname = self.myconfig('logname')

        if logname == 'default':
            self.logger().error("logname is not specified")
            return []
        
        else:
            if logname == "sed":
                pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.?\d*Z)\s(\S+)(.*)'
                prog = re.compile(pattern)
                filename = os.path.basename(path)
                count_lines = 0
                prev_line_dict = {}
                for line in self.from_module.run(path):
                    match = prog.search(line.strip())
                    if match:
                        if count_lines != 0:
                            count_lines = 0
                            yield prev_line_dict

                        count_lines = 1
                        timestamp, logname, message = match.groups(default='')
                        log_entry_dict = {
                            "Time": timestamp.strip(),
                            "Message": message.strip(), 
                            "LogFilename": filename
                        }
                        prev_line_dict = log_entry_dict
                    else:
                        if (line.strip() != "" and count_lines != 0):
                            prev_line_dict["Message"] = prev_line_dict["Message"] + line

                if len(prev_line_dict) != 0:
                    yield prev_line_dict
            
            elif logname == "sam":
                pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.?\d*Z)\s(.*)'
                prog = re.compile(pattern)
                filename = os.path.basename(path)
                count_lines = 0
                prev_line_dict = {}
                for line in self.from_module.run(path):
                    match = prog.search(line.strip())
                    if match:
                        if count_lines != 0:
                            count_lines = 0
                            yield prev_line_dict

                        count_lines = 1
                        timestamp, message = match.groups(default='')
                        log_entry_dict = {
                            "Time": timestamp.strip(),
                            "Message": message.strip(), 
                            "LogFilename": filename
                        }
                        prev_line_dict = log_entry_dict
                    else:
                        if (line.strip() != "" and count_lines != 0):
                            prev_line_dict["Message"] = prev_line_dict["Message"] + line

                if len(prev_line_dict) != 0:
                    yield prev_line_dict
            
            elif logname == "sna":
                pattern = r'(\S+)\s(\S+)(.*)'
                prog = re.compile(pattern)
                filename = os.path.basename(path)
                count_lines = 0
                prev_line_dict = {}
                for line in self.from_module.run(path):
                    match = prog.search(line)
                    if match:
                        if count_lines != 0:
                            count_lines = 0
                            yield prev_line_dict

                        count_lines = 1
                        timestamp, logname, message = match.groups(default='')
                        log_entry_dict = {
                            "Time": timestamp.strip(),
                            "Message": message.strip(), 
                            "LogFilename": filename
                        }
                        prev_line_dict = log_entry_dict
                    else:
                        if (line.strip() != "" and count_lines != 0):
                            prev_line_dict["Message"] = prev_line_dict["Message"] + line

                if len(prev_line_dict) != 0:
                    yield prev_line_dict


class EventJournals(base.job.BaseModule):

    """ Parser the Sophos EventJournals files

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()
    
    def run(self, path=None):
        pattern = r'^(\w+)-(\w+)-(\w+)-(\d+)-(\d+)(\..+)?'
        prog = re.compile(pattern)
        filename = os.path.basename(path)

        match = prog.search(filename)
        if match:
            app, proc1, proc2, timestamp1, timestamp2, extension = match.groups(default='')

            datetime1 = self.ldap_to_datetime(int(timestamp1))
            datetime2 = self.ldap_to_datetime(int(timestamp2))
            if extension ==".xz":
                with lzma.open(path, 'rb') as f:
                    data = f.read()
                    decoded_data = data.decode('utf-8', errors='ignore')
                    printable_strings = re.findall(r'[\x20-\x7E]{6,}', decoded_data)
                    printable_strings = list( dict.fromkeys(printable_strings) )
                    for string in printable_strings:
                        log_dict = {
                            "@timestamp": datetime1,
                            "timestamp2": datetime2,
                            "process1": proc1,
                            "process2": proc2,
                            "data": string
                        }
                        yield log_dict
            else:
                with open(path, 'rb') as f:
                    data = f.read()
                    decoded_data = data.decode('utf-8', errors='ignore')
                    printable_strings = re.findall(r'[\x20-\x7E]{6,}', decoded_data)
                    printable_strings = list( dict.fromkeys(printable_strings) )
                    for string in printable_strings:
                        log_dict = {
                            "@timestamp": datetime1,
                            "timestamp2": datetime2,
                            "process1": proc1,
                            "process2": proc2,
                            "data": string
                        }
                        yield log_dict
        else:
            self.logger().error(f"Filename: {filename}, doesn't have the expected structure")
            return[]
    
    def ldap_to_datetime(self, timestamp):
        # Convert LDAP timestamp to seconds since January 1, 1601 (UTC)
        seconds_since_1601 = timestamp / 10000000
        delta = timedelta(seconds=seconds_since_1601)
        start_date = datetime(1601, 1, 1)
        result_date = start_date + delta
        # Convert to UTC
        utc_timezone = pytz.utc
        result_utc_date = result_date.astimezone(utc_timezone)
        return result_utc_date
    

class KasperskyEndpoint(base.job.BaseModule):

    """ Parser the KasperskyEndpoint Message windows events

    Module description:
        - **from_module**: Data dict.
        - **yields**: The updated dict data.
    """

    def read_config(self):
        super().read_config()
    
    def run(self, path=None):
        pattern_path = r'Ruta\sde\sla\saplicación:\s?(.*?)\\r|Application\spath:\s?(.*?)\\r'
        prog_path = re.compile(pattern_path)
        pattern_name = r'Nombre:\s?(.*?)\\r|Name:\s?(.*?)\\r'
        prog_name = re.compile(pattern_name)
        pattern_user = r'Usuario:\s?(.*?)\\r|User:\s?(.*?)\\r'
        prog_user = re.compile(pattern_user)  

        for line in self.from_module.run(path):
            message = line["Message"]

            match_path = prog_path.search(message)
            if match_path:
                path = match_path.groups(default='')
                line["Object"] = "".join(path).strip()

            match_namefile = prog_name.search(message)
            if match_namefile:
                namefilelist = match_namefile.groups(default='')
                namefile = "".join(namefilelist).strip()
                line["Object"] = line.get("Object","") + "\\" + namefile

            match_user = prog_user.search(message)
            if match_user:
                user = match_user.groups(default='')
                line["User"] = "".join(user).strip()

            yield line
        
