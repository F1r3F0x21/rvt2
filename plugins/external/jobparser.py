#!/usr/bin/python3
import struct

"""
Based on https://github.com/gleeda/misc-scripts/blob/master/misc_python/jobparser.py

Author: Gleeda <jamie.levy@gmail.com>

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version
2 of the License, or (at your option) any later version.
"""


# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tsch/2d1fbbab-fe6c-4ae5-bdf5-41dc526b2439#Appendix_A_11
products = {
    0x400: "Windows NT 4.0",
    0x500: "Windows 2000",
    0x501: "Windows XP",
    0x600: "Windows Vista",
    0x601: "Windows 7",
    0x0602: "Windows 8",
    0x0603: "Windows 8.1",
    0x0a00: "Windows 10"
}

# https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-error-and-success-constants
task_status = {
    0x41300: "SCHED_S_TASK_READY", # Task is not running but is scheduled to run at some time in the future.
    0x41301: "SCHED_S_TASK_RUNNING", # Task is currently running.
    0x41302: "SCHED_S_TASK_DISABLED", # The task will not run at the scheduled times because it has been disabled.
    0x41303: "SCHED_S_TASK_HAS_NOT_RUN", # The task has not yet run.
    0x41304: "SCHED_S_TASK_NO_MORE_RUNS", # There are no more runs scheduled for this task.
    0x41305: "SCHED_S_TASK_NOT_SCHEDULED", # The task is not running and has no valid triggers.
    0x41306: "SCHED_S_TASK_TERMINATED", # The last run of the task was terminated by the user.
    0x41307: "SCHED_S_TASK_NO_VALID_TRIGGERS", # Either the task has no triggers or the existing triggers are disabled or not set.
    0x41308: "SCHED_S_EVENT_TRIGGER", # Event triggers don't have set run times.
    0x80041309: "SCHED_E_TRIGGER_NOT_FOUND", # Trigger not found.
    0x8004130A: "SCHED_E_TASK_NOT_READY", # One or more properties that are needed to run this task have not been set.
    0x8004130B: "SCHED_E_TASK_NOT_RUNNING", # There is no running instance of the task.
    0x8004130C: "SCHED_E_SERVICE_NOT_INSTALLED", # The Task Scheduler Service is not installed on this computer.
    0x8004130D: "SCHED_E_CANNOT_OPEN_TASK", # The task object could not be opened.
    0x8004130E: "SCHED_E_INVALID_TASK", # The object is either an invalid task object or is not a task object.
    0x8004130F: "SCHED_E_ACCOUNT_INFORMATION_NOT_SET", # No account information could be found in the Task Scheduler security database for the task indicated.
    0x80041310: "SCHED_E_ACCOUNT_NAME_NOT_FOUND", # Unable to establish existence of the account specified.
    0x80041311: "SCHED_E_ACCOUNT_DBASE_CORRUPT", # Corruption was detected in the Task Scheduler security database; the database has been reset.
    0x80041312: "SCHED_E_NO_SECURITY_SERVICES", # Task Scheduler security services are available only on Windows NT.
    0x80041313: "SCHED_E_UNKNOWN_OBJECT_VERSION", # The task object version is either unsupported or invalid.
    0x80041314: "SCHED_E_UNSUPPORTED_ACCOUNT_OPTION", # The task has an unsupported combination of account settings and run time options.
    0x80041315: "SCHED_E_SERVICE_NOT_RUNNING", # The Task Scheduler Service is not running.
    0x80041316: "SCHED_E_UNEXPECTEDNODE", # The task XML contains an unexpected node.
    0x80041317: "SCHED_E_NAMESPACE", # The task XML contains an element or attribute from an unexpected namespace.
    0x80041318: "SCHED_E_INVALIDVALUE", # The task XML contains a value which is incorrectly formatted or out of range.
    0x80041319: "SCHED_E_MISSINGNODE", # The task XML is missing a required element or attribute.
    0x8004131A: "SCHED_E_MALFORMEDXML", # The task XML is malformed.
    0x0004131B: "SCHED_S_SOME_TRIGGERS_FAILED", # At least one of the task's triggers failed to start the task.
    0x0004131C: "SCHED_S_BATCH_LOGON_PROBLEM", # Batch logon privilege needs to be enabled for the task principal.
    0x8004131D: "SCHED_E_TOO_MANY_NODES", # The task XML contains too many nodes of the same type.
    0x8004131E: "SCHED_E_PAST_END_BOUNDARY", # The task cannot be started after the trigger's end boundary.
    0x8004131F: "SCHED_E_ALREADY_RUNNING", # An instance of this task is already running.
    0x80041320: "SCHED_E_USER_NOT_LOGGED_ON", # The task will not run because the user is not logged on.
    0x80041321: "SCHED_E_INVALID_TASK_HASH", # The task image is corrupt or has been tampered with.
    0x80041322: "SCHED_E_SERVICE_NOT_AVAILABLE", # The Task Scheduler service is not available.
    0x80041323: "SCHED_E_SERVICE_TOO_BUSY", # The Task Scheduler service is too busy to handle your request. Please try again later.
    0x80041324: "SCHED_E_TASK_ATTEMPTED", # The Task Scheduler service attempted to run the task, but the task did not run due to one of the constraints in the task definition.
    0x00041325: "SCHED_S_TASK_QUEUED", # The Task Scheduler service has asked the task to run.
    0x80041326: "SCHED_E_TASK_DISABLED", # The task is disabled.
    0x80041327: "SCHED_E_TASK_NOT_V1_COMPAT", # The task has properties that are not compatible with previous versions of Windows.
    0x80041328: "SCHED_E_START_ON_DEMAND", # The task settings do not allow the task to start on demand.
    0x80041329: "SCHED_E_TASK_NOT_UBPM_COMPAT", # The combination of properties that task is using is not compatible with the scheduling engine.
    0x80041330: "SCHED_E_DEPRECATED_FEATURE_USED", # The task definition uses a deprecated feature.
    0x00006200: "SCHED_E_SERVICE_NOT_LOCALSYSTEM" # The Task Scheduler service must be configured to run in the System account.
}

weekdays = {
    0x0: "Sunday",
    0x1: "Monday",
    0x2: "Tuesday",
    0x3: "Wednesday",
    0x4: "Thursday",
    0x5: "Friday",
    0x6: "Saturday",
}

months = {
    0x1: "Jan",
    0x2: "Feb",
    0x3: "Mar",
    0x4: "Apr",
    0x5: "May",
    0x6: "Jun",
    0x7: "Jul",
    0x8: "Aug",
    0x9: "Sep",
    0xa: "Oct",
    0xb: "Nov",
    0xc: "Dec",
}

flags = {
    0x1:"TASK_APPLICATION_NAME",
    0x200000:"TASK_FLAG_RUN_ONLY_IF_LOGGED_ON",
    0x100000:"TASK_FLAG_SYSTEM_REQUIRED",
    0x80000:"TASK_FLAG_RESTART_ON_IDLE_RESUME",
    0x40000:"TASK_FLAG_RUN_IF_CONNECTED_TO_INTERNET",
    0x20000:"TASK_FLAG_HIDDEN",
    0x10000:"TASK_FLAG_RUN_ONLY_IF_DOCKED",
    0x80000000:"TASK_FLAG_KILL_IF_GOING_ON_BATTERIES",
    0x40000000:"TASK_FLAG_DONT_START_IF_ON_BATTERIES",
    0x20000000:"TASK_FLAG_KILL_ON_IDLE_END",
    0x10000000:"TASK_FLAG_START_ONLY_IF_IDLE",
    0x4000000:"TASK_FLAG_DISABLED",
    0x2000000:"TASK_FLAG_DELETE_WHEN_DONE",
    0x1000000:"TASK_FLAG_INTERACTIVE",
#     0x80: "TASK_APPLICATION_NAME",
#     0x40000: "TASK_FLAG_RUN_ONLY_IF_LOGGED_ON",
#     0x80000: "TASK_FLAG_SYSTEM_REQUIRED",
#     0x100000: "TASK_FLAG_RESTART_ON_IDLE_RESUME",
#     0x200000: "TASK_FLAG_RUN_IF_CONNECTED_TO_INTERNET",
#     0x400000: "TASK_FLAG_HIDDEN",
#     0x800000: "TASK_FLAG_RUN_ONLY_IF_DOCKED",
#     0x1000000: "TASK_FLAG_KILL_IF_GOING_ON_BATTERIES",
#     0x2000000: "TASK_FLAG_DONT_START_IF_ON_BATTERIES",
#     0x4000000: "TASK_FLAG_KILL_ON_IDLE_END",
#     0x8000000: "TASK_FLAG_START_ONLY_IF_IDLE",
#     0x20000000: "TASK_FLAG_DISABLED",
#     0x40000000: "TASK_FLAG_DELETE_WHEN_DONE",
#     0x80000000: "TASK_FLAG_INTERACTIVE",
}

# http://msdn.microsoft.com/en-us/library/cc248286%28v=prot.10%29.aspx
priorities = {
    0x20000000:"NORMAL_PRIORITY_CLASS",
    0x40000000:"IDLE_PRIORITY_CLASS",
    0x80000000:"HIGH_PRIORITY_CLASS",
    0x100000:"REALTIME_PRIORITY_CLASS",
#     0x800000: "NORMAL_PRIORITY_CLASS",
#     0x1000000: "IDLE_PRIORITY_CLASS",
#     0x2000000: "HIGH_PRIORITY_CLASS",
#     0x4000000: "REALTIME_PRIORITY_CLASS",
}

class JobDate:

    def __init__(self, data, scheduled=False):
        # scheduled is the time the job was scheduled to run
        self.scheduled = scheduled
        self.Year = struct.unpack("<H", data[:2])[0]
        self.Month = struct.unpack("<H", data[2:4])[0]
        if not self.scheduled:
            self.Weekday = struct.unpack("<H", data[4:6])[0]
            self.Day = struct.unpack("<H", data[6:8])[0]
            self.Hour = struct.unpack("<H", data[8:10])[0]
            self.Minute = struct.unpack("<H", data[10:12])[0]
            self.Second = struct.unpack("<H", data[12:14])[0]
            self.Milliseconds = struct.unpack("<H", data[14:16])[0]
        else:
            self.Weekday = None
            self.Day = struct.unpack("<H", data[4:6])[0]
            self.Hour = struct.unpack("<H", data[12:14])[0]
            self.Minute = struct.unpack("<H", data[14:16])[0]
            self.Second = struct.unpack("<H", data[16:18])[0]
            self.Milliseconds = struct.unpack("<H", data[18:20])[0]

    def __repr__(self):
        day = weekdays.get(self.Weekday, None)
        mon = months.get(self.Month, None)
        if day is not None and mon is not None and not self.scheduled:
            return "{}-{:02}-{:02} {:02}:{:02}:{:02}.{}".format(self.Year, self.Month, self.Day, self.Hour, self.Minute, self.Second, self.Milliseconds)
            # return "{0} {1} {2} {3:02}:{4:02}:{5:02}.{6} {7}".format(day, mon, self.Day, self.Hour, self.Minute, self.Second, self.Milliseconds, self.Year)
        elif self.scheduled:
            return "{}-{:02}-{:02} {:02}:{:02}:{:02}.{}".format(self.Year, self.Month, self.Day, self.Hour, self.Minute, self.Second, self.Milliseconds)
            # return "{0} {1} {2:02}:{3:02}:{4:02}.{5} {6}".format(mon, self.Day, self.Hour, self.Minute, self.Second, self.Milliseconds, self.Year)
        return ""

class UUID:

    def __init__(self, data):
        self.UUID0 = struct.unpack("<I", data[:4])[0]
        self.UUID1 = struct.unpack("<H", data[4:6])[0]
        self.UUID2 = struct.unpack("<H", data[6:8])[0]
        self.UUID3 = struct.unpack(">H", data[8:10])[0]
        self.UUID4 = struct.unpack(">H", data[10:12])[0]
        self.UUID5 = struct.unpack(">H", data[12:14])[0]
        self.UUID6 = struct.unpack(">H", data[14:16])[0]

    def __repr__(self):
        return "{" + "{0:08X}-{1:04X}-{2:04X}-{3:04X}-{4:02X}{5:02X}{6:02X}".format(self.UUID0, self.UUID1, self.UUID2,
                                                                                    self.UUID3, self.UUID4, self.UUID5, self.UUID6) + "}"

# http://msdn.microsoft.com/en-us/library/cc248285%28PROT.10%29.aspx


class Job:

    def __init__(self, data):
        info = {
            "ProductInfo": "",
            "FileVersion": "",
            "UUID": "",
            "Priorities": "",
            "MaximumRunTime": "",
            "ExitCode": "",
            "Status": "",
            "Flags": "",
            "RunDate": "",
            "RunningInstances": "",
            "Application": "",
            "Parameters": "",
            "WorkingDirectory": "",
            "User": "",
            "Comment": "",
            "ScheduledDate": "",
            "ErrorParsing": False
        }

        '''
        Fixed length section
        http://msdn.microsoft.com/en-us/library/cc248286%28v=prot.13%29.aspx
        '''
        try:
            info["ProductInfo"] = struct.unpack("<H", data[:2])[0]
            info["FileVersion"] = struct.unpack("<H", data[2:4])[0]
            info["UUID"] = UUID(data[4:20])
            self.AppNameLenOffset = struct.unpack("<H", data[20:22])[0]
            self.TriggerOffset = struct.unpack("<H", data[22:24])[0]
            self.ErrorRetryCount = struct.unpack("<H", data[24:26])[0]
            self.ErrorRetryInterval = struct.unpack("<H", data[26:28])[0]
            self.IdleDeadline = struct.unpack("<H", data[28:30])[0]
            self.IdleWait = struct.unpack("<H", data[30:32])[0]
            self.Priority = struct.unpack(">I", data[32:36])[0]
            info["MaximumRunTime"] = struct.unpack("<i", data[36:40])[0] # In milliseconds
            info["ExitCode"] = struct.unpack("<i", data[40:44])[0]
            info["Status"] = struct.unpack("<i", data[44:48])[0]
            self.Flags = struct.unpack(">I", data[48:52])[0]
            info["RunDate"] = JobDate(data[52:68])
        except Exception as exc:
            info["ErrorParsing"] = str(exc)

        info["ProductInfo"] = products.get(info["ProductInfo"], "None")
        info["Status"] = task_status.get(info["Status"], "Unknown Status")
        theflags = ""
        for flag in flags:
            if self.Flags & flag == flag:
                theflags += flags[flag] + ", "
        info["Flags"] = theflags.rstrip(", ")
        priority = ""
        for p in priorities:
            if self.Priority & p == p:
                priority += priorities[p] + ", "
        info["Priorities"] = priority.rstrip(", ")

        '''
        Variable length section
        http://msdn.microsoft.com/en-us/library/cc248287%28v=prot.10%29.aspx
        '''

        try:
            info["RunningInstances"] = struct.unpack("<H", data[68:70])[0]
            self.NameLength = struct.unpack("<H", data[70:72])[0]
            self.cursor = 72 + (self.NameLength * 2)
            if self.NameLength > 0:
                info["Application"] = data[72:self.cursor].decode("utf-16").rstrip('\x00')
            self.ParameterSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0]
            self.cursor += 2
            info["Parameters"] = ""
            if self.ParameterSize > 0:
                info["Parameters"] = data[self.cursor:self.cursor + self.ParameterSize * 2].decode("utf-16").rstrip('\x00')
                self.cursor += (self.ParameterSize * 2)
            self.WorkingDirectorySize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0]
            self.cursor += 2
            info["WorkingDirectory"] = "Working Directory not set"
            if self.WorkingDirectorySize > 0:
                info["WorkingDirectory"] = data[self.cursor:self.cursor + (self.WorkingDirectorySize * 2)].decode("utf-16").rstrip('\x00')
                self.cursor += (self.WorkingDirectorySize * 2)
            self.UserSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0]
            self.cursor += 2
            info["User"] = "User not set"
            if self.UserSize > 0:
                info["User"] = data[self.cursor:self.cursor + self.UserSize * 2].decode("utf-16").rstrip('\x00')
                self.cursor += (self.UserSize * 2)
            self.CommentSize = struct.unpack("<H", data[self.cursor:self.cursor + 2])[0]
            self.cursor += 2
            info["Comment"] = "Comment not set"
            if self.CommentSize > 0:
                info["Comment"] = data[self.cursor:self.cursor + self.CommentSize * 2].decode("utf-16").rstrip('\x00')
                self.cursor += self.CommentSize * 2
            # this is probably User Data + Reserved Data:
            self.UserData = data[self.cursor:self.cursor + 18]
            self.cursor += 18
            # This isn't really documented, but this is the time the job was scheduled to run:
            if len(data) >= self.cursor + 20:
                info["ScheduledDate"] = JobDate(data[self.cursor:self.cursor + 20], scheduled=True)
        except Exception as exc:
            info["ErrorParsing"] =str(exc)

        self.data = info

    def _get_job_info(self):
        return self.data
