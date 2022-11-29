<%
source = data[0]['source']
os_info = data[0]['os_info']
subtitle = '##'
%>
# Source ${source} OS characterization

% for p in os_info:

${subtitle} Partition ${p[1:]} description
${subtitle}# OS Information

|Information|Value|
--|--
**ProductName**| ${os_info[p].get("ProductName", 'Unknown')}
**ComputerName**| ${os_info[p].get("ComputerName", 'Unknown')}
**ProductId**| ${os_info[p].get("ProductId", 'Unknown')}
**RegisteredOwner**| ${os_info[p].get("RegisteredOwner", 'Unknown')}
**RegisteredOrganization**| ${os_info[p].get("RegisteredOrganization", 'Unknown')}
**CurrentVersion**| ${os_info[p].get("CurrentVersion", 'Unknown')}
**CurrentBuild**| ${os_info[p].get("CurrentBuild", 'Unknown')}
**InstallationType**| ${os_info[p].get("InstallationType", 'Unknown')}
**EditionID**| ${os_info[p].get("EditionID", 'Unknown')}
**ProcessorArchitecture**| ${os_info[p].get("ProcessorArchitecture", 'Unknown')}
**TimeZone**| ${os_info[p].get("TimeZone", 'Unknown')}
**InstallDate**| ${os_info[p].get("InstallDate", 'Unknown')}
**ShutdownTime**| ${os_info[p].get("ShutdownTime", 'Unknown')}
**IpAddress**| ${os_info[p].get("IpAddress", '-')}

${subtitle}# Users

[[[inlinetable(Users,m{5cm}m{4cm}m{4cm})]]]
User|Creation date (UTC)|Last login/logoff (UTC)
--|--|--
% for u, user_data in os_info[p].get("users", {}).items():
${u}|${user_data['creation_time']}|${user_data['last_write']}
% endfor

${subtitle}# User profiles

[[[inlinetable(User Profiles,m{4cm}m{2.2cm}m{2.2cm}m{4cm})]]]
User|Creation date (UTC)|Last login/logoff (UTC)|SID
--|--|--|--
% for u, user_data in os_info[p].get("user_profiles", {}).items():
${u}|${user_data['creation_time']}|${user_data['last_write']}|${user_data['sid']}
% endfor


% endfor
