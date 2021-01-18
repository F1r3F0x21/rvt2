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

${subtitle}# Users

User|Creation date (UTC)|Last login/logoff (UTC)
--|--|--
% for u in os_info[p].get("users", []):
${u[0]}|${u[1]}|${u[2]}
% endfor

${subtitle}# User profiles
User|Creation date (UTC)|Last login/logoff (UTC)|SID
--|--|--|--
% for u in os_info[p].get("user_profiles", []):
${u[0]}|${u[1]}|${u[2]}|${u[3]}
% endfor


% endfor
