[An active directory service object was modified]
search = sourcetype=WinEventLog:Security EventCode=5136 
| rex field=Message "(?<summary>.*)" 
| rex field=Message "Subject:\s+Security ID:\s+(?<Subject_Security_ID>.*)\s+Account Name:\s+(?<Subject_Account_Name>.*)\s+Account Domain:\s+(?<Subject_Account_Domain>.*)\s+Logon ID:\s+(?<Subject_Logon_ID>.*)" 
| rex field=Message "Directory Service:\s+Name:\s+(?<DS_Name>.*)\s+Type:\s+(?<DS_Type>.*)" 
| rex field=Message "Object:\s+DN:\s+(?<Obj_DN>.*)\s+GUID:\s+(?<Obj_GUID>.*)\s+Class:\s+(?<Obj_Class>.*)" 
| rex field=Message "Attribute:\s+LDAP Display Name:\s+(?<Attr_LDAP_Display_Name>.*)\s+Syntax \(OID\):\s+(?<Attr_OID>.*)\s+Value:\s+(?<Attr_Value>.*)" 
| rex field=Message "Operation:\s+Type:\s+(?<Op_Type>.*)\s+Correlation ID:\s+(?<Op_Corr_ID>.*)\s+Application Correlation ID:\s+(?<Op_App_Corr_ID>.*)" 
| table _time host sourcetype EventCode summary Subject_Security_ID Subject_Account_Name Subject_Account_Domain Subject_Logon_ID DS_Name DS_Type Obj_DN Obj_GUID Obj_Class Attr_LDAP_Display_Name Attr_OID Attr_Value Op_Type Op_Corr_ID Op_App_Corr_ID

