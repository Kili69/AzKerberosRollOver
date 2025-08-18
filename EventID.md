#Known Event ID
This script writes events t the application log and to the Debuglog File. The following event will be logged:

|EventID |Severity|Message|
|---|---|---|
|3000    | Information | The script is started. This event contains the current log file        |
|3001    | Information | Sucessfully reset the password for the rollover account                |
|3002    | Information | The rollover account successfully authenticated to Entra.ID            |
|3003    | Information | Successfully update the Azure Kerberos object                          |
|3100    | Error       | The AzureADSSO Powershell module is missing                            |
|3101    | Error       | A Powershell Module is missing                                         |
|3102    | Error       | A permission error occured while resetting the password                |
|3103    | Error       | Multifactor enforced for the reset account                             |
|3104    | Error       | Multifactor enforced for the reset account                             |
|3105    | Error       | Password Error, the password is not synced to Entra.ID                 |
|3106    | Error       | The AzuerADssoACC account could not be found in the global catalog     |
|3107    | Warning     | The latest password reset doesn't expired the TGT lifetime             |    
|3197    | Error       | Can not write to log file                                              |
|3198    | Error       | Unknown authenthentication error                                       |  
|3199    | Error       | A unexpected error occurs                                              |
