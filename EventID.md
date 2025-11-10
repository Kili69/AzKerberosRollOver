#Known Event ID
This script writes events t the application log and to the Debuglog File. The following event will be logged:

|EventID |Severity|Message|
|---|---|---|
|3000    | Information | The script is started. This event contains the current log file            |
|3001    | Information | Sucessfully reset the password for the rollover account                    |
|3002    | Information | Azure AD conenct sync started                                              |
|3003    | Information | The rollover account successfully authenticated to Entra.ID                |
|3004    | Information | Successfully update the Azure Kerberos object                              |
|3005    | Warning     | Script terminated with error                                               |
|3006    | Information | Script finished successfully                                               |
|3007    | Information | Impersonation account information                                          |
|3008    | Warning     |Skipping the TGT lifetime check as the IgnoreTGTLifetimeCheck switch is set |
|3100    | Warning     | The Azure Sync wait time is to low change to minimum value                 |
|3101    | Warning     | The Azure Sync wait time it to high change to maximum value                |
|3102    | Error       | A permission error occured while resetting the password                    |
|3103    | Error       | Multifactor enforced for the reset account                                 |
|3104    | Error       | Multifactor enforced for the reset account                                 |
|3105    | Error       | Password Error, the password is not synced to Entra.ID                     |
|3106    | Error       | The AzuerADssoACC account could not be found in the global catalog         |
|3107    | Warning     | The latest password reset doesn't expired the TGT lifetime                 |
|3108    | Error       | The rollover user account could not be found                               |
|3109    | Error       | The active directory user could not be found                               |    
|3110    | Error       | Invalid Argument provided                                                  |
|3111    | Error       | A Powershell Module is missing                                             |
|3112    | Warning     | The TGT life time is below the minimum supported value                     |
|3113    | Warning     | The TGT life time exceed the maximum supported value                       |
|3196    | Warning     | Script terminated with errors                                              |
|3197    | Error       | Can not write to log file                                                  |
|3198    | Error       | Unknown authenthentication error                                           |  
|3199    | Error       | A unexpected error occurs                                                  |
