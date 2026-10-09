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
|3102    | Error       | A permission error occured while resetting the password                    |
|3103    | Error       | Multifactor enforced for the reset account                                 |
|3104    | Error       | Multifactor enforced for the reset account                                 |
|3105    | Error       | Password Error, the password is not synced to Entra.ID                     |
|3106    | Error       | The AzuerADssoACC account could not be found in the global catalog         |
|3107    | Warning     | The latest password reset doesn't expired the TGT lifetime                 |
|3108    | Error       | The AzureADSSOAcc password was not updated                                 |
|3109    | Error       | The configured rollover account could not be found in Active Directory     |
|3110    | Error       | An invalid argument was provided or a required command is unavailable      |
|3111    | Error       | A Powershell Module is missing                                             |
|3112    | Warning     | The TGT life time is below the minimum supported value                     |
|3113    | Warning     | The TGT life time exceed the maximum supported value                       |
|3114    | Error       | The worker account password was not synchronized within five minutes       |
|3196    | Warning     | Script terminated with errors                                              |
|3197    | Error       | Can not write to log file                                                  |
|3198    | Error       | An invalid operation or authentication operation failed                    |
|3199    | Error       | A unexpected error occurs                                                  |
