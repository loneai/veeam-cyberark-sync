@{
    CyberArkServer = 'cyberark.example.com'
    AppID          = 'YOUR_APPID'
    Safe           = 'YOUR_SAFE'
    Folder         = 'Root'

    AIMPath        = '/AIMWebService/api/Accounts'
    ObjectsFile    = '.\examples\objects.txt'

    LogFile        = 'C:\Logs\CyberArk_VeeamCredsSync.log'
    TimeoutSec     = 60

    # Not recommended unless needed
    SkipCertificateCheck = $false
}

