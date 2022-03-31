# Cloudflare Dynamic DNS IP Updater
<img alt="GitHub" src="https://img.shields.io/github/license/timetoexpire/cloudflare-ddns-updater?color=black"> <img alt="GitHub last commit (branch)" src="https://img.shields.io/github/last-commit/timetoexpire/cloudflare-ddns-updater/main"> <img alt="GitHub contributors" src="https://img.shields.io/github/contributors/timetoexpire/cloudflare-ddns-updater">

This script is used to update dynamic DNS entries for accounts on Cloudflare.

This script where it been attempted to as Bash POSIX as possible. 

You are able to get status reports via Slack/eMail/Console/File/Nextcloud/Telegram

Now with support for Windows Subsystem for Linux (WSL).

The only other thing might need to install are _curl_ and _jq_.

## Installation

```bash
git clone https://github.com/timetoexpire/cloudflare-ddns-updater.git
```

## Usage

TODO Need to edit this

This script is used with crontab. Specify the frequency of execution through crontab.

```bash
# ┌───────────── minute (0 - 59)
# │ ┌───────────── hour (0 - 23)
# │ │ ┌───────────── day of the month (1 - 31)
# │ │ │ ┌───────────── month (1 - 12)
# │ │ │ │ ┌───────────── day of the week (0 - 6) (Sunday to Saturday 7 is also Sunday on some systems)
# │ │ │ │ │ ┌───────────── command to issue                               
# │ │ │ │ │ │
# │ │ │ │ │ │
# * * * * * /bin/bash {Location of the script}
```

## Commands
`bash
cloudflare-template.sh -help` 

`bash cloudflare-template.sh -tolerant mydomain.com -sleep=10 example.com -proxy=false www.example.com -auth_ttl=10 x1.example.com`

<details><summary>[script] -help, -tolerant, -debug, -config_file, -sleep, -rsleep, -purge</summary>
  
- -help , list commands
  
- -tolerant ,  - - - - - - TODO - - - - -

- -debug , will output to console a debug log
  
- -config_file=X , this is config that to used

- -sleep=X , this is sleep timer for that script

- -rsleep=X , this will set a random legth time sleep timer for the script
  
- <details><summary>-purge=x , To purge settings (operates using bitwise values)</summary>
  <p>  
    
  | Value | Option        |  Purged Settings                                                                                                          |
  |-------|---------------|---------------------------------------------------------------------------------------------------------------------------|
  | 1     | Cloudflare    | auth_email, auth_method=token, auth_key, zone_identifier, auth_ttl=3600, auth_proxy=true                                  |
  | 2     | DNS           | ip_maxage=60, ip_timestamp=0, ip                                                                                          |
  | 4     | Report        | report_attribute=0, report_distribution=0, report_name                                                                    |
  | 8     | Slack         | slackuri                                                                                                                  |
  | 16    | eMail         | email_username, email_password, email_smtp, email_port, email_fromName, email_toName, email_fromAddress, email_toAddress  |
  | 32    | File          | file_logPath                                                                                                              |
  | 64    | Telegram      | telegram_token, telegram_chatID                                                                                           |
  | 128   | Nextcloud     | nextcloud_domain, nextcloud_username, nextcloud_apppass, nextcloud_roomtoken                                              |
   
  _example:_ 
    - Purge **Nothing** set it to **0**.
    
    - Purge **Cloudflare** only set it to **1**. 
    
    - Purge **Report** and **Slack** set it to **12** (4+8=12). 
    
    - Purge **Report**, **Slack**, **eMail**, **File**, **Telegram**, **Nextcloud** set it to **252** (4+8+16+32+64+128=252)

  </details>
  
</details>
  
<details><summary>[Cloudflare] -auth_email, -auth_method, -auth_key, -zone_identifier, -auth_ttl, -auth_proxy</summary>

-  -auth_email=X , The e-mail that used to login to cloudflare 'https://dash.cloudflare.com'

-  -auth_method=X , Set to "global" for Global API Key or "token" for Scoped API Token 
  
-  -auth_key=X , The Global API Key or Scope API Token
  
-  -zone_identifier=X , Can be found in the "Overview" tab of your domain
  
-  -auth_ttl=X DNS Record TTL (seconds)
  
-  -auth_proxy=X , Set to "ture" to using cloudflare Proxing service or set to "false" do disclose you IP publicly
  
</details>

<details><summary>[DNS] -record_name, -ip_recheck, -ip_set, -ip_maxage</summary>
  
- -record_name=X , this record that wish update [testing123.example.com]
  
- -ip_recheck , this will purge ip that know to system so will check if there updated one
  
- -ip_set=X ,  this will set ip record to what you want to define [1.1.1.1]. There 24 hours (86400 seconds) from time it set until recheck publicly for IP. _-ip_maxage_ value it upon this value, so if _-ip_maxage=60_ then is 24 hours and 1 minute (86460 seconds). If _-ip_recheck_ XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
  
- -ip_maxage=X , How many time (seconds) that have to pass until it checks for IP number again. If use _-ip_set_ then note changes that happen when using command _-ip_set_ for more information

</details>

<details><summary>[Reports] -report_distribution, -report_attribute, -report_name</summary>
<p>
  
- <details><summary>-report_distribution=X , services that being used sending reports (operates using bitwise values)</summary>
  <p>
  
  | Value | Option        |
  |-------|---------------|
  | 1     | Slack         |
  | 2     | eMail         |
  | 4     | Console       |
  | 8     | File          |
  | 16    | Telegram      |
  | 32    | Nextcloud     |
   
  _example:_ 
    - Distribution **disable** set it to **0**. 
    
    - Distribution **Console** only set it to **4** (4=4). 
    
    - Distribution **eMail** and **Console** set it to **6** (2+4=6)
  </p>
  </details>
- <details><summary>-report_attribute=X , control which atttibute is contained in the report (operates using bitwise values)</summary>
  <p>  
    
  | Value | Option        |
  |-------|---------------|
  | 1     | Account       |
  | 2     | Type          |
  | 4     | IP Address    |
  | 8     | Proxy         |
  | 16    | TTL           |
  | 32    | Time          |
  | 64    | Identifier    |
  | 128   | BootID        |
  | 256   | Status        |
  
  _example:_ 
    - Attribute **disable** set it to **0**.
    
    - Attribute **Account** only set it to **1**. 
    
    - Attribute **Account** and **Proxy** set it to **9** (1+8=9). 
    
    - Attribute **Acount**, **Type**, **IP Address**, **Proxy**, **TTL**, **Time**, **Identifier**, **BootID** and **Status** set it to **511** (1+2+4+8+16+32+64+128+256=511)
  
  </p>
  </details>
  
- -report_name=X , this is system identifier name being used, if it not be set it will hostname instead
</p>
</details>

<details><summary>[Slack] -slackuri</summary>
  
  The _-report_distribution_ has an bitwise value of _1_
  
-  -slackuri=X , URI for Slack WebHook [https://hooks.slack.com/services/xxxxx]
  
  | Command              | Requirements |
  |----------------------|--------------|
  | -slackuri            | **Required** |
  
</details>

<details><summary>[SMTP] -email_username, -email_password, -email_smtp, -email_port, -email_fromName, -email_toName, -email_fromAddress, -email_toAddress</summary>

  The _-message_type_ has an bitwise value of _2_
  
-  -email_username=X , SMTP login username

-  -email_password=X , SMTP login password
  
-  -email_smtp=X , ip/domain name of the SMTP server
  
-  -email_port=X , port number used to connect to SMTP server
  
-  -email_fromName=X , name that being used for that e-mail (from) [Joe Bloggs]
  
-  -email_toName=X , name that being used for that e-mail (to) e-mail [Jane Doe]
  
-  -email_fromAddress=X , email address that being used (from) [joe@example.com]

-  -email_toAddress=X , email address that being used (to) [jane@example.org]
  
  | Command              | Requirements |
  |----------------------|--------------|
  | -email_username      | **Required** |
  | -email_password      | **Required** |
  | -email_smtp          | **Required** |
  | -email_port          | Recommended  |
  | -email_fromName      | Optional     |
  | -email_toName        | Optional     |
  | -email_fromAddress   | **Required** |
  | -email_toAddress     | Recommended  |
  
</details>

<details><summary>[File] -file_logPath</summary>
  
  The _-report_distribution_ has an bitwise value of _4_
 
-  -file_logPath=X , The location of where log file is saved
  
  | Command              | Requirements |
  |----------------------|--------------|
  | -file_logPath        | **Required** |
  
</details>


<details><summary>[Console] < No commands > </summary>
 
  The _-report_distribution_ has an bitwise value of _8_
  
  Output to Bash console
  
</details>

<details><summary>[Telegram] -telegram_token, -telegram_chatID</summary>
   
  The _-report_distribution_ has an bitwise value of _16_
  
-  -telegram_token=X , The API token that was issued by Telegram BotFather
  
-  -telegram_chatID=X , This is user that sending message to
  
  | Command              | Requirements |
  |----------------------|--------------|
  | -telegram_token      | **Required** |
  | -telegram_chatID     | **Required** |
  
  Setup support tool _tools/telegram.sh_
  
  _End-to-end encryption (E2EE) not supported_
  
  </details>
  
  <details><summary>[Nextcloud] -nextcloud_domain, -nextcloud_username, -nextcloud_apppass, -nextcloud_roomtoken</summary>
 
  The _-report_distribution_ has an bitwise value of _32_
  
-  -nextcloud_domain=X , The location of server as domain name [https://nextcloud.example.com] or as ip [https://192.168.1.60]
  
-  -nextcloud_username=X , The username name for Nextcloud
  
-  -nextcloud_apppass=X , The App-Password for Nextcloud
  
-  -nextcloud_roomtoken=X , Nexcloud talk room token ID
  
  | Command              | Requirements |
  |----------------------|--------------|
  | -nextcloud_domain    | **Required** |
  | -nextcloud_username  | **Required** |
  | -nextcloud_apppass   | **Required** |
  | -nextcloud_roomtoken | **Required** |
  
  Setup support tool _tools/nextcloud.sh_
    
  </details>

## Tools

### Nextcloud
  
   If authorise it will supply the valid information for
- -nextcloud_domain
- -nextcloud_username
- -nextcloud_apppass
- -nextcloud_roomtoken
  
### Telegram
  
  You will need your API token from Telegram BotFather.
  
  If authorise it will supply the valid information for
- -telegram_token
- -telegram_chatid

## Erratum

### GMail
  
[Google has changed it requirements for SMTP authentication](https://github.com/timetoexpire/cloudflare-ddns-updater/discussions/3)

#### Windows Subsystem for Linux 

It is possible to executable this Bash script using Windows Subsystem for Linux ("_WSL_"). 

Due limitations which Microsoft have imposed in _WSL_. It not possiable to use _syslog_ output to _/var/log/syslog_ .
  
Some messages will be output to the applicable console. But this is not being done using _logger_

#### Superuser 

It unnecessary execute this script as a Superuser ("_root_"). You are able to execute it as a _root_ user but it discouraged. It was designed to execute the Bash script as _non-root_ user. 

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Reference
This script was made with reference from [Keld Norman](https://www.youtube.com/watch?v=vSIBkH7sxos) video.

This was forked from [Jason K](https://github.com/K0p1-Git/cloudflare-ddns-updater) script.

## License
[MIT](https://github.com/timetoexpire/cloudflare-ddns-updater/blob/main/LICENSE)
