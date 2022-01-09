# Cloudflare Dynamic DNS IP Updater
<img alt="GitHub" src="https://img.shields.io/github/license/timetoexpire/cloudflare-ddns-updater?color=black"> <img alt="GitHub last commit (branch)" src="https://img.shields.io/github/last-commit/timetoexpire/cloudflare-ddns-updater/main"> <img alt="GitHub contributors" src="https://img.shields.io/github/contributors/timetoexpire/cloudflare-ddns-updater">

This script is used to update dynamic DNS entries for accounts on Cloudflare.
You are able to get status reports via Slack/eMail

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
cloudflare-ddns-updater.sh -help` 

`bash cloudflare-ddns-updater.sh -tolerant mydomain.com -sleep=10 example.com -proxy=false www.example.com -auth_ttl=10 x1.example.com`

[script] help, tolerant, debug, config_file, sleep, rsleep

[Cloudflare] auth_email, auth_method, auth_key, auth_identifier, auth_ttl, auth_proxy, purge

[Slack] slackuri

[SMTP] email_username, email_password, email_smtp, email_port, email_fromName, email_toName, email_fromAddress, email_toAddress

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

## Reference
This script was made with reference from [Keld Norman](https://www.youtube.com/watch?v=vSIBkH7sxos) video.

This was forked from [Jason K](https://github.com/K0p1-Git/cloudflare-ddns-updater) script.

## License
[MIT](https://github.com/timetoexpire/cloudflare-ddns-updater/blob/main/LICENSE)
