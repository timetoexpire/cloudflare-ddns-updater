#!/bin/bash
## change to "bin/sh" when necessary

auth_email=""                                      # The email used to login 'https://dash.cloudflare.com'
auth_method="token"                                # Set to "global" for Global API Key or "token" for Scoped API Token 
auth_key=""                                        # Your API Token or Global API Key
zone_identifier=""                                 # Can be found in the "Overview" tab of your domain
record_name=""                                     # Which record you want to be synced
ttl="3600"                                         # Set the DNS TTL (seconds)
proxy="true"                                       # Set the proxy to true or false

config_file=""                                     # file location of config file

report_attribute="0"                               # (bitwise) (1)=Account (2)=Type (4)=IP Address (8)=Proxy (16)=TTL (32)=Time (64)=Identifier (128)=BootID (256)=Status   'https://en.wikipedia.org/wiki/Bitwise_operation'
report_name=""                                     # set an identifier name, if none is set (NULL) it will use $HOSTNAME
report_distribution="0"                            # (bitwise) (1)=Slack (2)=email (4)=console (8)=file (16)=telegram (32)=nextcloud 'https://youtu.be/LpuPe81bc2w'

slackuri=""                                        # URI for Slack WebHook "https://hooks.slack.com/services/xxxxx"

email_username=""                                  # email account username
email_password=""                                  # email account password
email_smtp=""                                      # email SMTP server
email_port=""                                      # email SMTP port number
email_fromName=""                                  # email poster name
email_fromAddress=""                               # email poster (email) address
email_toName=""                                    # email recive name
email_toAddress=""                                 # email recive (email) address, if empty will use one defined in $email_fromAddress

file_logPath=""                                    # File location of where it output the log, the file is appended

telegram_token=""                                  # API token that been issued by telegram #BotFather
telegram_chatID=""                                 # Telegram chatID

nextcloud_domain=""                                # Nextcloud server url 'https://nextcloud.example.com'
nextcloud_username=""                              # Nextcloud account username
nextcloud_apppass=""                               # Nextcloud account app-password
nextcloud_roomtoken=""                             # Nextcloud room token 

user_agent_name=""                                 # This part string that curl users as user agent, if set to Test123 supplement to curl user-agent "[uan Test123]"

ip_maxage="60"                                     # The max length time before IP recheck (60 seconds)

curl_max_time=30.5
log_name="DDNS Updater:"

####################################################
# Only edit bellow if understand what you are doing 
####################################################
parameter_input=("$@")


cf_ddns_ip () {
  ###########################################
  ## Check if we have a public IP
  ###########################################
  ip=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -4 https://api.ipify.org || curl -s --user-agent "$agent_name" --max-time $curl_max_time -4 https://ipv4.icanhazip.com/)
  if [ "${ip}" == "" ]; then 
    logger_output="$log_name No public IP found"
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
    #no point going on if can not get ip
    exit_code 1
  else
    ip_timestamp="$EPOCHSECONDS"
  fi
}

cf_ddns_authheader (){
  ###########################################
  ## Check and set the proper auth header
  ###########################################
  if [ "${auth_method}" == "global" ]; then
    auth_header="X-Auth-Key:"
  else
    auth_header="Authorization: Bearer"
  fi
 }

cf_ddns_seeka () {
  ###########################################
  ## Seek for the A record
  ###########################################
  WSL_Logger "$log_name Check Initiated"
  debug_output+="$logger_output\n"
  record=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -X GET "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records?type=A&name=$record_name" \
                        -H "X-Auth-Email: $auth_email" \
                        -H "$auth_header $auth_key" \
                        -H "Content-Type: application/json")
  debug_output+="cf_ddns_seeka : $record\n"
}

cf_ddns_checka () {
  ###########################################
  ## Check if the domain has an A record
  ###########################################
  if [[ $record == *"\"count\":0"* ]]; then
    logger_output="$log_name Record does not exist, perhaps create one first? (${ip} for ${record_name})"
      debug_output+="$logger_output\n"
      WSL_Logger -s "$logger_output"
      cf_nonexistsrecord=0
      exit_code 1
  else
    cf_nonexistsrecord=1
  fi
}

cf_ddns_recordchanged () {
  ###########################################
  ## The record has had an change
  ###########################################
  old_ip=$(echo "$record" | sed -E 's/.*"content":"(([0-9]{1,3}\.){3}[0-9]{1,3})".*/\1/')
  old_proxy=$(echo "$record" | sed 's/.*"proxied":"\{0,1\}\([^,"]*\)"\{0,1\}.*/\1/')
  old_ttl=$(echo "$record" | sed 's/.*"ttl":"\{0,1\}\([^,"]*\)"\{0,1\}.*/\1/')
  debug_output+="cf_ddns_recordchanged: record_name [$record_name] ip [$ip] old_ip [$old_ip] proxy [$proxy] old_proxy [$old_proxy] ttl [$ttl] old_ttl [$old_ttl]"

  # Compare if they're the same
  record_changed=0

  if [[ $ip != $old_ip ]]; then
    (( record_changed++ ))
  fi
  if [[ $proxy != $old_proxy ]]; then 
    (( record_changed++ ))
  fi
  if [[ $proxy == false ]] && [[ $ttl != $old_ttl ]]; then
    (( record_changed++ ))
  fi
 
  if [[ record_changed -eq 0 ]]; then
    logger_output="$log_name IP ($ip) also "
    if [[ $proxy == true ]]; then
      logger_output+="proxy ($proxy)"
    else
      logger_output+="ttl ($ttl)"
    fi
    logger_output+=" have not changed."
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
    exit_code 0
  fi
}

cf_ddns_set_identifier () {
  ##########################################
  ## Set the record identifier from result
  ###########################################
  record_identifier=$(echo "$record" | sed -E 's/.*"id":"(\w+)".*/\1/')
  debug_output+="cf_ddns_set_identifier : $record_identifier\n"
}

cf_ddns_update () {
  ###########################################
  ## Change the IP@Cloudflare using the API
  ###########################################
  update=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records/$record_identifier" \
                      -H "X-Auth-Email: $auth_email" \
                      -H "$auth_header $auth_key" \
                      -H "Content-Type: application/json" \
                --data "{\"type\":\"A\",\"name\":\"$record_name\",\"content\":\"$ip\",\"ttl\":\"$ttl\",\"proxied\":${proxy}}")
  debug_output+="cf_ddns_update : $update\n"
}

cf_ddns_status_slack () {
  if [ -z $slackuri ]; then
    logger_output="$log_name -slackurl is undefined value"
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
    exit_code 1
  else
    set_message_slack
    update_slack=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -X POST $slackuri -H 'Content-type: application/json' --data "$output_messageBody")
    if [[ "$update_slack" != "ok" ]] || [ ${#update_slack} -eq 0 ]; then
      # FAILED
      logger_output="$log_name slack unable to send message"  
      debug_output+="$logger_output\n"
      WSL_Logger -s "$logger_output"
    fi
  fi
}

cf_ddns_status () {
  get_date_strings
  get_bootid
  # If it reports "false" or it NULL string from [cf_ddns_update] $update=$(curl) then it FAILED

  update_status=${update##*\"success\":false*}
  if [ ${#update_status} -eq 0 ]; then
    # FAILED
    logger_output="$log_name $ip $record_name DDNS failed for $record_identifier ($ip). DUMPING RESULTS:\n$update"
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
  else
    # Success
    logger_output="$log_name $ip $record_name DDNS updated."
    debug_output+="$logger_output\n"
    WSL_Logger "$logger_output"
  fi

  for ((cf_ddns_status_bitwise_lc=1, cf_ddns_status_bitwise_loop=1; cf_ddns_status_bitwise_loop <= $report_distribution; cf_ddns_status_bitwise_loop=((cf_ddns_status_bitwise_loop << 1)), cf_ddns_status_bitwise_lc++)); do
    case $(($cf_ddns_status_bitwise_loop & $report_distribution)) in
      1)
        #send message via slack
        cf_ddns_status_slack
        ;;
      2)
        #send message via email
        cf_ddns_status_email
        ;;
      4)
        #display via console
        cf_ddns_status_console
        ;;
      8)
        #write text file
        cf_ddns_status_planetext
        ;;
      16)
        #send message via telegrame
        cf_ddns_status_telegram
        ;;
      32)
        #send message via nextcloud
        cf_ddns_status_nextcloud
        ;;
      *)
        :
        ;;
    esac
  done

  if [ ${#update_status} -eq 0 ]; then
    #FAILED
    exit_code 1
  else
    #Success
    exit_code 0
  fi
}

cf_ddns_main () {
  if [ ${#ip} -eq 0 ] || [ $(( $ip_timestamp + $ip_maxage )) -lt "$EPOCHSECONDS" ]; then
  #Only worth getting current IP address with first domain or if max age has been passed
    cf_ddns_ip
  fi

  cf_ddns_authheader
  cf_ddns_seeka
  cf_ddns_checka
  if [ $cf_nonexistsrecord -eq 1 ]; then
    cf_ddns_recordchanged
    if [ $record_changed -gt 0 ]; then
      cf_ddns_set_identifier
      cf_ddns_update
      cf_ddns_status
    fi
  fi
}

debug_output_echo () {
  if [ -n "$debug_mode_active" ]; then
    if [ "$debug_mode_active" -eq 1 ]; then
      echo -e "$debug_output"
    fi
  fi
}

exit_code () {
  excode="$1"
  if [ -z "$top_exit_code" ]; then
    top_exit_code=-999
  fi
  if [ $top_exit_code -lt "$excode" ]; then
    top_exit_code=$excode
  fi

  if [ $tolerant_is_set -eq 1 ]; then
  # Only when tolerent mode is active, it will not stop for error
    logger_output="$log_name in tolerant mode - exit [$excode]"
    debug_output+="$logger_output\n"
    WSL_Logger "$logger_output"
  else
  # If strict mode it will stop instantly on error
    debug_output_echo
    exit "$excode"
  fi
}

cf_counting_sheep () {
  datestart=$(date +"%Y-%m-%d %H:%M:%S %Z")
  dateend=$(date --date="+$parameter_value seconds" +"%Y-%m-%d %H:%M:%S %Z")
  logger_output="$log_name counting sheep ($parameter_value) $datestart : $dateend"
  debug_output+="$logger_output\n"
  WSL_Logger -s "$logger_output"
  sleep "$parameter_value"
}

cf_help () {
# TODO ############################################################################################################################################
  echo "# crontab"
  echo "*/5 * * * * /bin/bash /home/user/cloudflare-ddns-updater/cloudflare-init.sh"
  echo '*/5 * * * * /bin/bash /home/user/cloudflare-ddns-updater/cloudflare-init.sh -tolerant mydomain.com example.com www.example.com x1.example.com'
  echo '*/5 * * * * /bin/bash /home/user/cloudflare-ddns-updater/cloudflare-init.sh -tolerant mydomain.com -sleep=10 example.com -proxy=false www.example.com -auth_ttl=10 x1.example.com'
  echo "Add in -tolerant option that get continue if when reason to exit, this should be first parameter"
  
  echo "-help , list commands"
  echo "-tolerant , - - - - - - TODO - - - - -"
  echo "-debug , will output to console a debug log"
  echo "-config_file=X , this is config that to used"
  echo "-sleep=X , this is sleep timer for that script"
  echo "-rsleep=X , this will set a random legth time sleep timer for the script"
  echo "-purge=X , To purge settings (operates using bitwise values)"
  echo "; 1 Cloudflare, 2 DNS, 4 Report, 8 Slack, 16 eMail, 32 File, 64 Telegram, 128 Nextcloud"

  echo "-auth_email=X , The e-mail that used to login to cloudflare \"https://dash.cloudflare.com\""
  echo "-auth_method=X , Set to \"global\" for Global API Key or \"token\" for Scoped API Token"
  echo "-auth_key=X , The Global API Key or Scope API Token"
  echo "-zone_identifier=X , Can be found in the \"Overview\" tab of your domain"
  echo "-auth_ttl=X DNS Record TTL (seconds)"
  echo "-auth_proxy=X , Set to \"ture\" to using cloudflare Proxing service or set to \"false\" do disclose you IP publicly"
  

  echo "-record_name=X , this record that wish update [testing123.example.com]"
  echo "-ip_recheck , this will purge ip that know to system so will check if there updated one"
  echo "-ip_set=X , this will set ip record to what you want to define \"1.1.1.1\""
  echo "-ip_maxage=X , the duration then needs to pass until IP is rechecked"

  echo "-report_distribution=X , services that being used sending messaging reports (operates using bitwise values)"
  echo "; 1 Slack, 2 eMail, 4 Console, 8 File, 16 Telegram, 32 Nextcloud"
  echo "-report_attribute=X , control what is contained in messaging reports (operates using bitwise values)"
  echo "; 1 Account, 2 Type, 4 IP Address, 8 Proxy, 16 TTL, 32 Time, 64 Identifier, 128 BootID, 256 Status"
  echo "-report_name=X , this is system identifier name being used, if it not be set it will hostname instead"

  echo "-email_username=X , SMTP login username"
  echo "-email_password=X , SMTP login password"
  echo "-email_smtp=X , ip/domain name of the SMTP server"
  echo "-email_port=X , port number used to connect to SMTP server"
  echo "-email_fromName=X , name that being used for that e-mail (from) [Joe Bloggs]"
  echo "-email_toName=X , name that being used for that e-mail (to) e-mail [Jane Doe]"
  echo "-email_fromAddress=X , email address that being used (from) [joe@example.com]"
  echo "-email_toAddress=X , email address that being used (to) [jane@example.org]"

  echo "-file_logPath=X , The location of where log file is saved"

  echo "-telegram_token=X , The API token that was issued with Telegram BotFather"
  echo "-telegram_chatID=X , This is user that sending message to on Telegram"

  echo "-nextcloud_domain=X , The location of server as domain name \"https://nextcloud.example.com\" or as ip \"https://192.168.1.60\""
  echo "-nextcloud_username=X , The username name for Nextcloud"
  echo "-nextcloud_apppass=X , The App-Password for Nextcloud"
  echo "-nextcloud_roomtoken=X , Nexcloud talk room token ID"

  exit
}

cf_tolerant () {
  tolerant_is_set=1
  logger_output="$log_name Been set as being tolerant"
  debug_output+="$logger_output\n"
  WSL_Logger "$logger_output"
}

cf_rsleep () {
  logger_output="$log_name rsleep range ($parameter_value) : "
  parameter_temp=$(( $parameter_value+1 ))
  parameter_value=$(( $RANDOM % $parameter_temp ))
  logger_output+="($parameter_value)"
  debug_output+="$logger_output\n"
  WSL_Logger "$logger_output"
  cf_counting_sheep
}

cf_auth_email () {
  logger_output="$log_name Changed [auth_email]"
  debug_output+="$logger_output ($parameter_value)\n"
  WSL_Logger "$logger_output"
  auth_email=$parameter_value
}

cf_auth_method () {
  logger_output="$log_name Changed [auth_method]"
  debug_output+="$logger_output ($parameter_value)\n"
  WSL_Logger "$logger_output"
  auth_method=$parameter_value
}

cf_auth_key () {
  logger_output="$log_name Change [auth_key]"
  debug_ouput+="$logger_output ($parameter_value)\n"
  WSL_Logger "$logger_output"
  auth_key=$parameter_value
}

cf_zone_identifier () {
  logger_output="$log_name Change [zone_identifier]"
  debug_ouput+="$logger_output ($parameter_value)\n"
  WSL_Logger "$logger_output"
  zone_identifier=$parameter_value
}

cf_ttl () {
  logger_output="$log_name Change [ttl]"
  debug_ouput+="$logger_output ($parameter_value)\n"
  WSL_Logger "$logger_output"
  ttl=$parameter_value
}

cf_proxy () {
  logger_output="$log_name Changed [proxy]"
  if [ $parameter_value = "true" ] || [ $parameter_value = "false" ]; then
    logger_output+=" ($parameter_value)"
    proxy=$parameter_value
    WSL_Logger "$logger_output"
  else
    logger_output+=" ($parameter_value) is invalied option"
    WSL_Logger -s "$logger_output"
  fi
  debug_output+="$logger_output\n"
}

cf_record_name () {
  record_name=$parameter_value
  cf_err_human
  if [ "$err_is_human" -eq 0 ]; then
    cf_ddns_main
  fi
  # TODO IPv4/IPv6 ##########################################################
}

cf_ip_set () {
  cf_ip_set_ipv4
# TODO IPv4/IPv6 ##########################################################
}

cf_ip_set_ipv4 () {
  if [[ "$parameter_value" =~ ^$regex_ipv4$ ]]; then
    ip=$parameter_value
    ip_timestamp=$(( "$EPOCHSECONDS" + 86400 ))
    logger_output="$log_name IPv4 been set to [$parameter_value]"
    WSL_Logger "$logger_output"
  else
    logger_output="$log_name IPv4 can not be set to [$parameter_value], as it not a vailed IPv4"
    WSL_Logger -s "$logger_output"
    ip="[SET INVALID IPv4 $parameter_value]"
  fi
  debug_ouput+="$logger_output\n"
}

cf_ip_recheck () {
  ip=""
  ip_timestamp=0
  logger_output="$log_name IP been set to do a recheck"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_ip_maxage () {
  ip_maxage=$parameter_value
  logger_output="$log_name IP max age limit set to $ip_maxage"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_entry_point () {
  logger_output="$log_name [entrypoint] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_remark_statment () {
  debug_output+="REMark: $parameter_value\n"
}

cf_slack () {
  slackuri=$parameter_value
  logger_output="$log_name [slackuri] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_username () {
  email_username=$parameter_value
  logger_output="$log_name [email_username] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_password () {
  email_password=$parameter_value
  logger_output="$log_name [email_password] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_smtp () {
  email_smtp=$parameter_value
  logger_output="$log_name [email_smtp] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_port () {
  email_port=$parameter_value
  logger_output="$log_name [email_port] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_fromName () {
  email_fromName=$parameter_value
  logger_output="$log_name [email_fromName] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_fromAddress () {
  email_fromAddress=$parameter_value
  logger_output="$log_name [email_fromAddress] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_toName () {
  email_toName=$parameter_value
  logger_output="$log_name [email_toName] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_toAddress () {
  email_toAddress=$parameter_value
  logger_output="$log_name [email_toAddress] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_report_attribute () {
  report_attribute=$parameter_value
  logger_output="$log_name [report_attribute] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_report_name() { 
  report_name=$parameter_value
  logger_output="$log_name [report_name] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
} 

cf_report_distribution() { 
  report_distribution=$parameter_value
  logger_output="$log_name [report_distribution] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
} 

cf_file_logPath() { 
  file_logPath=$parameter_value
  logger_output="$log_name [file_logPath] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
} 

cf_telegram_token() { 
  telegram_token=$parameter_value
  logger_output="$log_name [telegram_token] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
} 

cf_telegram_chatID() { 
  telegram_chatID=$parameter_value
  logger_output="$log_name [telegram_chatID] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
} 

cf_nextcloud_domain() { 
  nextcloud_domain=$parameter_value
  logger_output="$log_name [nextcloud_domain] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
} 

cf_nextcloud_username() { 
  nextcloud_username=$parameter_value
  logger_output="$log_name [nextcloud_username] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
} 

cf_nextcloud_apppass() { 
  nextcloud_apppass=$parameter_value
  logger_output="$log_name [nextcloud_apppass] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
} 

cf_nextcloud_roomtoken() { 
  nextcloud_roomtoken=$parameter_value
  logger_output="$log_name [nextcloud_roomtoken] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
} 

cf_user_agent_name() {
  user_agent_name=$parameter_value
  set_user_agent
  logger_output="$log_name [user_agent_name] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_purge() {
  purge_set=$parameter_value
  logger_output="$log_name [purge] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
  purge_main
}

cf_purge_all() {
  parameter_value=255
  logger_output="$log_name [purge_all] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
  cf_purge
}

cf_parameter_commands () {
  parameter_temp="${1:1}"
  string_character=${parameter_temp:${#parameter_temp}-1:1}
  parameter_command=$(echo "${parameter_temp%=*}" | tr '[:upper:]' '[:lower:]') # This is done so all commands are lower case
  parameter_value=${parameter_temp##*=}

  case $parameter_command in
    "debug")
      #debug_mode_active=1
      :
      ;;
    "help")
      cf_help
      ;;
    "tolerant")
      #cf_tolerant
      :
      ;;
    "sleep")
      cf_counting_sheep
      ;;
    "rsleep")
      cf_rsleep
      ;;
    "auth_email")
      cf_auth_email
      ;;
    "auth_method")
      cf_auth_method
      ;;
    "auth_key")
      cf_auth_key
      ;;
    "zone_identifier")
      cf_zone_identifier
      ;;
    "ttl")
      cf_ttl
      ;;
    "proxy")
      cf_proxy
      ;;
    "record_name")
      cf_record_name
      ;;
    "ip_set")
      cf_ip_set
      ;;
    "ip_recheck")
      cf_ip_recheck
      ;;
    "ip_maxage")
      cf_ip_maxage
      ;;
    "entrypoint")
      cf_entry_point
      ;;
    "purge")
      cf_purge
      ;;
    "purge_all")
      cf_purge_all
      ;;
    "#")
      cf_remark_statment
      ;;
    "slackuri")
      cf_slack
      ;;
    "email_username")
      cf_email_username
      ;;
    "email_password")
      cf_email_password
      ;; 
    "email_smtp")
      cf_email_smtp
      ;; 
    "email_port")
      cf_email_port
      ;; 
    "email_fromname")
      cf_email_fromName
      ;; 
    "email_fromaddress")
      cf_email_fromAddress
      ;; 
    "email_toname")
      cf_email_toName
      ;; 
    "email_toaddress")
      cf_email_toAddress
      ;;   
    "report_attribute")
      cf_report_attribute
      ;;
    "report_name")
      cf_report_name
      ;;
    "report_distribution")
      cf_report_distribution
      ;;
    "file_logpath")
      cf_file_logPath
      ;;
    "telegram_token")
      cf_telegram_token
      ;;
    "telegram_chatid")
      cf_telegram_chatID
      ;;
    "nextcloud_domain")
      cf_nextcloud_domain
      ;;
    "nextcloud_username")
      cf_nextcloud_username
      ;;
    "nextcloud_apppass")
      cf_nextcloud_apppass
      ;;
    "nextcloud_roomtoken")
      cf_nextcloud_roomtoken
      ;;
    "user_agent_name")
      cf_user_agent_name
      ;;
    
    "config_file")
      :
      ;;
    *)
      logger_output="$log_name invalid parameter option been defined [${parameter_temp}]"
      debug_output+="$logger_output\n"
      WSL_Logger -s "$logger_output"
      ;;
  esac
}

cf_err_human () {
  err_is_human=0

  if [ ${#auth_email} -eq 0 ]; then
    err_is_human=1
    logger_output="$log_name ERROR [auth_email] record not been defined"
    WSL_Logger -s "$logger_output"
  fi

  if [ ${#auth_method} -eq 0 ]; then
    err_is_human=1
    logger_output='$log_name ERROR [auth_method] setting has not been defined'
    WSL_Logger -s "$logger_output"
  else
    if [ $auth_method != "token" ] && [ $auth_method != "global" ]; then
      err_is_human=1
      logger_output='$log_name ERROR [auth_method] is invaled it has to be defined "token" "global" defined'
      WSL_Logger -s "$logger_output"
    fi
  fi

  if [ ${#auth_key} -eq 0 ]; then
    err_is_human=1
    logger_output="$log_name ERROR [auth_key] record not been defined"
    WSL_Logger -s "$logger_output"
  fi

  if [ ${#zone_identifier} -eq 0 ]; then
    err_is_human=1
    logger_output="$log_name ERROR [zone_identifier] record has not been defined"
    WSL_Logger -s "$logger_output"
  fi

  if [ ${#record_name} -eq 0 ]; then
    err_is_human=1
    logger_output="$log_name ERROR [record_name] record has not been defined"
    WSL_Logger -s "$logger_output"
  fi

   if [ ${#ttl} -eq 0 ]; then
    err_is_human=1
    logger_output="$log_name ERROR [ttl] record has not been defined"
    WSL_Logger -s "$logger_output"
  fi

  if [ ${#proxy} -eq 0 ]; then
    err_is_human=1
    logger_output='$log_name ERROR [proxy] setting has not been defined'
    WSL_Logger -s "$logger_output"
  else
    if [ $proxy != "true" ] && [ $proxy != "false" ]; then
      err_is_human=1
      logger_output='$log_name ERROR [proxy] is invaled it has to be defined "true" "false" defined'
      WSL_Logger -s "$logger_output"
    fi
  fi

  if [ ${#record_name} -eq 0 ]; then
    err_is_human=1
    logger_output="$log_name ERROR [record_name] record not has been defined"
    WSL_Logger -s "$logger_output"
  fi

  if [ -z "$tolerant_is_set" ]; then
    # if tolerant_is_set has not been set up it will be strict
    tolerant_is_set=0
  fi

  if [ $tolerant_is_set -lt 0 ] || [ $tolerant_is_set -gt 1 ]; then
    err_is_human=1
    logger_output="$log_name ERROR [tolerant_is_set] can only by 0 or 1"
    WSL_Logger -s "$logger_output"
  fi

  if [ $err_is_human -eq 1 ]; then
    #It is done if there is error detected above
    exit_code 1
  fi
}



cf_setting_internal () {
  debug_output_local="cf_setting_internal:"
  cf_setting_internal_array=('-entrypoint=_settinginternal')
  
  ####################################################################
  # TODO There is lot better way of doing this, but that
  #      will have to wait until some other things working
  ####################################################################

  if [[ -z $auth_email ]]; then
    debug_output+="$debug_output_local undefined [auth_email]\n"
  else
    cf_setting_internal_array+=("-auth_email=$auth_email")
  fi
  if [[ -z $auth_method ]]; then
    debug_output+="$debug_output_local undefined [auth_method]\n"
  else
    cf_setting_internal_array+=("-auth_method=$auth_method")
  fi
  if [[ -z $auth_key ]]; then
    debug_output+="$debug_output_local undefined [auth_key]\n"
  else
    cf_setting_internal_array+=("-auth_key=${auth_key}")
  fi
  if [[ -z $zone_identifier ]]; then
    debug_output+="$debug_output_local undefined [zone_identifier]\n"
  else
    cf_setting_internal_array+=("-zone_identifier=${zone_identifier}")
  fi
  if [[ -z $ttl ]]; then
    debug_output+="$debug_output_local undefined [ttl]\n"
  else
    cf_setting_internal_array+=("-ttl=${ttl}")
  fi
  if [[ -z $proxy ]]; then
    debug_output+="$debug_output_local undefined [proxy]\n"
  else
    cf_setting_internal_array+=("-proxy=${proxy}")
  fi
  if [[ -z $slacksitename ]]; then
    debug_output+="$debug_output_local undefined [slacksitename]\n"
  else
    cf_setting_internal_array+=("-slacksitename=${slacksitename}")
  fi
  if [[ -z $slackchannel ]]; then
    debug_output+="$debug_output_local undefined [slackchannel]\n"
  else
    cf_setting_internal_array+=("-slackchannel=${slackchannel}")
  fi
  if [[ -z $slackuri ]]; then
    debug_output+="$debug_output_local undefined [slackuri]\n"
  else
    cf_setting_internal_array+=("-slackuri=${slackuri}")
  fi
  if [[ -z $config_file ]]; then
    debug_output+="$debug_output_local undefined [config_file]\n"
  else
    cf_setting_internal_array+=("-config_file=${config_file}")
  fi

  if [[ -z $ip_maxage ]]; then
    debug_output+="$debug_output_local undefined [ip_maxage]\n"
  else
    cf_setting_internal_array+=("-ip_maxage=${ip_maxage}")
  fi

  if [[ -z $email_username ]]; then
    debug_output+="$debug_output_local undefined [email_username]\n"
  else
    cf_setting_internal_array+=("-email_username=${email_username}")
  fi
  if [[ -z $email_password ]]; then
    debug_output+="$debug_output_local undefined [email_password]\n"
  else
    cf_setting_internal_array+=("-email_password=${email_password}")
  fi
  if [[ -z $email_smtp ]]; then
    debug_output+="$debug_output_local undefined [email_smtp]\n"
  else
    cf_setting_internal_array+=("-email_smtp=${email_smtp}")
  fi
  if [[ -z $email_port ]]; then
    debug_output+="$debug_output_local undefined [email_port]\n"
  else
    cf_setting_internal_array+=("-email_port=${email_port}")
  fi
  if [[ -z $email_fromName ]]; then
    debug_output+="$debug_output_local undefined [email_fromName]\n"
  else
    cf_setting_internal_array+=("-email_fromName=${email_fromName}")
  fi
  if [[ -z $email_fromAddress ]]; then
    debug_output+="$debug_output_local undefined [email_fromAddress]\n"
  else
    cf_setting_internal_array+=("-email_fromAddress=${email_fromAddress}")
  fi
  if [[ -z $email_toName ]]; then
    debug_output+="$debug_output_local undefined [email_toName]\n"
  else
    cf_setting_internal_array+=("-email_toName=${email_toName}")
  fi
  if [[ -z $email_toAddress ]]; then
    debug_output+="$debug_output_local undefined [email_toAddress]\n"
  else
    cf_setting_internal_array+=("-email_toAddress=${email_toAddress}")
  fi

  if [[ -z $report_attribute ]]; then
    debug_output+="$debug_output_local undefined [report_attribute]\n"
  else
    cf_setting_internal_array+=("-report_attribute=${report_attribute}")
  fi  
  if [[ -z $report_name ]]; then
    debug_output+="$debug_output_local undefined [report_name]\n"
  else
    cf_setting_internal_array+=("-report_name=${report_name}")
  fi 
  if [[ -z $report_distribution ]]; then
    debug_output+="$debug_output_local undefined [report_distribution]\n"
  else
    cf_setting_internal_array+=("-report_distribution=${report_distribution}")
  fi 
  if [[ -z $file_logPath ]]; then
    debug_output+="$debug_output_local undefined [file_logPath]\n"
  else
    cf_setting_internal_array+=("-file_logPath=${file_logPath}")
  fi 
  if [[ -z $telegram_token ]]; then
    debug_output+="$debug_output_local undefined [telegram_token]\n"
  else
    cf_setting_internal_array+=("-telegram_token=${telegram_token}")
  fi
  if [[ -z $telegram_chatID ]]; then
    debug_output+="$debug_output_local undefined [telegram_chatID]\n"
  else
    cf_setting_internal_array+=("-telegram_chatID=${telegram_chatID}")
  fi
  if [[ -z $nextcloud_domain ]]; then
    debug_output+="$debug_output_local undefined [nextcloud_domain]\n"
  else
    cf_setting_internal_array+=("-nextcloud_domain=${nextcloud_domain}")
  fi
  if [[ -z $nextcloud_username ]]; then
    debug_output+="$debug_output_local undefined [nextcloud_username]\n"
  else
    cf_setting_internal_array+=("-nextcloud_username=${nextcloud_username}")
  fi
  if [[ -z $nextcloud_apppass ]]; then
    debug_output+="$debug_output_local undefined [nextcloud_apppass]\n"
  else
    cf_setting_internal_array+=("-nextcloud_apppass=${nextcloud_apppass}")
  fi
  if [[ -z $nextcloud_roomtoken ]]; then
    debug_output+="$debug_output_local undefined [nextcloud_roomtoken]\n"
  else
    cf_setting_internal_array+=("-nextcloud_roomtoken=${nextcloud_roomtoken}")
  fi
  if [[ -z $user_agent_name ]]; then
    debug_output+="$debug_output_local undefined [user_agent_name]\n"
  else
    cf_setting_internal_array+=("-user_agent_name=${user_agent_name}")
  fi


  ## This has to called last as it do process of conatcting CF and the seting have to be already set
  if [[ -z $record_name ]]; then
    debug_output+="$debug_output_local undefined [record_name]\n"
  else
    cf_setting_internal_array+=("-record_name=${record_name}")
  fi

  for (( item=0; item < ${#cf_setting_internal_array[@]}; item++ )); do
    debug_output+="$debug_output_local declared ${cf_setting_internal_array[item]}\n"
  done
}

cf_setting_parameter () {
  debug_output_local="cf_setting_parameter:"
  argument_total=${#parameter_input[@]}

  if [ "$argument_total" -gt 0 ] ; then
    cf_setting_parameter_array=('-entrypoint=_settingparameter')
    for (( argument_depth=0 ; argument_depth < argument_total ; argument_depth++ )); do
      parameter_current=${parameter_input[argument_depth]}
      first_character=${parameter_current:0:1}
      # $'\055') # Hyphen -
      if [[ $first_character = $'\055' ]]; then
        retain_setting_to_check="$parameter_current"
        retain_setting
        activate_instantly_settings
        cf_setting_parameter_array+=("${retain_setting_output}")
      else
        cf_setting_parameter_array+=('-record_name='"${parameter_current}")
      fi
    done
  fi

  for (( item=0; item < ${#cf_setting_parameter_array[@]}; item++ )); do
    debug_output+="$debug_output_local declared ${cf_setting_parameter_array[item]}\n"
  done

}

cf_setting_file () {
#i: config_file
#i: line_to_check
#i: string_exit
#i: string_filename
#io: string_exit
#io: string_y_pos
#io: string_x_pos
#o: string_character

  setting_file_gt_len=2
  string_y_pos=0
  debug_output_local="cf_setting_file:"
  if [ -f $config_file ] && [ $config_file ]; then
    cf_setting_file_array=('-entrypoint=_settingfile')
    while IFS= read -r string_text
    do
      ((string_y_pos++))
      string_reset_whitespace
      # It will process only the line set as in $line_to_check
      # It will process everyline if $line_to_check == 0 or null
      if [[ $line_to_check == "$string_y_pos" ]] || [[ $line_to_check == 0 ]] || [[ -z $line_to_check ]]; then
        until (( $string_exit )); do
          string_character=${string_text:string_x_pos:1}
          string_check_whitspace
          ((string_x_pos++))
          string_length_check
        done
        if [[ $string_removed_whitespace ]]; then
          first_character=${string_removed_whitespace:0:1}
          # $'\055') # Hyphen -
          if [[ $first_character = $'\055' ]]; then
            retain_setting_to_check="$string_removed_whitespace"
            retain_setting
            activate_instantly_settings
          else
            if [[ ${#string_removed_whitespace} -gt $setting_file_gt_len ]]; then
              retain_setting_output=("-record_name=${string_removed_whitespace}")
            fi

          fi
          if [[ ${#string_removed_whitespace} -gt $setting_file_gt_len ]]; then
            cf_setting_file_array+=("${retain_setting_output}")
          fi
        fi
     fi
    done < "$config_file"
  else
    if [[ $config_file ]]; then
      logger_output="$log_name ${debug_output_local}file not found [${config_file}]"
      debug_output+="$logger_output\n"
      WSL_Logger -s "$logger_output"
    fi
  fi

  for (( item=0; item < ${#cf_setting_file_array[@]}; item++ )); do
    debug_output+="$debug_output_local declared ${cf_setting_file_array[item]}\n"
  done
}

string_reset_whitespace () {
#i: string_text
#o: string_exit
#o: string_x_pos
#o: within_quatation_mark
#o: string_remove_whitspace
#o: string_length

  string_exit=0
  string_x_pos=0
  string_where_equal_sign=0
  within_quatation_mark=0
  string_removed_whitespace=""
  string_length=${#string_text}
}

string_check_whitspace () {
#i: string_character
#i: string_x_pos
#i: string_y_pos
#io: string_removed_whitespace
#io: within_quatation_mark
#io: string_where_equal_sign
  # \011 = Tab (Tab vertical) || \040 = Space
  if [[ $string_character == $'\011' ]] || [[ $string_character == $'\040' ]]; then
    if (( $within_quatation_mark )); then
      string_removed_whitespace+=$string_character
    fi
  else
    if [[ $string_character != $'\015' ]]; then
      # If not (\015 0x0D \r) CR Carriage Return - Microsoft Windows
      # $'\055') # https://en.wikipedia.org/wiki/Carriage_return
      string_non_whitespace
    fi
  fi
}

string_length_check () {
#i: string_length
#i: string_x_pos
#o: string_exit
  if [ "$string_length" -eq $string_x_pos ]; then
    string_exit=1
  fi
  # $string_length = 0 is for line that have nothing
  if [ "$string_length" -eq 0 ]; then
    string_exit=1
  fi
}

string_non_whitespace (){
  # \042 Quatation mark
  if [[ $string_character == $'\042' ]]; then
    within_quatation_mark=$(( ! $within_quatation_mark ))
  else
    #doing after else will remove remove Quatation Mark, otherwise if want it remove else place after fi
    string_removed_whitespace+=$string_character
  fi

  # \075 Equal Sign
  # it only valied if not already been set and quatation mark is false
  if [[ $string_character == $'\075' ]] && (( ! $within_quatation_mark )); then
    if [[ $string_where_equal_sign == 0 ]]; then
      string_where_equal_sign=${#string_removed_whitespace}
    fi
  fi
}

retain_setting () {
  # The first time it declared it vaild, anthing else is not vaild.
  retain_setting_output=$retain_setting_to_check
  if [ "${retain_setting_to_check:0:13}" == "-config_file=" ]; then
    if [ $config_file ]; then
      logger_output="$log_name ${debug_output_local} [-config_file] already defened as [${config_file}] not changed to [${retain_setting_to_check:13}]"
      debug_output+="$logger_output\n"
      WSL_Logger -s "$logger_output"
      # This is done so file name is rem out
      retain_setting_output="-#=$retain_setting_to_check"
    else
      config_file=${retain_setting_to_check:13}
      retain_setting_output="-#=config_file [$config_file]"
    fi
  fi
}

activate_instantly_settings () {
  if [ "${retain_setting_to_check:0:6}" == "-debug" ]; then
    debug_mode_active=1
  fi

  if [ "${retain_setting_to_check:0:9}" == "-tolerant" ]; then
    cf_tolerant
  fi
}

cf_exec () {
  for (( item=0; item < ${#cf_setting_internal_array[@]}; item++ )); do
    cf_parameter_commands "${cf_setting_internal_array[item]}"
  done

  for (( item=0; item < ${#cf_setting_parameter_array[@]}; item++ )); do
    cf_parameter_commands "${cf_setting_parameter_array[item]}"
  done

  for (( item=0; item < ${#cf_setting_file_array[@]}; item++ )); do
    cf_parameter_commands "${cf_setting_file_array[item]}"
  done
}

check_install_command () {
  ## This is use to make shore for commands are install that are not part of POSIX
  check_installCommand=$1
  if [[ -z $check_installCommand ]]; then
    WSL_Logger -s "$0 [[check_install_command]]: NullReferenceException; nothing defined [$check_install_command]"
    exit 1
  fi
  if ! command -v "$check_installCommand" &> /dev/null; then
    check_installCommandMessage="$check_installCommand"$' is required for this to run.\n'
    check_installCommandMessage+='(Debian)# apt install '"$check_installCommand"$'\n'
    check_installCommandMessage+='(RHEL)# yum install '"$check_installCommand"$'\n'
    check_installCommandMessage+='(OpenSUSE)# zypper install '"$check_installCommand"$'\n'
    check_installCommandMessage+='(ArchLinux)# pacman -Sy '"$check_installCommand"$'\n'
    echo "$check_installCommandMessage"
    exit 1
  fi
}

get_date_strings () {
  # date_utc_nonhuman=$(date -u +%Y%m%d%H%M%S)
  date_utc=$(date -u +"%Y-%m-%d %H:%M:%S %Z")
  date_utc_subject=$(date -u +%Y%m%d%-H%M)
  # date_local=$(date +"%c %z")
  date_logger=$(date +"%b %d %H:%M:%S")
}

set_subject_email () {
  email_subjectLine="CF-DDNS [$record_name] $date_utc_subject "
}

set_message_slack () {
  style_slack
  output_bodyString
}

set_message_email () {
  style_emailText
  set_subject_email
  output_bodyString
}

set_message_console () {
  style_console
  output_bodyString
}

set_message_planetext () {
  style_planetext
  output_bodyString
}

set_message_telegram () {
  style_telegram_markdownV2
  output_bodyString
#  echo "DEBUG : set_message_telegram [$output_messageBody]"
}

set_message_nextcloud () {
  style_nextcloud
  output_bodyString
}

cf_ddns_status_email () {
  if [[ $email_username != "" ]]; then
    if [[ $email_fromAddress == "" ]]; then
      logger_output="$log_name : There is no from e-mail address been defiened [email_fromAddress]"
      debug_output+="$logger_output\n"
      WSL_Logger -s "$logger_output"
    fi

    if [[ $email_toAddress == "" ]]; then
      email_toAddress=$email_fromAddress
    fi

    set_message_email

    curl -s --user-agent "$agent_name" --max-time $curl_max_time -url smtps://$email_smtp:$email_port --ssl-reqd \
      --mail-from $email_fromAddress \
      --mail-rcpt $email_toAddress \
      --user $email_username:$email_password \
      -H "Subject: $email_subjectLine" \
      -H "From: $email_fromName <$email_fromAddress>" \
      -H "To: $email_toName <$email_toAddress>" \
      -F '=(;type=multipart/mixed' \
      -F "=$output_messageBody;" \
      -F '=)'

    curl_errorcode=${?}
    if [ $curl_errorcode -ne 0 ]; then
      case $curl_errorcode in
        3)
          curl_errorhuman="smtp server has not been defined"
          ;;
        6)
          curl_errorhuman="This is not a vaild host name"
          ;;
        7)
          curl_errorhuman="This service is unrespotive"
          ;;
        28)
          curl_errorhuman="Did not connect within timeout"
          ;;
        67)
          curl_errorhuman="The username/password is invailed"
          ;;
        *)
          curl_errorhuman="No idea what has gone wrong but it has, PANIC!"
          ;;
      esac
      logger_output="$log_name e-mail $curl_errorcode :- $curl_errorhuman"
      debug_output+="$logger_output\n"
      WSL_Logger -s "$logger_output"
      exit_code 1
    fi
  fi
}

cf_ddns_status_console () {
  ###########################################
  ## Report to the console
  ###########################################
  set_message_console
  echo -e "$output_messageBody"
}

cf_ddns_status_planetext () {
  if [ -z $file_logPath ]; then
    logger_output="$log_name -file_logPath is undefined value"
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
    exit_code 1
  else
    set_message_planetext
    echo -e "$output_messageBody" >>"$file_logPath"
  fi
}

cf_ddns_status_telegram () {
  if [ -z $telegram_token ] || [ -z $telegram_chatID ]; then
    logger_output="$log_name telegram telegram_token or telegram_chatID is undefined value"  
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
    exit_code 1
  else
    set_message_telegram
    update_telegram=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -X POST "https://api.telegram.org/bot""$telegram_token""/sendMessage" -d chat_id="$telegram_chatID" -d parse_mode="MarkdownV2" -d text="$output_messageBody")
    if [[ "$update_telegram" = *"\"ok\":false"* ]] || [ ${#update_telegram} -eq 0 ]; then
      # FAILED
      logger_output="$log_name telegram unable to send message"  
      debug_output+="$logger_output\n"
      WSL_Logger -s "$logger_output"
    fi
  fi 
}

cf_ddns_status_nextcloud () {
  if [ -z $nextcloud_domain ] || [ -z $nextcloud_username ] || [ -z $nextcloud_apppass ] || [ -z $nextcloud_roomtoken ]; then
    logger_output="$log_name "
    if [ -z nextcloud_domain ]; then
      logger_output+="-nextcloud_domain "
    fi
    if [ -z nextcloud_username ]; then
      logger_output+="-nextcloud_username "
    fi
    if [ -z nextcloud_apppass ]; then
      logger_output+="-nextcloud_apppass "
    fi
    if [ -z nextcloud_roomtoken ]; then
      logger_output+="-nextcloud_roomtoken "
    fi
    logger_output+="is undefined value"
    
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
    exit_code 1
  else
    set_message_nextcloud
    nextcloud_jsondata="{\"token\":\"$nextcloud_roomtoken\", \"message\":\"$output_messageBody\"}"
    update_nextcloud=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -d "$nextcloud_jsondata" -H "Content-Type: application/json" -H "Accept:application/json" -H "OCS-APIRequest:true" -u "$nextcloud_username:$nextcloud_apppass" "$nextcloud_domain""/ocs/v2.php/apps/spreed/api/v1/chat/$nextcloud_roomtoken")
    if [[ "$update_nextcloud" != *"\"status\":\"ok\""* ]] || [ ${#update_nextcloud} -eq 0 ]; then
      # FAILED
      logger_output="$log_name nextcloud unable to send message"  
      debug_output+="$logger_output\n"
      WSL_Logger -s "$logger_output"
    fi
    unset nextcloud_jsondata
  fi
}

style_slack () {
  rts_header='{"text":"'
  rte_header='"}'
  rts_bold="*"
  rte_bold="*"
  rts_italicize="_"
  rte_italicize="_"
  rts_strickethrough="~"
  rte_strickethrough="~"
  rts_line=""
  rte_line=$'\n'
  unset characters_prepend
  # NEED TO REVIEW :- characters_prepend not need for Slack
}

style_emailText () {
  rts_header=''
  rte_header=''
  rts_bold=""
  rte_bold=""
  rts_italicize=""
  rte_italicize=""
  rts_strickethrough=""
  rte_strickethrough=""
  rts_line=""
  rte_line=$'\n'
  unset characters_prepend
  # TODO email has issue with ;
}

style_console () {
  rts_header=$'---\n'
  rte_header=''
  rts_bold=""
  rte_bold=""
  rts_italicize=""
  rte_italicize=""
  rts_strickethrough=""
  rte_strickethrough=""
  rts_line=""
  rte_line=$'\n'
  unset characters_prepend
}

style_planetext () {
  rts_header=$'---\n'
  rte_header=''
  rts_bold=""
  rte_bold=""
  rts_italicize=""
  rte_italicize=""
  rts_strickethrough=""
  rte_strickethrough=""
  rts_line=""
  rte_line=$'\n'
  unset characters_prepend
}

style_telegram_markdownV2 () {
  rts_header=""
  rte_header=""
  rts_bold="*"
  rte_bold="*"
  rts_italicize="_"
  rte_italicize="_"
  rts_strickethrough="~"
  rte_strickethrough="~"
  rts_line=""
  rte_line="%0A"
  unset characters_prepend
  characters_prepend=('\' '\' '*' '_' '~' '`' '[' ']' '(' ')' '{' '}' '<' '>' '.' '-' '!' '=' '|' '#' '"' "=")
  # TODO telegram has issue with £ ¬ & + =
}

style_nextcloud () {
  rts_header=$''
  rte_header=''
  rts_bold=""
  rte_bold=""
  rts_italicize=""
  rte_italicize=""
  rts_strickethrough=""
  rte_strickethrough=""
  rts_line=""
  rte_line="\n"
  unset characters_prepend
}

output_bodyString () {
  local output_bodyString_temp
  # : ( )
  local output_bodyString_dbl=$(Characters_prepend ": ")
  local output_bodyString_pato=$(Characters_prepend " (")
  local output_bodyString_patc=$(Characters_prepend ")")
  output_messageBody="$rts_header"
  for ((output_bodyString_bitwise_lc=1, output_bodyString_bitwise_loop=1; output_bodyString_bitwise_loop <= $report_attribute; output_bodyString_bitwise_loop=((output_bodyString_bitwise_loop << 1)), output_bodyString_bitwise_lc++)); do

    case $(($output_bodyString_bitwise_loop & $report_attribute)) in
      1)
        output_bodyString_temp=$(Characters_prepend "Account")
        output_messageBody+="$rts_line""$rts_italicize""$output_bodyString_temp""$rte_italicize""$output_bodyString_dbl"
        output_bodyString_temp=$(Characters_prepend "$auth_email")
        output_messageBody+="$output_bodyString_temp""$rte_line"
        ;;
      2)
        output_bodyString_temp=$(Characters_prepend "Type A")
        output_messageBody+="$rts_line""$rts_italicize""$output_bodyString_temp""$rte_italicize""$output_bodyString_dbl"
        output_bodyString_temp=$(Characters_prepend "$record_name")
        output_messageBody+="$output_bodyString_temp""$rte_line"
        # email_messageBody+=$'Type AAAA: '$domain_name$'\n' # TODO IPv6 ###################################
        ;;
      4)
        output_bodyString_temp=$(Characters_prepend "IP address")
        output_messageBody+="$rts_line""$rts_italicize""$output_bodyString_temp""$rte_italicize""$output_bodyString_dbl"
        output_bodyString_temp=$(Characters_prepend "$ip")
        output_messageBody+="$output_bodyString_temp"
        output_bodyString_temp=$(Characters_prepend "$old_ip")
        output_messageBody+="$output_bodyString_pato""$rts_strickethrough""$output_bodyString_temp""$rte_strickethrough""$output_bodyString_patc""$rte_line"
        ;;
      8)
        output_bodyString_temp=$(Characters_prepend "Proxy")
        output_messageBody+="$rts_line""$rts_italicize""$output_bodyString_temp""$rte_italicize""$output_bodyString_dbl"
        output_bodyString_temp=$(Characters_prepend "$proxy")
        output_messageBody+="$output_bodyString_temp"
        output_bodyString_temp=$(Characters_prepend "$old_proxy")
        output_messageBody+="$output_bodyString_pato""$rts_strickethrough""$output_bodyString_temp""$rte_strickethrough""$output_bodyString_patc""$rte_line"
        ;;
      16)
        output_bodyString_temp=$(Characters_prepend "TTL")
        output_messageBody+="$rts_line""$rts_italicize""$output_bodyString_temp""$rte_italicize""$output_bodyString_dbl"
        if [[ $proxy == true ]]; then
          output_bodyString_temp=$(Characters_prepend "PROXIED")
          output_messageBody+="$output_bodyString_temp"
        else
          output_bodyString_temp=$(Characters_prepend "$ttl")
          output_messageBody+="$output_bodyString_temp"
        fi
        output_messageBody+="$output_bodyString_pato""$rts_strickethrough"
        if [[ $old_proxy == true ]]; then
          output_bodyString_temp=$(Characters_prepend "PROXIED")
          output_messageBody+="$output_bodyString_temp"
        else
          output_bodyString_temp=$(Characters_prepend "$ttl")
          output_messageBody+="$output_bodyString_temp"
        fi
        output_messageBody+="$rte_strickethrough""$output_bodyString_patc""$rte_line"
        ;;
      32)
        output_bodyString_temp=$(Characters_prepend "Time")
        output_messageBody+="$rts_line""$rts_italicize""$output_bodyString_temp""$rte_italicize""$output_bodyString_dbl"
        output_bodyString_temp=$(Characters_prepend "$date_utc")
        output_messageBody+="$output_bodyString_temp""$rte_line"
        ;;
      64)
        output_bodyString_temp=$(Characters_prepend "Identifier")
        output_messageBody+="$rts_line""$rts_italicize""$output_bodyString_temp""$rte_italicize""$output_bodyString_dbl"
        if [ -z $report_name ]; then
          output_bodyString_temp=$(Characters_prepend "$HOSTNAME")
          output_messageBody+="$output_bodyString_temp"
        else
          output_bodyString_temp=$(Characters_prepend "$report_name")
          output_messageBody+="$output_bodyString_temp"
        fi
        output_messageBody+="$rte_line"
        ;;
      128)
        output_bodyString_temp=$(Characters_prepend "BootID")
        output_messageBody+="$rts_line""$rts_italicize""$output_bodyString_temp""$rte_italicize""$output_bodyString_dbl"
        output_bodyString_temp=$(Characters_prepend "$boot_id")
        output_messageBody+="$output_bodyString_temp""$rte_line"
        ;;
      256)
        output_bodyString_temp=$(Characters_prepend "Status")
        output_messageBody+="$rts_line""$rts_italicize""$output_bodyString_temp""$rte_italicize""$output_bodyString_dbl"
        if [ ${#update_status} -eq 0 ]; then
          output_bodyString_temp=$(Characters_prepend "FAILED")
          output_messageBody+="$rts_bold""$output_bodyString_temp""$rte_bold"
        else
          output_bodyString_temp=$(Characters_prepend "Success")
          output_messageBody+="$output_bodyString_temp"
        fi 
        output_messageBody+="$rte_line"
        ;;
      *)
        :
        ;;
    esac

  done


  output_messageBody+="$rte_header"
}

Characters_prepend () {
  # characters_prepend[0]= is the prepend string
  # characters_prepend[X]= is character that needs to be prepend 
  # $characters_prepend[0]$characters_prepend[1...]
  # characters_prepend_stream ($1) is sting that beening processed and returned
  local characters_prepend_stream="$1"
  local characters_prepend_loop
  
  if [ ${#characters_prepend[@]} -gt 0 ]; then
    for (( characters_prepend_loop=1; characters_prepend_loop<${#characters_prepend[@]} ; characters_prepend_loop++ ));
    do
      characters_prepend_stream=${characters_prepend_stream//"${characters_prepend[$characters_prepend_loop]}"/${characters_prepend[0]}${characters_prepend[$characters_prepend_loop]}}
    done
  fi

  echo "$characters_prepend_stream"
}

Check_isRoot () {
  if [ $(id -u) -eq 0 ] || [ $EUID -eq 0 ]; then
    WSL_Logger -s "It is not advisable to run this from a superuser accout."
    echo -ne "\007" # Make computer BEEP sound
  fi
}

checkFor_WSL () {
  # we need this because (microsoft/windows) WSL dosn't have /var/log/syslog and this will give problems with "# Logger" command
  CheckFor_WSL="/proc/sys/fs/binfmt_misc/WSLInterop"
  if [ -f "$CheckFor_WSL" ]; then
    CheckFor_WSL="/proc/version"
    case "$(cat $CheckFor_WSL)" in
      *"-Microsoft ("*)
        CheckFor_WSL="1" # This is value for WSL1
        ;;
      *"-microsoft-standard-WSL2 ("*)
        CheckFor_WSL="2" # This is value for WSL2
        ;;
      *)
        CheckFor_WSL="0" # This is value if WSL version in unknown
        ;;
    esac
    logger_output="$log_name When using WSL, it is not writing the [logger] to [/var/log/syslog] or [/var/log/messages] etc..."  
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
  else
    CheckFor_WSL="" # This value NULL if WSLInterop dosnt exists
  fi
}

WSL_Logger () {
  # we need this because (microsoft/windows) WSL dosn't have /var/log/syslog and this will give problems with "# Logger" command
  # Need to set WSL_Output_boolean=0 otherwise end up get "unary operator expected"
  WSL_Output_boolean=0
  for WSL_loop in "$@"
  do
    if [ "$WSL_loop" = "-s" ]; then
        #"-s" Log the message to standard error 
      get_date_strings
      WSL_Output_boolean=1
    else
      if [ ! -z "$WSL_Output" ]; then
      WSL_Output+=" "
    fi
      WSL_Output+="$WSL_loop"
    fi
  done

  if [ -z "$CheckFor_WSL" ]; then
    if [ $WSL_Output_boolean = 1 ]; then
      WSL_Eval="logger -s \"$WSL_Output\""
    else
      WSL_Eval="logger \"$WSL_Output\"" 
    fi
  else
    if [ $WSL_Output_boolean = 1 ]; then
      WSL_Eval="echo \"<WSL-logger> $date_logger $USER: $WSL_Output\""
    else
      :
      #Not being use a moment NEEDS TO REVIEWED
    fi
  fi

  if [ ! -z "$WSL_Eval" ]; then
    # Not done if WSL and -s isn't required
    eval "$WSL_Eval"
  fi
  #Resting the values
  unset WSL_Output
  unset WSL_Output_boolean
  unset WSL_Eval
}

set_user_agent () {
  if [ -z "$curl_version_user_agent" ]; then
    curl_version_user_agent=$(curl --version)
  fi

  if [ ! -z "$user_agent_name" ]; then
    user_agent_name_temp=" [uan $user_agent_name]"
  fi

  agent_name="timetoexpire.co.uk cfddns $release [${curl_version_user_agent%%)*})]$user_agent_name_temp"
  unset $user_agent_name_temp
}

purge_main () {
# (bitwise) 
# (1)=Cloudflare auth_email, auth_method=token, auth_key, zone_identifier, auth_ttl=3600, auth_proxy=true
# (2)=DNS record_name, ip_maxage=60 , ip_timestamp=0, ip
# (4)=Report report_distribution=0, report_attribute_ERRORFIX=0, report_name
# (8)=Slack slackuri
# (16)=eMail email_username, email_password, email_smtp, email_port, email_fromName, email_toName, email_fromAddress, email_toAddress
# (32)=File file_logPath
# (64)=Telegram telegram_token, telegram_chatID
# (128)=Nextcloud nextcloud_domain, nextcloud_username, nextcloud_apppass, nextcloud_roomtoken

  for ((purge_main_bitwise_lc=1, purge_main_bitwise_loop=1; purge_main_bitwise_loop <= $purge_set; purge_main_bitwise_loop=((purge_main_bitwise_loop << 1)), purge_main_bitwise_lc++)); do
    case $(($purge_main_bitwise_loop & $purge_set)) in
      1)
        #purge cloudflare
        purge_cloudflare
        ;;
      2)
        #purge dns
        purge_dns
        ;;
      4)
        #purge messagebody
        purge_report
        ;;
      8)
        #purge slack
        purge_slack
        ;;
      16)
        #purge email
        purge_email
        ;;
      32)
        #purge file
        purge_file
        ;;
      64)
        #purge telegram
        purge_telegram
        ;;
      128)
        #purge nextcloud
        purge_nextcloud
        ;;
      *)
        :
        ;;
    esac
  done
  # A little bit of tidy up
  unset purge_set
}

purge_cloudflare () {
  unset auth_email
  unset auth_key
  unset zone_identifier
  unset record_name
  auth_method="token"
  auth_ttl="3600"
  proxy="true"
}

purge_dns () {
  unset record_name
  unset ip
  ip_maxage="60"
  ip_timestamp="0"
}

purge_report () {
  unset report_name
  report_distribution="0"
  report_attribute="0"
}

purge_slack () {
  unset slackuri
}

purge_email (){
  unset email_username
  unset email_password
  unset email_smtp
  unset email_port
  unset email_fromName
  unset email_toName
  unset email_fromAddress
  unset email_toAddress
}
purge_file () {
  unset file_logPath
}

purge_telegram () {
  unset telegram_token
  unset telegram_chatID
}

purge_nextcloud () {
  unset nextcloud_domain
  unset nextcloud_username
  unset nextcloud_apppass
  unset nextcloud_roomtoken
}
set_regex () {
  regex_ipv4='([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])\.([01]?[0-9]?[0-9]|2[0-4][0-9]|25[0-5])'
}

get_bootid () {
  # A simple "canary in a coal mine" way of get an current boot_id, 
  # if you get "/proc/sys/kernel/random/boot_id" or "boot_id is not accessible" 
  # something going wrong.
  boot_id="/proc/sys/kernel/random/boot_id"
  if [ -f "$boot_id" ]; then
    boot_id=$(cat "$boot_id")
  else
    boot_id="$boot_id is not accessible"
  fi
  if [[ $boot_id = *"/boot_id"* ]] || [ ${#boot_id} -eq 0 ]; then
    logger_output="$log_name $boot_id"  
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
    boot_id="[$boot_id]"
  fi
}

cf_kickstart () {
  check_install_command curl
  checkFor_WSL
  Check_isRoot
  set_regex
  set_user_agent
  cf_setting_internal
  cf_setting_parameter
  cf_setting_file 
  cf_purge_all
  cf_exec
  cf_purge_all
  debug_output_echo
}


cf_kickstart


#echo -e "$debug_output"

#echo "intrenal :${cf_setting_internal_array[*]}"
#echo "paramter :${cf_setting_parameter_array[*]}"
#echo "file :${cf_setting_file_array[*]}"
#exit