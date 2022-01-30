#!/bin/bash
## change to "bin/sh" when necessary

auth_email=""                                      # The email used to login 'https://dash.cloudflare.com'
auth_method="token"                                # Set to "global" for Global API Key or "token" for Scoped API Token 
auth_key=""                                        # Your API Token or Global API Key
zone_identifier=""                                 # Can be found in the "Overview" tab of your domain
record_name=""                                     # Which record you want to be synced
ttl="3600"                                         # Set the DNS TTL (seconds)
proxy=false                                        # Set the proxy to true or false

config_file=""                                     # file location of config file

message_output=255                                 # (bitwise) (1)=Account (2)=Type (4)=IP Address (8)=Proxy (16)=TTL (32)=Time (64)=Identifier (128)=Status   'https://en.wikipedia.org/wiki/Bitwise_operation'
message_name=""                                    # set an identifier name, if none is set (NULL) it will use $HOSTNAME
message_type=0                                     # (bitwise) (1)=Slack (2)=email (4)=console (8)=file   'https://youtu.be/LpuPe81bc2w'

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


####################################################
# Only edit bellow if understand what you are doing 
####################################################
parameter_input=("$@")
curl_max_time=30.5

cf_ddns_ip () {
  ###########################################
  ## Check if we have a public IP
  ###########################################
  ip=$(curl -s https://api.ipify.org || curl -s https://ipv4.icanhazip.com/)

  if [ "${ip}" == "" ]; then 
    logger_output="DDNS Updater: No public IP found"
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
    #no point going on if can not get ip
    exit_code 1
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

  WSL_Logger "DDNS Updater: Check Initiated"
  debug_output+="$logger_output\n"
  record=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records?type=A&name=$record_name" \
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
    logger_output="DDNS Updater: Record does not exist, perhaps create one first? (${ip} for ${record_name})"
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
    logger_output="DDNS Updater: IP ($ip) also "
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
  update=$(curl -s -X PATCH "https://api.cloudflare.com/client/v4/zones/$zone_identifier/dns_records/$record_identifier" \
                      -H "X-Auth-Email: $auth_email" \
                      -H "$auth_header $auth_key" \
                      -H "Content-Type: application/json" \
                --data "{\"type\":\"A\",\"name\":\"$record_name\",\"content\":\"$ip\",\"ttl\":\"$ttl\",\"proxied\":${proxy}}")
  debug_output+="cf_ddns_update : $update\n"
}

cf_ddns_status_slack () {
  ###########################################
  ## Report the status
  ###########################################
  set_message_slack

  update_statusSlack=$(curl -s --max-time $curl_max_time -X POST $slackuri -H 'Content-type: application/json' --data "$output_messageBody")
}

cf_ddns_status () {
  get_date_strings

  case "$update" in
  *"\"success\":false"*)
    # FAILED
    update_status=1

    logger_output="DDNS Updater: $ip $record_name DDNS failed for $record_identifier ($ip). DUMPING RESULTS:\n$update"
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
    ;;
  *)
    # Success
    update_status=0

    logger_output="DDNS Updater: $ip $record_name DDNS updated."
    debug_output+="$logger_output\n"
    WSL_Logger "$logger_output"
    ;;
  esac

  for ((cf_ddns_status_bitwise_lc=1, cf_ddns_status_bitwise_loop=1; cf_ddns_status_bitwise_loop <= $message_type; cf_ddns_status_bitwise_loop=((cf_ddns_status_bitwise_loop << 1)), cf_ddns_status_bitwise_lc++)); do
    case $(($cf_ddns_status_bitwise_loop & $message_type)) in
      1)
        #send message via slack
        cf_ddns_status_slack
        ;;
      2)
        #send message via email
        cf_ddns_status_email
        ;;
      4)
        cf_ddns_status_console
        ;;
      8)
        cf_ddns_status_planetext
        ;;
      *)
        :
        ;;
    esac
  done
  exit_code $update_status
}

cf_ddns_main () {
  if [ ${#ip} -eq 0 ]; then
  #Only worth getting current IP address with first domain
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
    logger_output="DDNS Updater: in tolerant mode - exit [$excode]"
    debug_output+="$logger_output\n"
    WSL_Logger "$logger_output"
  else
  #If strict mode it will stop instantly on error
    debug_output_echo
    exit "$excode"
  fi
}

cf_counting_sheep () {
  datestart=$(date +%Y/%m/%d\ %H:%M:%S)
  dateend=$(date --date="+$parameter_value seconds" +"%Y/%m/%d %H:%M:%S")
  logger_output="DDNS Updater: counting sheep ($parameter_value) $datestart : $dateend"
  debug_output+="$logger_output\n"
  WSL_Logger -s "$logger_output"
  sleep "$parameter_value"
}

cf_help () {
  echo "# crontab"
  echo "*/5 * * * * /bin/bash /home/user/cloudflare-ddns-updater/cloudflare-init.sh"
  echo '*/5 * * * * /bin/bash /home/user/cloudflare-ddns-updater/cloudflare-init.sh -tolerant mydomain.com example.com www.example.com x1.example.com'
  echo '*/5 * * * * /bin/bash /home/user/cloudflare-ddns-updater/cloudflare-init.sh -tolerant mydomain.com -sleep=10 example.com -proxy=false www.example.com -auth_ttl=10 x1.example.com'
  echo "Add in -tolerant option that get continue if when reason to exit, this should be first parameter"
  echo "-sleep=X will make it sleep for X seconds before doing proceeding domains"
  echo "-rsleep=X will random range from 0 to X seconds"
  echo "-auth_email=X it for this will change it for proceeding domains"
  echo "-auth_method=X it for this will change it for proceeding domains"
  echo "-auth_key=X it for this will change it for proceeding domains"
  echo "-auth_identifier=X it for this will change it for proceeding domains"
  echo "-auth_ttl=X it for this will change it for proceeding domains"
  echo "-auth_proxy=X it for this will change it for proceeding domains"
  echo "-purge will purge current setting for cloudflare"
  echo "Messaging services (Slack/email/console/file)"
  echo "-message_output=X (bitwise value) (1)=Account (2)=Type (4)=IP Address (8)=Proxy (16)=TTL (32)=Time (64)=Identifier (128)=Status"
  echo "-message_name=X set the reported Identifier name, if none is set (null) it will use \$HOSTNAME"
  echo "-message_type=X (bitwise value) (1)=Slack (2)=e-mail (4)=console (8)=file"
  echo "-slackuri=X Slack webhooks URI"
  echo "-email_username=X SMTP username"
  echo "-email_password=X SMTP password"
  echo "-email_smtp=X SMTP server (domain name/ip)"
  echo "-email_port=X SMTP port number"
  echo "-email_fromName / -email_toName=X name of user of that email address (Joe Bloggs / Jane Doe)"
  echo "-email_fromAddress / -email_toAddress=X email address of that user (joe@example.com / jane@example.org)"
  echo "-file_logPath ################################################"
}

cf_tolerant () {
  tolerant_is_set=1
  logger_output="DDNS Updater: Been set as being tolerant"
  debug_output+="$logger_output\n"
  WSL_Logger "$logger_output"
}

cf_rsleep () {
  logger_output="DDNS Updater: rsleep range ($parameter_value) : "
  parameter_temp=$(( $parameter_value+1 ))
  parameter_value=$(( $RANDOM % $parameter_temp ))
  logger_output+="($parameter_value)"
  debug_output+="$logger_output\n"
  WSL_Logger "$logger_output"
  cf_counting_sheep
}

cf_auth_email () {
  logger_output="DDNS Updater: Changed [auth_email]"
  debug_output+="$logger_output ($parameter_value)\n"
  WSL_Logger "$logger_output"
  auth_email=$parameter_value
}

cf_auth_method () {
  logger_output="DDNS Updater: Changed [auth_method]"
  debug_output+="$logger_output ($parameter_value)\n"
  WSL_Logger "$logger_output"
  auth_method=$parameter_value
}

cf_auth_key () {
  logger_output="DDNS Updater: Change [auth_key]"
  debug_ouput+="$logger_output ($parameter_value)\n"
  WSL_Logger "$logger_output"
  auth_key=$parameter_value
}

cf_zone_identifier () {
  logger_output="DDNS Updater: Change [zone_identifier]"
  debug_ouput+="$logger_output ($parameter_value)\n"
  WSL_Logger "$logger_output"
  zone_identifier=$parameter_value
}

cf_ttl () {
  logger_output="DDNS Updater: Change [ttl]"
  debug_ouput+="$logger_output ($parameter_value)\n"
  WSL_Logger "$logger_output"
  ttl=$parameter_value
}

cf_proxy () {
  logger_output="DDNS Updater: Changed [proxy]"
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
  #TODO **************************************************************************************************************************
}

cf_ip_set () {
  ip=$parameter_value
  logger_output="DDNS Updater: IP been set to $ip"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_ip_recheck () {
  ip=""
  logger_output="DDNS Updater: IP been set to do a recheck"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_entry_point () {
  logger_output="DDNS Updater: [entrypoint] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_remark_statment () {
  debug_output+="REMark: $parameter_value\n"
}

cf_slack () {
  slackuri=$parameter_value
  logger_output="DDNS Updater: [slackuri] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_username () {
  email_username=$parameter_value
  logger_output="DDNS Updater: [email_username] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_password () {
  email_password=$parameter_value
  logger_output="DDNS Updater: [email_password] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_smtp () {
  email_smtp=$parameter_value
  logger_output="DDNS Updater: [email_smtp] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_port () {
  email_port=$parameter_value
  logger_output="DDNS Updater: [email_port] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_fromName () {
  email_fromName=$parameter_value
  logger_output="DDNS Updater: [email_fromName] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_fromAddress () {
  email_fromAddress=$parameter_value
  logger_output="DDNS Updater: [email_fromAddress] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_toName () {
  email_toName=$parameter_value
  logger_output="DDNS Updater: [email_toName] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_email_toAddress () {
  email_toAddress=$parameter_value
  logger_output="DDNS Updater: [email_toAddress] ($parameter_value)"
  WSL_Logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_message_output () {
  message_output=$parameter_value
  logger_output="DDNS Updater: [message_output] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
}

cf_message_name() { 
  message_name=$parameter_value
  logger_output="DDNS Updater: [message_name] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
} 

cf_message_type() { 
  message_type=$parameter_value
  logger_output="DDNS Updater: [message_type] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
} 

cf_file_logPath() { 
  file_logPath=$parameter_value
  logger_output="DDNS Updater: [file_logPath] ($parameter_value)"
  logger "$logger_output"
  debug_ouput+="$logger_output\n"
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
    "entrypoint")
      cf_entry_point
      ;;
    "purge")
      cf_to_null
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
    "message_output")
      cf_message_output
      ;;
    "message_name")
      cf_message_name
      ;;
    "message_type")
      cf_message_type
      ;;
    "file_logpath")
      cf_file_logPath
      ;;
    "config_file")
      :
      ;;
    *)
      logger_output="DDNS Updater: invalid parameter option been defined [${parameter_temp}]"
      debug_output+="$logger_output\n"
      WSL_Logger -s "$logger_output"
      ;;
  esac
}

cf_err_human () {
  err_is_human=0

  if [ ${#auth_email} -eq 0 ]; then
    err_is_human=1
    logger_output="DDNS Updater: ERROR [auth_email] record not been defined"
    WSL_Logger -s "$logger_output"
  fi

  if [ ${#auth_method} -eq 0 ]; then
    err_is_human=1
    logger_output='DDNS Updater: ERROR [auth_method] setting has not been defined'
    WSL_Logger -s "$logger_output"
  else
    if [ $auth_method != "token" ] && [ $auth_method != "global" ]; then
      err_is_human=1
      logger_output='DDNS Updater: ERROR [auth_method] is invaled it has to be defined "token" "global" defined'
      WSL_Logger -s "$logger_output"
    fi
  fi

  if [ ${#auth_key} -eq 0 ]; then
    err_is_human=1
    logger_output="DDNS Updater: ERROR [auth_key] record not been defined"
    WSL_Logger -s "$logger_output"
  fi

  if [ ${#zone_identifier} -eq 0 ]; then
    err_is_human=1
    logger_output="DDNS Updater: ERROR [zone_identifier] record has not been defined"
    WSL_Logger -s "$logger_output"
  fi

  if [ ${#record_name} -eq 0 ]; then
    err_is_human=1
    logger_output="DDNS Updater: ERROR [record_name] record has not been defined"
    WSL_Logger -s "$logger_output"
  fi

   if [ ${#ttl} -eq 0 ]; then
    err_is_human=1
    logger_output="DDNS Updater: ERROR [ttl] record has not been defined"
    WSL_Logger -s "$logger_output"
  fi

  if [ ${#proxy} -eq 0 ]; then
    err_is_human=1
    logger_output='DDNS Updater: ERROR [proxy] setting has not been defined'
    WSL_Logger -s "$logger_output"
  else
    if [ $proxy != "true" ] && [ $proxy != "false" ]; then
      err_is_human=1
      logger_output='DDNS Updater: ERROR [proxy] is invaled it has to be defined "true" "false" defined'
      WSL_Logger -s "$logger_output"
    fi
  fi

  if [ ${#record_name} -eq 0 ]; then
    err_is_human=1
    logger_output="DDNS Updater: ERROR [record_name] record not has been defined"
    WSL_Logger -s "$logger_output"
  fi

  if [ -z "$tolerant_is_set" ]; then
    # if tolerant_is_set has not been set up it will be strict
    tolerant_is_set=0
  fi

  if [ $tolerant_is_set -lt 0 ] || [ $tolerant_is_set -gt 1 ]; then
    err_is_human=1
    logger_output="DDNS Updater: ERROR [tolerant_is_set] can only by 0 or 1"
    WSL_Logger -s "$logger_output"
  fi

  if [ $err_is_human -eq 1 ]; then
    #It is done if there is error detected above
    exit_code 1
  fi
}

cf_to_null () {
  auth_email=""
  auth_method=""
  auth_key=""
  zone_identifier=""
  record_name=""
  ttl=""
  proxy=""
  #ip=""
}

cf_setting_internal () {
  debug_output_local="cf_setting_internal:"
  cf_setting_internal_array=('-entrypoint=_settinginternal')

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

  if [[ -z $message_output ]]; then
    debug_output+="$debug_output_local undefined [message_output]\n"
  else
    cf_setting_internal_array+=("-message_output=${message_output}")
  fi  
  if [[ -z $message_name ]]; then
    debug_output+="$debug_output_local undefined [message_name]\n"
  else
    cf_setting_internal_array+=("-message_name=${message_name}")
  fi 
  if [[ -z $message_type ]]; then
    debug_output+="$debug_output_local undefined [message_type]\n"
  else
    cf_setting_internal_array+=("-message_type=${message_type}")
  fi 
  if [[ -z $file_logPath ]]; then
    debug_output+="$debug_output_local undefined [file_logPath]\n"
  else
    cf_setting_internal_array+=("-file_logPath=${file_logPath}")
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
      logger_output="DDNS Updater: ${debug_output_local}file not found [${config_file}]"
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
 #######if [[ $string_character == $'\015' ]]; then # WINDOWS CR
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
      logger_output="DDNS Updater: ${debug_output_local} [-config_file] already defened as [${config_file}] not changed to [${retain_setting_to_check:13}]"
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

cf_ddns_status_email () {
  if [[ $email_username != "" ]]; then
    if [[ $email_fromAddress == "" ]]; then
      logger_output="DDNS Updater : There is no from e-mail address been defiened [email_fromAddress]"
      debug_output+="$logger_output\n"
      WSL_Logger -s "$logger_output"
    fi

    if [[ $email_toAddress == "" ]]; then
      email_toAddress=$email_fromAddress
    fi

    #get_date_strings
    set_message_email

    curl -s --max-time $curl_max_time -url smtps://$email_smtp:$email_port --ssl-reqd \
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
      #curl_errorhuman+=$'\nSMTP: ['$sesSMTP']'
      #curl_errorhuman+=$'\nPort: ['$sesPort']'
      #curl_errorhuman+=$'\nAccess: ['$sesAccess']'
      logger_output="DDNS Updater: e-mail $curl_errorcode :- $curl_errorhuman"
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
    logger_output="DDNS Updater: file_logPath [$file_logPath] undefined value"
    debug_output+="$logger_output\n"
    WSL_Logger -s "$logger_output"
    exit_code 1
  else
    set_message_planetext
    echo -e "$output_messageBody" >>"$file_logPath"
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
}

output_bodyString () {
  output_messageBody="$rts_header"
  for ((output_bodyString_bitwise_lc=1, output_bodyString_bitwise_loop=1; output_bodyString_bitwise_loop <= $message_output; output_bodyString_bitwise_loop=((output_bodyString_bitwise_loop << 1)), output_bodyString_bitwise_lc++)); do

    case $(($output_bodyString_bitwise_loop & $message_output)) in
      1)
        output_messageBody+="$rts_line""$rts_italicize""Account""$rte_italicize"": ""$auth_email""$rte_line"
        ;;
      2)
        output_messageBody+="$rts_line""$rts_italicize""Type A""$rte_italicize"": ""$record_name""$rte_line"
        # email_messageBody+=$'Type AAAA: '$domain_name$'\n' # TODO
        ;;
      4)
        output_messageBody+="$rts_line""$rts_italicize""IP address""$rte_italicize"": ""$ip"" (""$rts_strickethrough""$old_ip""$rte_strickethrough"")""$rte_line"
        ;;
      8)
        output_messageBody+="$rts_line""$rts_italicize""Proxy""$rte_italicize"": ""$proxy"" (""$rts_strickethrough""$old_proxy""$rte_strickethrough"")""$rte_line"
        ;;
      16)
        output_messageBody+="$rts_line""$rts_italicize""TTL""$rte_italicize"": "
        if [[ $proxy == true ]]; then
          output_messageBody+="PROXIED"
        else
          output_messageBody+="$ttl"
        fi
        output_messageBody+=" (""$rts_strickethrough"
        if [[ $old_proxy == true ]]; then
          output_messageBody+="PROXIED"
        else
          output_messageBody+="$ttl"
        fi
        output_messageBody+="$rte_strickethrough"")""$rte_line"
        ;;
      32)
        output_messageBody+="$rts_line""$rts_italicize""Time""$rte_italicize"": ""$date_utc""$rte_line"
        ;;
      64)
        ####output_messageBody+="$rts_line""$rts_italicize""Hostname""$rte_italicize"": ""$HOSTNAME""$rte_line"
        output_messageBody+="$rts_line""$rts_italicize""Identifier""$rte_italicize"": "
        if [ -z $message_name ]; then
          output_messageBody+="$HOSTNAME"
        else
          output_messageBody+="$message_name"
        fi
        output_messageBody+="$rte_line"
        ;;
      128)
        output_messageBody+="$rts_line""$rts_italicize""Status""$rte_italicize"": "
        if [ $update_status -eq 0 ]; then
          output_messageBody+="Success"
        else
          output_messageBody+="$rts_bold""FAILED""$rte_bold"
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
  else
    CheckFor_WSL="" # This value NULL if WSLInterop dosnt exists
  fi
}

WSL_Logger () {
  # we need this because (microsoft/windows) WSL dosn't have /var/log/syslog and this will give problems with "# Logger" command

  #Resting the values
  WSL_Output="" 
  WSL_Output_boolean=0
  WSL_Eval=""

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
}

cf_kickstart () {
  check_install_command curl
  checkFor_WSL
  cf_setting_internal
  cf_setting_parameter
  cf_setting_file 
  cf_to_null
  cf_exec
  debug_output_echo
}


cf_kickstart


#echo -e "$debug_output"

#echo "intrenal :${cf_setting_internal_array[*]}"
#echo "paramter :${cf_setting_parameter_array[*]}"
#echo "file :${cf_setting_file_array[*]}"
#exit