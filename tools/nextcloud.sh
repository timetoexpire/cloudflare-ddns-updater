#!/bin/sh

nc_safey_range=$(( 60*4 ))                         #sec x mins

user_agent_name=""                                 # This part string that curl users as user agent, if set to Test123 supplement to curl user-agent "[uan Test123]"

curl_max_time=30.5

Check_install_command () {
  ## This is use to make shore for commands are install that are not part of POSIX
  check_installCommand=$1
  if [[ -z $check_installCommand ]]; then
    logger -s "$0 [[check_install_command]]: NullReferenceException; nothing defined [$check_install_command]"
    Escape_code 1
  fi
  if ! command -v "$check_installCommand" &> /dev/null; then
    check_installCommandMessage="$check_installCommand"$' is required for this to run.\n'
    check_installCommandMessage+='(Debian)# apt install '"$check_installCommand"$'\n'
    check_installCommandMessage+='(RHEL)# yum install '"$check_installCommand"$'\n'
    check_installCommandMessage+='(OpenSUSE)# zypper install '"$check_installCommand"$'\n'
    check_installCommandMessage+='(ArchLinux)# pacman -Sy '"$check_installCommand"$'\n'
    echo "$check_installCommandMessage"
    Escape_code 1
  fi
}

Set_user_agent () {
  if [ -z "$curl_version_user_agent" ]; then
    curl_version_user_agent=$(curl --version)
  fi

  if [ ! -z "$user_agent_name" ]; then
    user_agent_name_temp=" [uan $user_agent_name]"
  fi

  agent_name="timetoexpire.co.uk cfddns $release [${curl_version_user_agent%%)*})]$user_agent_name_temp"
  unset $user_agent_name_temp
}

Nextcloud_domain () {
  read -p "Nextcloud hostname [https://nextcloud.example.org] ? "
  nextcloud_curl_domain="$REPLY"
  unset REPLY
}

Nextcloud_enter_userpass () {
  read -p "What is Nextcloud account Username? "
  nextcloud_username="$REPLY"
  unset REPLY
  echo " "
  read -s -p "What is Nextcloud account Password? ***"
  nextcloud_password="$REPLY"
  unset REPLY
  echo " "

  nextcloud_curl=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -u "$nextcloud_username:$nextcloud_password" -H 'OCS-APIRequest: true' "$nextcloud_curl_domain""/ocs/v2.php/core/getapppassword")
  
  if [ ! -z "$nextcloud_curl" ]; then
    nextcloud_vailed=true
    Simple_XML_extractor "$nextcloud_curl" "status"
    if [ "$simple_XML_result" != "ok" ] || [ "${#simple_XML_result}" -eq 0 ]; then
      nextcloud_vailed=false
    fi
    Simple_XML_extractor "$nextcloud_curl" "message"
    if [ "$simple_XML_result" != "OK" ] || [ "${#simple_XML_result}" -eq 0 ]; then
      nextcloud_vailed=false
    fi

    if [ "$nextcloud_vailed" == true ]; then
      Simple_XML_extractor "$nextcloud_curl" "apppassword"
      nextcloud_password=$simple_XML_result
      Nextcloud_details
      letmeouthere=true
    else 
      echo "Been unable to authorised using those details"
    fi
  else
    echo "Unable to contact Nextcloud server [$nextcloud_curl_domain]"
  fi
  unset nextcloud_username
  unset nextcloud_password
  unset simple_XML_result
  unset nextcloud_curl
}

Nextcloud_details () {
  echo -e "nextcloud_domain=\"\e[40m\e[32m$nextcloud_curl_domain\e[39m\e[49m\""
  echo -e "nextcloud_username=\"\e[40m\e[32m$nextcloud_username\e[39m\e[49m\""
  echo -e "nextcloud_apppass=\"\e[40m\e[32m$nextcloud_password\e[39m\e[49m\""
  Nc_get_room_token
  if [ ${#nc_room_token[@]} -ne 0 ]; then
    echo "nextcloud_roomtoken :-"
    for (( x=0; x < ${#nc_room_token[@]}; x++ )); do
      echo -e "\"\e[40m\e[32m${nc_room_token[$x]}\e[39m\e[49m\"  ${nc_room_displayname[$x]}"
    done
  else 
    echo "Not a member of Talk channel"
  fi
  Escape_code 0
}

Nextcloud_URI () {
  nextcloud_curl=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -X POST "$nextcloud_curl_domain""/index.php/login/v2")
  nextcloud_base_json_test="{\"poll\":{\"token\":\"" # this is first 18 characters this is JSON that is expected if comes from Nextcloud server
  if [ "${nextcloud_curl:0:18}" != "$nextcloud_base_json_test" ]; then 
    echo -e "Unable to access Nextcloud server [\e[40m\e[32m$nextcloud_curl_domain\e[39m\e[49m]\n"
  else
    unset nextcloud_base_json_test
    Nc_url
    Nextcloud_output_browserURL
    Datetime_range
    while [ -z "$escape_code" ]
    do
      Api_main
    done
  fi
}

Nextcloud_output_browserURL () {
  temp_string="Copy this URL and past in browser"
  if [ ${nc_browser%%://*} != ${nextcloud_curl_domain%%://*} ]; then
    temp_string+=", if link unable to connect replace \"\e[40m\e[32m${nc_browser%%://*}://\\e[39m\e[49m\" with \"\e[40m\e[32m${nextcloud_curl_domain%%://*}://\e[39m\e[49m\""
  fi
  temp_string+="\n\e[40m\e[32m$nc_browser\e[39m\e[49m"
  echo -e "$temp_string"
  unset temp_string
}

Nc_url () {
  nc_url_endpoint_test_vailedstring="[]"
  nc_token=$(echo $nextcloud_curl | jq --raw-output ".poll.token")
  nc_endpoint=$(echo $nextcloud_curl | jq --raw-output ".poll.endpoint")
  nc_browser=$(echo $nextcloud_curl | jq --raw-output ".login")

  if [ ${nc_endpoint%%://*} != ${nextcloud_curl_domain%%://*} ]; then
    ## This is when set using http but it https
    echo -e "Nextcloud operating using \e[40m\e[32m${nc_endpoint%%://*}\e[39m\e[49m while you connected using \e[40m\e[32m${nextcloud_curl_domain%%://*}\e[39m\e[49m - Is it using \"load balancer, reverse proxy\"?"
  fi
  # First check using HTTPS protocal ## protocal://(domain/url)
  # Only change protocal for $nc_endpoint if sucessful
  nc_url_endpoint_test_url="${nc_endpoint/${nc_endpoint%%://*}/https}"
  nc_url_endpoint_test=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -X POST "$nc_url_endpoint_test_url" -d "token=$nc_token")
  if [ "${#nc_url_endpoint_test}" -gt 0 ]; then
    if [ "$nc_url_endpoint_test" == "$nc_url_endpoint_test_vailedstring" ]; then
      nc_endpoint="$nc_url_endpoint_test_url"
    else 
      # So it will do next test
      nc_url_endpoint_test=""
    fi
  fi
  # Only do test if previous test didn't work
  if [ "${#nc_url_endpoint_test}" -eq 0 ]; then
    # Second change protocal for $nc_endpoint insted use same (protocal) as used in $nextcloud_curl_domain with (domain/url) ## protocal://(domain/url)
    nc_url_endpoint_test_url="${nc_endpoint/${nc_endpoint%%://*}/${nextcloud_curl_domain%%://*}}"
    nc_url_endpoint_test=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -X POST "$nc_url_endpoint_test_url" -d "token=$nc_token")
    if [ "${#nc_url_endpoint_test}" -gt 0 ]; then
      if [ "$nc_url_endpoint_test" == "$nc_url_endpoint_test_vailedstring" ]; then
        nc_endpoint="$nc_url_endpoint_test_url"
      else 
        # So it will do next test
        nc_url_endpoint_test=""
      fi
    fi
  fi

  unset nc_url_endpoint_test_url
  unset nc_url_endpoint_test
  unset nc_url_endpoint_test_vailedstring
}

Nc_get_room_token () {
  TEMPNAME_XML_data=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -X GET "$nextcloud_curl_domain""/ocs/v2.php/apps/spreed/api/v4/room" -u "$nextcloud_username:$nextcloud_password" -H "OCS-APIRequest: true")
  nc_room_token=()
  nc_room_displayname=()
  Simple_XML_extractor "$TEMPNAME_XML_data" "data"
  if [ -z "$simple_XML_result" ]; then
    echo "unable to find object [data]"
    return
  fi
  nc_get_room_token_remaining_TEMP="$simple_XML_result" ## $nc_get_room_token_remaining_TEMP

  while [[ ${#simple_XML_result} -gt 0 ]]
  do
    Simple_XML_extractor "$nc_get_room_token_remaining_TEMP" "element" ## $nc_get_room_token_remaining_TEMP
    if [[ ${#simple_XML_result} -ne 0 ]]; then
    nc_get_room_token_remaining_TEMP="$simple_XML_remaining"  ## $nc_get_room_token_remaining_TEMP
    
    nc_get_room_token_element_TEMP="$simple_XML_result"

    Simple_XML_extractor "$nc_get_room_token_element_TEMP" "token"
    nc_room_token+=("$simple_XML_result")
    
    Simple_XML_extractor "$nc_get_room_token_element_TEMP" "displayName"
    nc_room_displayname+=("${simple_XML_result:0:32}") # Limited string output to first 32 characters
    fi
  done

  unset nc_get_room_token_remaining_TEMP
  unset nc_get_room_token_element_TEMP
}

Escape_code () {
  echo_nextline
  escape_code="$1"

  if [[ -z "$escape_code" ]]; then
    exit 
  else 
    exit "$escape_code"
  fi
}

Api_main () {
  Update_time_status  
  if [ -z "$api_deferment_sleep" ]; then
    Api_deferment
  else
    if [ $api_deferment_end -lt $dtr_unix ]; then
      Api_scan
      Api_deferment
    fi
  fi

  if [ $dtr_unix_safe_end -lt $dtr_unix ]; then
    Api_scan
    # no point in checking after deadline has passed
    echo_replace "Passed Deadline - The time was $dtr_current, expired at $dtr_safe_end_human"
    Escape_code 1
  fi

  Keypressed_poll
  if [ $keypressed_c -eq 0 ]; then
    Api_scan
    Api_deferment
  fi
}

Nc_getUpdates () {
  nc_getUpdates=$(curl -s --user-agent "$agent_name" --max-time $curl_max_time -X POST "$nc_endpoint" -d "token=$nc_token")
}

Nc_check() {
  if [ "${#nc_getUpdates}" -lt 2 ]; then
    # no credentials are not supplied but connection is valid "[]" 
    # if corentales are vaild you JSON { ... }
    # This should never be true [ "${#nc_getUpdates}" -lt 2 ]
    echo_nextline
    echo "ERROR: Unable unable to connect to remote server Nextcloud [$nc_browser] with those credentials"
    Escape_code 1
  fi
 if [ "${#nc_getUpdates}" -gt 2 ]; then
    nextcloud_username=$(echo "$nc_getUpdates" | jq -r '.loginName')
    nextcloud_password=$(echo "$nc_getUpdates" | jq -r '.appPassword')
    #echo "$nc_getUpdates" | jq
    echo_nextline
    Nextcloud_details
  fi
}

Api_deferment () {
  if [ -z "$api_deferment_sleep" ]; then
    api_deferment_sleep=10
  fi
  ((api_deferment_sleep+=$(($RANDOM%7+1))))
  if [ $api_deferment_sleep -gt 25 ]; then
    api_deferment_sleep=3
  fi
  api_deferment_start=$(date +%s)
  api_deferment_end=$(($api_deferment_start+$api_deferment_sleep))
}

Api_scan () {
  api_scan="Checking Nextcloud, please wait."
  echo_replace "$api_scan"
  Nc_getUpdates
  echo_replace "$api_scan."
  Nc_check
  echo_replace "$api_scan.."
  ############################################################
  ## sleep 1   is done so the user has chance to be able 
  ##           notice that an check for Nextcloud taken place
  ############################################################
  sleep 1
}


Keypressed_poll (){
  keypressed_c=1
  read -s -n1 -t0.05
  if [ "$REPLY" == "c" ]; then
    keypressed_c=0
  fi
  if [ "$REPLY" == "E" ]; then
    echo_replace "User selected exiting - The time was $dtr_current"
    Escape_code 0
  fi
  unset $REPLY
}

echo_replace () {
    tput civis
    echo_replace_output_len=${#echo_replace_output}
    #echo "output_len [$output_len]"
    echo_replace_output=$1
    tput cub "$echo_replace_output_len"
    tput el
    echo -n -e "$echo_replace_output"
    #sleep 1
    #tput cnorm
}

echo_nextline () {
  echo_replace_ouput=""
  echo -n -e "\n"
  tput cnorm
}

Get_current_time () {
  Datetime_range
  current_time="The current time is : $dtr_current ($dtr_format)"
}

Update_time_status () {
  update_time_status_date=0
  update_time_status_date=$(date '+%s')
  if [ $update_time_status_date -ne $dtr_unix ]; then
    Get_current_time
    echo_replace "$current_time"
  fi
}

Datetime_range () {
  dtr_setting="%Y-%m-%d %H:%M:%S %Z"
  dtr_current=$(date +"$dtr_setting")
  
  dtr_format="YYYY-MM-DD HH:MM:SS Tz"
  dtr_unix=$(date '+%s')
  
  if [ -z "$dtr_unix_first_start" ]; then
    dtr_unix_first_start=$dtr_unix
    dtr_unix_safe_start=$(( dtr_unix_first_start - nc_safey_range ))
    dtr_unix_safe_end=$(( dtr_unix + nc_safey_range ))
    dtr_safe_end_human=$(date -d "@$dtr_unix_safe_end" +"$dtr_setting")
  fi
}

Simple_XML_extractor () {
  # $1=is XML data
  # $2=is XML element processing

  # $simple_XML_result is result if found element

    if [ -z "$1" ]; then
    echo "Simple_XML_extractor unset XML data in \$1 [\$simple_XML_data]"
    exit 1
  fi
  if [ -z "$2" ]; then
    echo "Simple_XML_extractor defined element in \$2 [\$simple_XML_object]"
    exit 1
  fi
  
  simple_XML_data=$1
  simple_XML_object=$2

  # This will find up <$simple_XML_object>
  simple_XML_remaining=${simple_XML_data#*<$simple_XML_object>}
  # This is result you looking for
  simple_XML_result=${simple_XML_remaining%%</$simple_XML_object*}
  if [ "$simple_XML_result" == "$simple_XML_data" ]; then
    # if the element is not available it will return $simple_XML_result=NULL
    simple_XML_result=""
  fi
  # Some tidding up, will anything before </$simple_XML_object> give the remain XML data
  simple_XML_remaining=${simple_XML_remaining#*</$simple_XML_object}
  simple_XML_remaining=${simple_XML_remaining#*>}
}

Useragent_name () {
  read -p "Use a useragent of [uan] ? "
  user_agent_name="$REPLY"
  unset REPLY
}

Check_install_command curl
Check_install_command jq

Set_user_agent

while [ -z "$letmeouthere" ]
do 
  echo "There are two ways of seting up for Nextcloud" 
  echo "1) Enter in your username/password on this console that want use for Nextcloud instance account"
  echo "2) From weblink you sign in uses webbrower in to your Nextcloud instance account"
  if [ "${#user_agent_name}" -gt 0 ]; then
    temp_output=" [uan $user_agent_name]"
  fi
  echo "3) Define an user agent name""$temp_output" 
  unset temp_output
  echo "EXIT) "
  read -p "? "
  case $REPLY in
    "1")
      Nextcloud_domain
      Nextcloud_enter_userpass
      ;;
    "2")
      Nextcloud_domain
      Nextcloud_URI
      ;;
    "3")
      Useragent_name
      Set_user_agent
      ;;
    "EXIT")
      letmeouthere=true
      ;;
    *)
      echo "That not vailed option [$REPLY]"
      ;;
  esac
done

