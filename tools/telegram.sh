#!/bin/sh

tg_safey_range=$(( 60*4 )) #sec x mins

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

echo_replace () {
    tput civis
    echo_replace_output_len=${#echo_replace_output}
    echo_replace_output=$1
    tput cub "$echo_replace_output_len"
    tput el
    echo -n -e "$echo_replace_output"
}

echo_nextline () {
  echo_replace_ouput=""
  echo -n -e "\n"
  tput cnorm
}

Datetime_range () {
  dtr_setting="%Y-%m-%d %H:%M:%S %Z"
  dtr_current=$(date +"$dtr_setting")
  dtr_format="YYYY-MM-DD HH:MM:SS Tz"
  dtr_unix=$(date '+%s')

  if [ -z "$dtr_unix_first_start" ]; then
    dtr_unix_first_start=$dtr_unix
    dtr_unix_safe_start=$(( dtr_unix_first_start - tg_safey_range ))
    dtr_unix_safe_end=$(( dtr_unix + tg_safey_range ))
    dtr_safe_end_human=$(date -d "@$dtr_unix_safe_end" +"$dtr_setting")
  fi
}

Tg_getUpdates () {
  tg_getUpdates="$tg_url""getUpdates"
  tg_getUpdates=$(curl -s "$tg_getUpdates")
  if [ ! $(echo "$tg_getUpdates" | jq ".ok") = "true" ]; then
    echo "ERROR: Unable to make contact with Telegram with those credentials"
    Escape_code 1
  fi
}

Tg_postMsg () {
  tg_postMsg="$tg_url""sendMessage"
  tg_postMsg=$(curl -s -X POST "$tg_postMsg" -d chat_id="$jq_chatid" -d text="$tg_output" -d parse_mode="MarkdownV2")
  sleep 1
}

Tg_url () {
  tg_url="https://api.telegram.org/bot$tg_token/"
}

Jq_length () {
  jq_length=$(echo "$tg_getUpdates" | jq '.result | length')
  if [ -z "$jq_length_start" ]; then
    jq_length_start="$jq_length"
  fi
}

Jq_check () {
  for (( jq_x="$jq_length_start"; jq_x < jq_length ; jq_x++ )); do
    jq_result=$(echo "$tg_getUpdates" | jq -r ".result[$jq_x].message.text")
    if [ "$jq_result" = "$tg_random" ]; then
      jq_chatid=$(echo "$tg_getUpdates" | jq -r ".result[$jq_x].message.chat.id")
      jq_date_unix=$(echo "$tg_getUpdates" | jq -r ".result[$jq_x].message.date")
      jq_date_age_sec=$(( $(date '+%s') - $jq_date_unix ))

      echo_nextline
      if [ $jq_date_unix -ge $dtr_unix_safe_start ] && [ $jq_date_unix -le $dtr_unix_safe_end ]; then
        tg_output="Check ID : "
        tg_output_number=""
        for (( jq_check_x=0; jq_check_x<$(($RANDOM%4+4)); jq_check_x++ )); do
          tg_output_number+=$(($RANDOM%9))
        done
        tg_output_console="[""$tg_output_number""-"
        tg_output+="\[""$tg_output_number""\-"

        tg_output_number=""
        for (( jq_check_x=0; jq_check_x<$(($RANDOM%2+3)); jq_check_x++ )); do
          tg_output_number+=$(($RANDOM%9))
        done

        tg_output_console+="$tg_output_number""]"
        tg_output+="$tg_output_number""\]"

        Tg_postMsg
        echo "An confirmation message has been sent on Telegram that should verify is correct"
        echo "Check ID : $tg_output_console"
        echo " "
        echo "telegram_token=\"$tg_token\""
        echo "telegram_chatID=\"$jq_chatid\""
        Escape_code 0
      else
        echo "Found record outside vailed time scope, is it correct time?"
        sleep 5
      fi
    else
      :
    fi
  done
}

Get_random_number () {
  while [[ $tg_random -lt 1000 ]]; do
    tg_random=$(($RANDOM%999999))
  done
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
  #echo "DEBUG Api_scan"
  api_scan="Checking Telegram, please wait."
  echo_replace "$api_scan"
  Tg_getUpdates
  echo_replace "$api_scan."
  Jq_length
  Jq_check
  # scand json file is done here
  echo_replace "$api_scan.."
  ############################################################
  ## sleep 1   is done so the user has chance to be able
  ##           notice that an check for Telegram taken place
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

Check_install_command curl
Check_install_command jq

tg_token=$1
if [ -z $tg_token ]; then
  echo "You need supply you Telegram token that BotFather has supplied ie"
  echo "$0 1234567890:AA12BB12CC12dd12ee12fF12Ab12cD12EfA"
  Escape_code 1
fi
echo "Going to check the telegram_token $tg_token"
echo "For manual recheck Telegram servers press \"c\", to exit out press \"E\""
Tg_url
Get_random_number


echo "On Telegram enter this number [$tg_random]"

Datetime_range

echo " "

# This is so will know which records start to checking from
Tg_getUpdates
Jq_length

while [ -z "$escape_code" ]
do
      Api_main
done
