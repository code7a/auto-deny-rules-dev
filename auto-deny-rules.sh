#!/bin/bash
#
#auto-deny-rules.sh
#
#Licensed under the Apache License, Version 2.0 (the "License"); you may not
#use this file except in compliance with the License. You may obtain a copy of
#the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
#Unless required by applicable law or agreed to in writing, software
#distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#License for the specific language governing permissions and limitations under
#the License.
#
version="0.2.0"
#
usage(){
    cat << EOF
This script will create a deny rule, for each risky service, environment, and application with no traffic flows on that risky service's ports and protocols.
Workloads are recommended to be in at least visibility with 90 days of traffic flow data. Workloads need to be in selective enforcement for deny rules to take effect.

Dependencies:
.illumio.config file with illumio variables (save in a secure location, i.e. user profile)
Example:
export user=api_135450a1288aa3466
export key=55182a5fa20f04faa12345678921507aa55c3bab65f1234567896345333949b2
export fqdn=pce.lab.local
export port=8443
export org=1

jq is required to parse results
https://stedolan.github.io/jq/

usage: ./auto-deny-rules.sh [options]

options:
    -b, --exclude-broadcast     exclude broadcast transmissions
    -m, --exclude-multicast     exclude multicast transmissions
    -i, --include LABEL_NAME    include label or comma separated labels
    -e, --exclude LABEL_NAME    exclude label or comma separated labels
    -v, --version               returns version
    -h, --help                  returns help message

examples:
    ./auto-deny-rules.sh
    ./auto-deny-rules.sh -b
    ./auto-deny-rules.sh -b -m
    ./auto-deny-rules.sh --exclude-broadcast --exclude-multicast
    ./auto-deny-rules.sh --include DEV,APP1
    ./auto-deny-rules.sh --exclude PROD
    ./auto-deny-rules.sh --version
    ./auto-deny-rules.sh --help
EOF
}

get_jq_version(){
    jq_version=$(jq --version)
    if [ $(echo $?) -ne 0 ]; then
        echo "jq application not found. jq is a command line JSON processor and is used to process and filter JSON inputs."
        echo "Reference: https://stedolan.github.io/jq/"
        echo "Please install jq, i.e. yum install jq"
        exit 1
    fi
}

get_illumio_config(){
    source $BASEDIR/.illumio.config >/dev/null 2>&1 || get_illumio_vars
}

get_illumio_vars(){
    echo ""
    read -p "Enter illumio PCE domain: " fqdn
    read -p "Enter illumio PCE port: " port
    read -p "Enter illumio PCE organization ID: " org
    read -p "Enter illumio PCE API username: " user
    echo -n "Enter illumio PCE API secret: " && read -s key && echo ""
    cat << EOF > $BASEDIR/.illumio.config
export fqdn=$fqdn
export port=$port
export org=$org
export user=$user
export key=$key
EOF
}

create_deny_rules(){
    #notice
    echo "This script can take several hours to complete. It will request traffic queries for each risky service, env, and app."
    echo "Please run in a screen or tmux session to ensure it does not expire."
    while true; do
        read -rp "Press [Enter] to continue or type 'q' to quit: " input
        if [[ "$input" == "q" ]]; then
            echo "Exiting..."
            exit 0
        fi
        echo "Continuing..."
        break
    done
    #get pce version
    major_version=$(curl -s https://$user:$key@$fqdn:$port/api/v2/users/1/kvpair/whats_new | jq -r .major)
    #get auto deny rules rule set
    rule_set_curl_response=$(curl -s https://$user:$key@$fqdn:$port/api/v2/orgs/$org/sec_policy/draft/rule_sets?name=Auto-Deny-Rules)
    #count rulesets
    rules_count=$(echo $rule_set_curl_response | jq 'length')
    #if greater than 1, exit
    if (( rules_count > 1 )); then
        echo "ERROR: more than one ruleset with name 'Auto-Deny-Rules'. Please resolve."
        exit 1
    elif (( rules_count == 1 )); then
        #get href
        rule_set_curl_response_href=$(echo $rule_set_curl_response | jq -r .[0].href)
        #get rule set response
        rule_set_response=$(curl -s https://$user:$key@$fqdn:$port/api/v2$rule_set_curl_response_href)
        #disable rules, disable ruleset, and rename
        disable_payload=$(echo $rule_set_response | jq '.deny_rules |= map(if .enabled == true then .enabled = false else . end)' | jq -c '{deny_rules: [.deny_rules[] | {providers, consumers, enabled, ingress_services}]} + {enabled: false} + {"name":"Disabled-Deny-Rules-'$(date +"%Y%m%d%H%M")'"}')
        curl -s https://$user:$key@$fqdn:$port/api/v2$rule_set_curl_response_href -X PUT -H 'content-type: application/json' --data-raw $disable_payload
    fi
    #create auto deny rules rulesent
    rule_set_curl_post_response=$(curl -s https://$user:$key@$fqdn:$port/api/v2/orgs/$org/sec_policy/draft/rule_sets -X POST -H "content-type:application/json" --data-raw '{"name":"Auto-Deny-Rules","description":"created by auto-deny-rules.sh","scopes":[[]]}')
    echo "$rule_set_curl_post_response" >> "$BASEDIR/$LOGFILE"
    rule_set_href=$(echo "$rule_set_curl_post_response" | jq -r .href)
    #get ransomware services
    services_curl_response=$(curl -s https://$user:$key@$fqdn:$port/api/v2/orgs/$org/sec_policy/active/services?is_ransomware=true)
    echo "$services_curl_response" >> "$BASEDIR/$LOGFILE"
    ransomware_service_hrefs=($(echo "$services_curl_response" | jq -r .[].href))
    #get the any ip list href
    ip_lists_curl_response=$(curl -s https://$user:$key@$fqdn:$port/api/v2/orgs/$org/sec_policy/draft/ip_lists?name=Any%20%280.0.0.0%2F0%20and%20%3A%3A%2F0%29)
    echo "$ip_lists_curl_response" >> "$BASEDIR/$LOGFILE"
    any_ip_list_href=$(echo "$ip_lists_curl_response" | jq -r .[0].href)
    #for each ransomware service
    for ransomware_service_href in "${ransomware_service_hrefs[@]}"; do
        service_ports=$(curl -s https://$user:$key@$fqdn:$port/api/v2$ransomware_service_href | jq -rc .service_ports)
        echo "$service_ports" >> "$BASEDIR/$LOGFILE"
        service_name=$(curl -s https://$user:$key@$fqdn:$port/api/v2$ransomware_service_href | jq -r .name)
        echo "$service_name" >> "$BASEDIR/$LOGFILE"
        #for each env
        labels_curl_response=$(curl -s https://$user:$key@$fqdn:$port/api/v2/orgs/$org/labels?key=env)
        echo "$labels_curl_response" >> "$BASEDIR/$LOGFILE"
        env_label_hrefs=($(echo "$labels_curl_response" | jq -r .[].href))
        for env_label_href in "${env_label_hrefs[@]}"; do
            #get env href name value
            env_label_name=$(curl -s https://$user:$key@$fqdn:$port/api/v2$env_label_href | jq -r .value)
            #check if env is in include parameter
            if [[ $include_labels ]]; then
                if [ "$include_labels" = "$env_label_name" ]; then
                    #include
                    :
                else
                    if [[ "$include_labels" =~ (^|,)"$env_label_name"(,|$) ]]; then
                        #include
                        :
                    else
                        #exclude
                        continue
                    fi
                fi
            fi
            #check if env is in exclude parameter
            if [[ $exclude_labels ]]; then
                if [ "$exclude_labels" = "$env_label_name" ]; then
                    #exclude
                    continue
                else
                    if [[ "$exclude_labels" =~ (^|,)"$env_label_name"(,|$) ]]; then
                        #exclude
                        continue
                    else
                        #include
                        :
                    fi
                fi
            fi
            echo "" | tee -a "$BASEDIR/$LOGFILE"
            echo "Checking service $service_name, environment $env_label_name..."
            #get online workloads in visibility or selective
            workloads=($(curl -s "https://$user:$key@$fqdn:$port/api/v2/orgs/$org/workloads?managed=true&online=true&labels=%5B%5B%22$env_label_href%22%5D%5D&enforcement_modes=%5B%22selective%22%2C%22visibility_only%22%5D" | jq -r .[].href))
            echo "$workloads" >> "$BASEDIR/$LOGFILE"
            app_label_hrefs=()
            #get workload application labels
            for workload in "${workloads[@]}"; do
                app_label_hrefs+=($(curl -s "https://$user:$key@$fqdn:$port/api/v2$workload" | jq -r '.labels[]|select(.key=="app")|.href'))
            done
            unique_app_label_hrefs=($(printf "%s\n" "${app_label_hrefs[@]}" | sort -u))
            echo "$unique_app_label_hrefs" >> "$BASEDIR/$LOGFILE"
            apps_with_no_traffic_flows=()
            for unique_app_label_href in "${unique_app_label_hrefs[@]}"; do
                #get app name
                app_label_name=$(curl -s https://$user:$key@$fqdn:$port/api/v2$unique_app_label_href | jq -r .value)
                #check if app is in include parameter
                if [[ $include_labels ]]; then
                    if [ "$include_labels" = "$app_label_name" ]; then
                        #include
                        :
                    else
                        if [[ "$include_labels" =~ (^|,)"$app_label_name"(,|$) ]]; then
                            #include
                            :
                        else
                            #exclude
                            continue
                        fi
                    fi
                fi
                #check if env is in exclude parameter
                if [[ $exclude_labels ]]; then
                    if [ "$exclude_labels" = "$app_label_name" ]; then
                        #exclude
                        continue
                    else
                        if [[ "$exclude_labels" =~ (^|,)"$app_label_name"(,|$) ]]; then
                            #exclude
                            continue
                        else
                            #include
                            :
                        fi
                    fi
                fi
                echo "$app_label_name" >> "$BASEDIR/$LOGFILE"
                #query allowed traffic flows
                now=$(date --utc +"%Y-%m-%dT%H:%M" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M")
                days_ago_89=$(date --utc -d "89 days ago" +"%Y-%m-%dT%H:%M" 2>/dev/null || date -v-89d +"%Y-%m-%dT%H:%M")
                hours_ago_24=$(date --utc -d "24 hours ago" +"%Y-%m-%dT%H:%M" 2>/dev/null || date -v-24H +"%Y-%m-%dT%H:%M")
                #first do a 24 hour query
                body='{"sources":{"include":[[]],"exclude":[]},"destinations":{"include":[[{"label":{"href":"'$env_label_href'"}},{"label":{"href":"'$unique_app_label_href'"}}]],"exclude":['$transmission']},"services":{"include":'$service_ports',"exclude":[]},"sources_destinations_query_op":"and","start_date":"'$hours_ago_24'","end_date":"'$now'","policy_decisions":["allowed","potentially_blocked","unknown"],"boundary_decisions":[],"query_name":"","exclude_workloads_from_ip_list_query":false,"max_results":1}'
                #echo $body
                echo "$body" >> "$BASEDIR/$LOGFILE"
                async_queries_curl_response=$(curl -s https://$user:$key@$fqdn:$port/api/v2/orgs/$org/traffic_flows/async_queries -X POST -H 'content-type:application/json' --data-raw $body)
                #echo $async_queries_curl_response
                echo "$async_queries_curl_response" >> "$BASEDIR/$LOGFILE"
                traffic_flows_query_href=$(echo "$async_queries_curl_response" | jq -r .href)
                traffic_flows_query_status=""
                while [[ $traffic_flows_query_status != "completed" ]]; do
                    sleep 10
                    traffic_flows_query_curl_response=$(curl -s https://$user:$key@$fqdn:$port/api/v2$traffic_flows_query_href)
                    echo "$traffic_flows_query_curl_response" >> "$BASEDIR/$LOGFILE"
                    traffic_flows_query_status=$(echo "$traffic_flows_query_curl_response" | jq -r .status)
                done
                traffic_flows_query_results=$(curl -s https://$user:$key@$fqdn:$port/api/v2$traffic_flows_query_href/download -H 'Accept:application/json')
                echo "$traffic_flows_query_results" >> "$BASEDIR/$LOGFILE"
                #if no traffic flow results, add application label
                if [[ $traffic_flows_query_results == "[]" ]]; then
                    #do a 90 day query
                    body_90day='{"sources":{"include":[[]],"exclude":[]},"destinations":{"include":[[{"label":{"href":"'$env_label_href'"}},{"label":{"href":"'$unique_app_label_href'"}}]],"exclude":['$transmission']},"services":{"include":'$service_ports',"exclude":[]},"sources_destinations_query_op":"and","start_date":"'$days_ago_89'","end_date":"'$now'","policy_decisions":["allowed","potentially_blocked","unknown"],"boundary_decisions":[],"query_name":"","exclude_workloads_from_ip_list_query":false,"max_results":1}'
                    traffic_flows_query_90day_curl_post_response=$(curl -s https://$user:$key@$fqdn:$port/api/v2/orgs/$org/traffic_flows/async_queries -X POST -H 'content-type:application/json' --data-raw $body_90day)
                    echo "$traffic_flows_query_90day_curl_post_response" >> "$BASEDIR/$LOGFILE"
                    traffic_flows_query_href_90day=$(echo "$traffic_flows_query_90day_curl_post_response" | jq -r .href)
                    traffic_flows_query_status_90day=""
                    while [[ $traffic_flows_query_status_90day != "completed" ]]; do
                        sleep 30
                        traffic_flows_query_90day_curl_response=$(curl -s https://$user:$key@$fqdn:$port/api/v2$traffic_flows_query_href_90day)
                        echo "$traffic_flows_query_90day_curl_response" >> "$BASEDIR/$LOGFILE"
                        traffic_flows_query_status_90day=$(echo "$traffic_flows_query_90day_curl_response" | jq -r .status)
                    done
                    traffic_flows_query_results_90day=$(curl -s https://$user:$key@$fqdn:$port/api/v2$traffic_flows_query_href_90day/download -H 'Accept:application/json')
                    echo "$traffic_flows_query_results_90day" >> "$BASEDIR/$LOGFILE"
                    if [[ $traffic_flows_query_results_90day == "[]" ]]; then
                        apps_with_no_traffic_flows+=($unique_app_label_href)
                    fi
                fi
            done
            if [[ -z $apps_with_no_traffic_flows ]]; then continue; fi
            #update apps label href array
            rule_set_app_hrefs='['
            for app_with_no_traffic_flows in "${apps_with_no_traffic_flows[@]}"; do
                rule_set_app_hrefs+='{"label":{"href":"'$app_with_no_traffic_flows'"}},'
            done
            #rule_set_app_hrefs=${rule_set_app_hrefs::-1}
            #rule_set_app_hrefs=$(echo "$rule_set_app_hrefs" | sed 's/.$//')
            rule_set_app_hrefs+='{"label":{"href":"'$env_label_href'"}}'
            rule_set_app_hrefs+=']'
            #create deny rule
            deny_rules=$(curl -s https://$user:$key@$fqdn:$port/api/v2$rule_set_href/deny_rules -X POST -H 'content-type: application/json' --data-raw '{"providers":'$rule_set_app_hrefs',"consumers":[{"ip_list":{"href":"'$any_ip_list_href'"}}],"enabled":true,"ingress_services":[{"href":"'$ransomware_service_href'"}],"egress_services":[],"network_type":"brn","description":""}')
            echo "$deny_rules" >> "$BASEDIR/$LOGFILE"
        done
    done
    echo "Done."
}

log_clean_up(){
    date >> "$BASEDIR/$LOGFILE"
    tail -n 20000 "$BASEDIR/$LOGFILE" > "$BASEDIR/$LOGFILE.tmp" && mv "$BASEDIR/$LOGFILE.tmp" "$BASEDIR/$LOGFILE"
}

set_transmission(){
    #if both broadcast and multicast variables are not empty
    if [[ -n "$broadcast" && -n "$multicast" ]]; then
        transmission='{"transmission":"broadcast"},{"transmission":"multicast"}'
    #if broadcast variable is not empty
    elif [[ -n "$broadcast" ]]; then
        transmission=$broadcast
    #if multicast variable is not empty
    elif [[ -n "$multicast" ]]; then
        transmission=$multicast
    #if both broadcast and multicast variables are empty
    else
        transmission=''
    fi
}

get_version(){
    echo "auto-deny-rules v"$version
}

LOGFILE="auto-deny-rules.log"
BASEDIR=$(dirname -- $0)

#init variables
include_labels=""
exclude_labels=""

get_jq_version

get_illumio_config

log_clean_up

while true
do
    if [ "$1" == "" ]; then
        break
    fi
    case $1 in
        -b|--exclude-broadcast)
            broadcast='{"transmission":"broadcast"}'
            shift
            ;;
        -m|--exclude-multicast)
            multicast='{"transmission":"multicast"}'
            shift
            ;;
        -i|--include)
            shift
            include_labels="$1"
            shift
            ;;
        -e|--exclude)
            shift
            exclude_labels="$1"
            shift
            ;;
        -v|--version)
            get_version
            exit 0
            ;;
        -h|--help)
            usage
            exit 1
            ;;
        -*)
            echo -e "\n$0: ERROR: Unknown option: $1" >&2
            usage
            exit 1
            ;;
        *)
            echo -e "\n$0: ERROR: Unknown argument: $1" >&2
            usage
            exit 1
            ;;
    esac
done

set_transmission

create_deny_rules

exit 0
