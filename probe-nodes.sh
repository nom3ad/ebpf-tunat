#!/usr/bin/env bash

function log() {
    msg="[$(date)] $*"
    if [[ -t 2 || $FORCE_COLOR ]]; then
        case $1 in
        ERROR) msg="\e[31m$msg\e[0m" ;;
        WARN) msg="\e[33m$msg\e[0m" ;;
        INFO) msg="\e[36m$msg\e[0m" ;;
        OK) msg="\e[32m$msg\e[0m" ;;
        esac
    fi
    echo -e " $msg" >&2
}


tunat_bin="./dist/tunat"

agent_ssh_private_key=~/.ssh/jenkins-nodes.pem

agent_ssh_user=ec2-user

prob_script='
    # set -x
    # ec2-metadata -o | awk "{print \$2}"
    docker ps --filter="label=tunat.target" -q | xargs --no-run-if-empty docker inspect --format "{{index .Config.Labels \"tunat.target\"}}" |xargs
'

region=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)
log "Region: $region"

function probe() {
    # List instances' ID and private IP address in an associated URI
    local result
    result=$(aws ec2 --region "$region" describe-instances --filters "Name=tag:Environment,Values=JENKINS" "Name=tag:Name,Values=*Agent*" "Name=instance-state-name,Values=running" \
        --query "Reservations[].Instances[].[InstanceId, PrivateIpAddress, PublicIpAddress,Tags[?Key=='Name'].Value|[0] ]" --output text | tee /dev/stderr)
   
    if [[ -z "$result" ]]; then
        log WARN "No instances found"
        return 0
    fi

    readarray -t result <<<"$result"

    local -a mapping=()
    for line in "${result[@]}"; do
        read -r instance_id private_ip public_ip _ <<<"$line"
        log "Probing $instance_id ($private_ip)"
        
        if ! ping -c 1 -W 1 "$private_ip" &>/dev/null; then
            log ERROR "PING: Instance $instance_id ($private_ip) is not reachable"
            continue
        fi

        local targets
        if ! targets=$(ssh -i "$agent_ssh_private_key" -o StrictHostKeyChecking=no -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
            "$agent_ssh_user@$private_ip" "$prob_script"); then
            log ERROR "Failed to probe $instance_id ($private_ip)"
            continue
        fi
        if [[ -z "$targets" ]]; then
            log WARN "Probed $instance_id ($private_ip): No targets"
            continue
        fi
        log OK "Probed $instance_id ($private_ip): targets=$targets"

        for target in $targets; do
            mapping+=("$target:$private_ip/$target")
        done
    done
    if [[ ${#mapping[@]} -eq 0 ]]; then
       log WARN "No mapping to update"
    fi
    log "Mapping: ${mapping[*]}"
    set -x
    sudo $tunat_bin update -i eth0 "${mapping[@]}" || log ERROR "Failed to update mapping"
    set +x
}

sleep_time=60s
while true; do
    probe || log ERROR "Probe failed"
    log INFO "Sleeping for $sleep_time"
    sleep $sleep_time
done
