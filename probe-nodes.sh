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

agent_ssh_private_key=~/.ssh/jenkins-nodes.pem

agent_ssh_user=ec2-user

prob_script='
    # set -x
    # ec2-metadata -o | awk "{print \$2}"
    docker ps --filter="label=tunat.target" -q | xargs docker inspect --format "{{index .Config.Labels \"tunat.target\"}}"
'

region=$(curl -s http://169.254.169.254/latest/dynamic/instance-identity/document | jq -r .region)
log "Region: $region"

function probe() {
    # List instances' ID and private IP address in an associated URI
    instances=$(aws ec2 --region "$region" describe-instances --filters "Name=tag:Environment,Values=JENKINS" "Name=tag:Name,Values=*Agent*" "Name=instance-state-name,Values=running" \
        --query "Reservations[].Instances[].[InstanceId, PrivateIpAddress]" --output text | tee /dev/stderr)

    if [[ -z "$instances" ]]; then
        log WARN "No instances found"
        exit 1
    fi
    while read -r instance_id private_ip; do
        log "Found $instance_id ($private_ip)"
        if ! ping -c 1 -W 1 "$private_ip" &>/dev/null; then
            log ERROR "Instance $instance_id ($private_ip) is not reachable"
            continue
        fi
        local result
        if result=$(ssh -i "$agent_ssh_private_key" -o StrictHostKeyChecking=no -o LogLevel=ERROR -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 \
            "$agent_ssh_user@$private_ip" "$prob_script"); then
            log OK "Probed $instance_id ($private_ip): $result"
        else
            log ERROR "Failed to probe $instance_id ($private_ip)"
        fi
    done <<<"$instances"
}

sleep_time=60s
while true; do
    probe || log ERROR "Probe failed"
    log INFO "Sleeping for $sleep_time"
    sleep $sleep_time
done
