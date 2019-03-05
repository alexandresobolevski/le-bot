#!/bin/bash

set -xeo pipefail

# le_server.py is the high level command that uses dehydrated.sh client in order
# to validate ownership and control over a given domain name. It is executed
# with a timeout in case any of these steps hangs.

# This script is used by dehydrated.sh during dialog with LetsEncrypt servers
# to execute and validate the required challenge.

# This script was modified from the dehydrated hook for google cloud example
# taken from https://github.com/spfguru/dehydrated4googlecloud.

if [[ "$CIRCLE_CI" == "True" ]] ; then
    echo "Domain and Zone set by Circle CI: $DNS_DOMAIN and $ZONE_NAME"
    GCLOUD="sudo /opt/google-cloud-sdk/bin/gcloud"
elif [[ "$PROD" == 'True' ]] ; then
    echo "Domain and Zone set by environment: $DNS_DOMAIN and $ZONE_NAME"
    GCLOUD="gcloud"
else
    source "$(dirname "$0")"/../credentials.sh
    GCLOUD="gcloud"
fi

function expbackoff() {
    # Exponential backoff: retries a command upon failure, scaling up the delay
    # Example: "expbackoff my_command --with --some --args --maybe"
    local MAX_RETRIES="${EXPBACKOFF_MAX_RETRIES:-10}" # Max number of retries
    local BASE="${EXPBACKOFF_BASE:-1}" # Base value for backoff calculation
    local MAX="${EXPBACKOFF_MAX:-30}" # Max value for backoff calculation
    local FAILURES=0
    while ! "$@"; do
        FAILURES=$(( FAILURES + 1 ))
        if (( FAILURES > MAX_RETRIES )); then
            echo "$@" >&2
            echo " * Failed, max retries exceeded" >&2
            return 1
        else
            local SECONDS=$(( BASE * 2 ** (FAILURES - 1) ))
            if (( SECONDS > MAX )); then
                SECONDS="$MAX"
            fi
            sleep "$SECONDS"
            echo
        fi
    done
}

function deploy_challenge() {
    # This hook is called once for every domain that needs to be
    # validated, including any alternative names you may have listed.
    #
    # Parameters:
    # - DOMAIN
    #   The domain name (CN or subject alternative name) being
    #   validated.
    # - TOKEN_FILENAME
    #   The name of the file is irrelevant for the DNS challenge, yet still provided
    # - TOKEN_VALUE
    #   The token value that needs to be served for validation. For DNS
    #   validation, this is what you want to put in the _acme-challenge
    #   TXT record. For HTTP validation it is the value that is expected
    #   be found in the $TOKEN_FILENAME file.
    local DOMAIN="${1}" TOKEN_VALUE="${3}" #TOKEN_FILENAME="${2}"

    start=$(date +%s)
    transaction_dir=`mktemp -d`
    transaction_file_arg="--transaction-file=$transaction_dir/transaction.json"

    echo;
    echo "Deploying challenge for domain $DOMAIN"
    echo "DNS_DOMAIN: $DNS_DOMAIN on ZONE_NAME: $ZONE_NAME"

    function add_challenge_to_dns() {
        # Adds the challenge DNS record using gcloud.  Sets $changeID on
        # success, returns 1 on failure.

        $GCLOUD dns record-sets transaction start "$transaction_file_arg" --zone "$ZONE_NAME"
        $GCLOUD dns record-sets transaction add "$transaction_file_arg" --name "_acme-challenge.$DOMAIN." --ttl 300 --type TXT "$TOKEN_VALUE" --zone "$ZONE_NAME"
        $GCLOUD dns record-sets transaction describe "$transaction_file_arg" --zone "$ZONE_NAME"

        changeID=$($GCLOUD dns record-sets transaction execute "$transaction_file_arg" --zone "$ZONE_NAME"  --format='value(id)')

        if [[ -z "$changeID" ]]; then
             $GCLOUD dns record-sets transaction abort $transaction_file_arg --zone "$ZONE_NAME"
             return 1
        fi
    }

    if ! expbackoff add_challenge_to_dns ; then
        echo "Could not add challenge to DNS. Aborting."
        rm -r "$transaction_dir" || true
        exit 1
    fi

    rm -r "$transaction_dir" || true
    echo "Got change ID."

    function check_challenge_with_gcloud() {
        # Checks that the challenge has successfully been added using the
        # "gcloud" command.  Returns 1 on failure.

        status=$($GCLOUD dns record-sets changes describe "$changeID" --zone "$ZONE_NAME"  --format='value(status)')
        echo -n "${status}..."

        if [[ "$status" != "done" ]]; then
            return 1
        fi
    }

    echo "Checking challenge using gcloud: "
    if ! expbackoff check_challenge_with_gcloud ; then
        echo "FAILED, aborting."
        exit 1
    fi

    echo "Change implemented in records."

    # Even if the transaction is executed, the results may not be available in the DNS servers yet

    function check_challenge_with_nameserver() {
        # Checks that the challenge has successfully been added with $nameserver.
        # Returns 1 on failure.

        nsresult=$(dig "_acme-challenge.$DOMAIN" TXT @"$nameserver" +short)
        # nsresult comes with the TXT RR in double quotes - remove those
        nsresult=${nsresult//$'"'/''}

        if [[ "$nsresult" != "$TOKEN_VALUE" ]]; then
            echo -n "pending..."
            return 1
        fi
    }

    echo "Verifying results on live DNS servers:"
    for nameserver in $(dig "$DNS_DOMAIN" NS +short); do
        echo -n "$nameserver "

        if ! expbackoff check_challenge_with_nameserver ; then
            echo "FAILED, aborting."
            exit 1
        fi

        echo "done"
    done

    # A small sleep time is required to eliminate intermittent "No TXT records found for DNS challenge" errors
    # TODO: https://github.com/plotly/le-bot/issues/4
    sleep 15
    end=$(date +%s)
    runtime=$((end-start))
    rm -r "transaction_dir" || true
    echo "TIMER: Challenge deployed within $runtime seconds."
}


function clean_challenge() {
    # This hook is called after attempting to validate each domain,
    # whether or not validation was successful. Here you can delete
    # files or DNS records that are no longer needed.
    #
    # The parameters are the same as for deploy_challenge.

    local DOMAIN="${1}" TOKEN_VALUE="${3}" #TOKEN_FILENAME="${2}"

    echo;
    echo "Cleaning challenge for domain $DOMAIN"
    start=$(date +%s)
    transaction_dir=`mktemp -d`
    transaction_file_arg="--transaction-file=$transaction_dir/transaction.json"

    existingRecord=$($GCLOUD dns record-sets list --name "_acme-challenge.$DOMAIN." --type TXT --zone "$ZONE_NAME"  --format='value(name,rrdatas[0],ttl)')
    existingRecord=${existingRecord//$'\t'/,}
    echo "existing record ... ${existingRecord}"
    IFS=',' read -r -a splitRecord <<< "$existingRecord"
    echo "splitRecord ... ${splitRecord}"
    echo "name ... ${splitRecord[0]}"
    echo "rrdata ... ${splitRecord[1]}"
    echo "ttl ... ${splitRecord[2]}"

    function remove_challenge_from_dns() {
        # Removes a challenge DNS record using gcloud. Returns 1 on failure.
        $GCLOUD dns record-sets transaction start "$transaction_file_arg" --zone "$ZONE_NAME"
        $GCLOUD dns record-sets transaction remove "$transaction_file_arg" "${splitRecord[1]}" --name "${splitRecord[0]}" --type TXT --ttl "${splitRecord[2]}" --zone "$ZONE_NAME"
        changeID=$($GCLOUD dns record-sets transaction execute "$transaction_file_arg" --zone "$ZONE_NAME")

        if [[ -z "$changeID" ]]; then
            $GCLOUD dns record-sets transaction abort "$transaction_file_arg" --zone "$ZONE_NAME"
            echo -n "..."
            return 1
        fi
    }

    EXPBACKOFF_MAX_RETRIES=20   # Try harder to cleanup
    if ! expbackoff remove_challenge_from_dns ; then
        echo "FAILED, aborting."
        rm -r "$transaction_dir" || true
        exit 1
    fi

    rm -r "$transaction_dir" || true
    echo "Got change ID."
}


function deploy_cert() {
    # This hook is called once for each certificate that has been
    # produced. Here you might, for instance, copy your new certificates
    # to service-specific locations and reload the service.
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
    # local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}"
    #
    # We do not require to deploy these certs thus this functions is kept empty.
    echo;
}

function unchanged_cert() {
    # This hook is called once for each certificate that is still valid at least 30 days
    #
    # Parameters:
    # - DOMAIN
    #   The primary domain name, i.e. the certificate common
    #   name (CN).
    # - KEYFILE
    #   The path of the file containing the private key.
    # - CERTFILE
    #   The path of the file containing the signed certificate.
    # - FULLCHAINFILE
    #   The path of the file containing the full certificate chain.
    # - CHAINFILE
    #   The path of the file containing the intermediate certificate(s).
    #local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}"

    echo "Certificate for domain $DOMAIN is still valid - no action taken"
}

function exit_hook() {
    exit 0
}

HANDLER="$1"; shift; "$HANDLER" "$@"
