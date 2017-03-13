# le_server.py is the high level command that uses dehydrated.sh client in order
# to validate ownership and control over a given domain name. It is executed
# with a timeout in case any of these steps hangs.

# This script is used by dehydrated.sh during dialog with LetsEncrypt servers
# to execute and validate the required challenge.

# This script was modified from the dehydrated hook for google cloud example
# taken from https://github.com/spfguru/dehydrated4googlecloud.

if [ "$CIRCLE_CI" == "True" ]
then
    echo "Domain and Zone should be set by Circle CI: $DNS_DOMAIN and $ZONE_NAME"
    GCLOUD="sudo /opt/google-cloud-sdk/bin/gcloud"
elif [ "$PROD" == 'True' ]
then
    echo "Domain and Zone should be set by Heroku: $DNS_DOMAIN and $ZONE_NAME"
    GCLOUD="gcloud"
else
    source $(dirname $0)/../credentials.sh
    GCLOUD="gcloud"
fi

function deploy_challenge {
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
    local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

    start=`date +%s`
    random_number=$(( ( RANDOM % 999999999 )  + 1 ))
    transaction_file="--transaction-file=transaction$random_number.yaml"

    echo;
    echo "Deploying challenge for domain $DOMAIN"
    echo "DNS_DOMAIN: $DNS_DOMAIN on ZONE_NAME: $ZONE_NAME"

    function transaction_add {
        $GCLOUD dns record-sets transaction start $transaction_file --zone $ZONE_NAME
        $GCLOUD dns record-sets transaction add $transaction_file --name "_acme-challenge.$DOMAIN." --ttl 300 --type TXT "$TOKEN_VALUE" --zone $ZONE_NAME
        $GCLOUD dns record-sets transaction describe $transaction_file --zone $ZONE_NAME
    }

    transaction_add
    changeID=$($GCLOUD dns record-sets transaction execute $transaction_file --zone $ZONE_NAME  --format='value(id)')

    until [[ ! -z "$changeID" ]]; do
        $GCLOUD dns record-sets transaction abort $transaction_file --zone $ZONE_NAME
        transaction_add
        changeID=$($GCLOUD dns record-sets transaction execute $transaction_file --zone $ZONE_NAME  --format='value(id)')
        sleep 3
        echo -n "..."
    done
    echo "Got change ID."

    until [[ "$status" = "done" ]]; do
        echo -n "$status"
        sleep 3
        echo -n "..."
        status=$($GCLOUD dns record-sets changes describe $changeID --zone $ZONE_NAME  --format='value(status)')
    done
    echo "Change implemented in records."

    # Even if the transaction is executed, the results may not be available in the DNS servers yet
    echo "Verifying results on live DNS servers:"
    for nameserver in $(dig $DNS_DOMAIN NS +short); do
        echo -n "$nameserver "
        nsresult=$(dig _acme-challenge.$DOMAIN TXT @$nameserver +short)
        # nsresult comes with the TXT RR in double quotes - remove those
        nsresult=${nsresult//$'"'/''}
        until [[ "$nsresult" = "$TOKEN_VALUE" ]]; do
            echo -n "pending"
            sleep 3
            echo -n "..."
            nsresult=$(dig _acme-challenge.$DOMAIN TXT @$nameserver +short)
            # nsresult comes with the TXT RR in double quotes - remove those
            # TODO DRY: move to dedicated function
            nsresult=${nsresult//$'"'/''}
        done
        echo "done"
    done
    # A small sleep time is required to eliminate intermittent "No TXT records found for DNS challenge" errors
    # TODO: https://github.com/plotly/le-bot/issues/4
    sleep 15
    end=`date +%s`
    runtime=$((end-start))
    rm -f transaction$random_number.yaml
    echo "TIMER: Challenge deployed within $runtime seconds."
}


function clean_challenge {
    local DOMAIN="${1}" TOKEN_FILENAME="${2}" TOKEN_VALUE="${3}"

    echo;
    echo "Cleaning challenge for domain $DOMAIN"
    # This hook is called after attempting to validate each domain,
    # whether or not validation was successful. Here you can delete
    # files or DNS records that are no longer needed.
    #
    # The parameters are the same as for deploy_challenge.
    start=`date +%s`
    random_number=$(( ( RANDOM % 999999999 )  + 1 ))
    transaction_file="--transaction-file=transaction$random_number.yaml"

    $GCLOUD dns record-sets transaction start $transaction_file --zone $ZONE_NAME
    existingRecord=`$GCLOUD dns record-sets list --name "_acme-challenge.$DOMAIN." --type TXT --zone $ZONE_NAME  --format='value(name,rrdatas[0],ttl)'`
    existingRecord=${existingRecord//$'\t'/,}
    echo "existing record ... ${existingRecord}"
    IFS=',' read -r -a splitRecord <<< "$existingRecord"
    echo "splitRecord ... ${splitRecord}"
    echo "name ... ${splitRecord[0]}"
    echo "rrdata ... ${splitRecord[1]}"
    echo "ttl ... ${splitRecord[2]}"

    $GCLOUD dns record-sets transaction remove $transaction_file "${splitRecord[1]}" --name ${splitRecord[0]} --type TXT --ttl ${splitRecord[2]} --zone $ZONE_NAME
    changeID=$($GCLOUD dns record-sets transaction execute $transaction_file --zone $ZONE_NAME)

    until [[ ! -z "$changeID" ]]; do
        $GCLOUD dns record-sets transaction abort $transaction_file --zone $ZONE_NAME
        $GCLOUD dns record-sets transaction start $transaction_file --zone $ZONE_NAME
        $GCLOUD dns record-sets transaction remove $transaction_file "${splitRecord[1]}" --name ${splitRecord[0]} --type TXT --ttl ${splitRecord[2]} --zone $ZONE_NAME
        changeID=$($GCLOUD dns record-sets transaction execute $transaction_file --zone $ZONE_NAME)
        sleep 3
        echo -n "..."
    done
    echo "Got change ID."

    rm -rf transaction$random_number.yaml

}


function deploy_cert {
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

function unchanged_cert {
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
    local DOMAIN="${1}" KEYFILE="${2}" CERTFILE="${3}" FULLCHAINFILE="${4}" CHAINFILE="${5}"

    echo "Certificate for domain $DOMAIN is still valid - no action taken"
}

HANDLER=$1; shift; $HANDLER $@
