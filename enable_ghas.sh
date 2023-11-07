#! /usr/bin/env bash

# This script iterates through a list of repos running the ghas-cli commands to enable GHAS on a repo in the tyler-technologies Github org
# No inputs are required other than the REPOS_LIST file being list of repos one per line in the file.

ORG="tyler-technologies"
REPO_LIST=$1
NO_CODEQL=$2
AUTO_PR=$3
OVERRIDE_CODEQL_TEMPLATE=$4

IFS=$'\n' read -d '' -r -a REPOS < $REPO_LIST

for i in ${REPOS[@]}; do
  echo $i
  REPO_SLUG=$i
  PUSH_PROTECTION="True"
  echo ----------------------------------------
  echo ORG:             $ORG
  echo REPO:            $REPO_SLUG
  echo NO_CODEQL:       $NO_CODEQL
  echo AUTO_PR:         $AUTO_PR
  echo OVERRIDE:        $OVERRIDE_CODEQL_TEMPLATE
  #echo TOKEN:           $GITHUB_TOKEN
  #echo PUSH_PROTECTION: $PUSH_PROTECTION

  ## WORKS
  echo enable actions
  ghas-cli actions set_permissions -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG -e True -a all

  ## WORKS
  echo enable dependabot+dependency reviewer
  ghas-cli repositories create_dep_enforcement_pr -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG -b "appsec-ghas-dep-enforcement-pr-${REPO_SLUG}"
  ghas-cli repositories enable_dependabot -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG
  ghas-cli issues create -n "GHAS: About Dependabot" -r $REPO_SLUG -o $ORG -t $GITHUB_TOKEN ./templates/dependabot.md

  if [ "${PUSH_PROTECTION}" == "True" ]
  then
    ## WORKS
    echo deploy secret scanner with push proections and create informative issue
    ghas-cli repositories enable_ss_protection -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG
    ghas-cli issues create -n "GHAS: About Secret Push Protection" -r $REPO_SLUG -o $ORG -t $GITHUB_TOKEN ./templates/secret_scanner_push_protection.md
    ##read varname
  else
    ## WORKS
    echo enable secret scanner and create informative issue
    ghas-cli repositories enable_ss -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG
    ghas-cli issues create -n "GHAS: About Secret Scanner" -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG  ./templates/secret_scanner.md
  fi

  if [ "${NO_CODEQL}" != "True" ]
  then
    echo deploy codeql and create an educational issue
    if [ "${OVERRIDE_CODEQL_TEMPLATE}" == "True" ]
    then
      ghas-cli repositories create_codeql_pr -o $ORG -t $GITHUB_TOKEN -b "appsec-ghas-codeql_enable-${REPO_SLUG}" -r $REPO_SLUG -e "True"
    else
      ghas-cli repositories create_codeql_pr -o $ORG -t $GITHUB_TOKEN -b "appsec-ghas-codeql_enable-${REPO_SLUG}" -r $REPO_SLUG
    fi
    ghas-cli issues create -n "GHAS: About Security code scanning" -r $REPO_SLUG -o $ORG -t $GITHUB_TOKEN ./templates/codeql.md
  else
      echo "Skipping codeql creation"
  fi

#  read -p 'Proceed (y|n)?' selection

#  if [ $selection != 'y' ] && [ $selection != 'Y' ]
#  then
#    exit 0
#  fi

   SECONDS=240
   echo
   echo [[ sleeping for $SECONDS seconds ]]
   echo
   sleep $SECONDS
done

