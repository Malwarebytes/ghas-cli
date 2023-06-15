

ORG=$1
REPO_SLUG=$2
PUSH_PROTECTION=$3

echo ORG:             $ORG
echo REPO:            $REPO_SLUG
echo TOKEN:           $GITHUB_TOKEN
echo PUSH_PROTECTION: $PUSH_PROTECTION

## WORKS
echo enable actions
ghas-cli actions set_permissions -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG -e True -a selected

## WORKS
echo enable dependabot+dependency reviewer
ghas-cli repositories create_dep_enforcement_pr -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG
ghas-cli repositories enable_dependabot -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG
ghas-cli issues create -n "About Dependabot" -r $REPO_SLUG -o $ORG -t $GITHUB_TOKEN ./templates/dependabot.md

if [ "${PUSH_PROTECTION}" == "True" ]
then  
  ## WORKS
  echo deploy secret scanner push proections and create informative issue
  ghas-cli repositories enable_ss_protection -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG
  ghas-cli issues create -n "About Secret Push Protection" -r $REPO_SLUG -o $ORG -t $GITHUB_TOKEN ./templates/secret_scanner_push_protection.md
  #read varname
else  
  ## WORKS
  echo enable secret scanner and create informative issue
  ghas-cli repositories enable_ss -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG
  ghas-cli issues create -n "About Secret Scanner" -o $ORG -t $GITHUB_TOKEN -r $REPO_SLUG  ./templates/secret_scanner.md
fi

echo deploy codeql and create an educational issue
ghas-cli repositories create_codeql_pr -o $ORG -t $GITHUB_TOKEN -b "appsec-ghas-codeql_enable" -r $REPO_SLUG
ghas-cli issues create -n "About Security code scanning" -r $REPO_SLUG -o $ORG -t $GITHUB_TOKEN ./templates/codeql.md
