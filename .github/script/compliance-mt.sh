#!/bin/bash
#########################
# Determine Environment #
#########################

# Override
GITHUB_BASE_REF="${GITHUB_BASE_REF:=environment_at}"
#GITHUB_BASE_REF=environment_at

if   [[ ${GITHUB_BASE_REF} == environment_at ]]; then
	     NAMESPACE_PREFIX="at-"
         NETWORKPOLICY_LABEL="networkpolicy.at.cetemp.com"
elif [[ ${GITHUB_BASE_REF} == environment_test ]]; then
         NAMESPACE_PREFIX="test-"
         NETWORKPOLICY_LABEL="networkpolicy.at.cetemp.com"
elif [[ ${GITHUB_BASE_REF} == environment_prod ]]; then
         NETWORKPOLICY_LABEL="networkpolicy.ads.cetemp.com"
fi


# ArgoCD Applications Folder
ARGOCDFOLDER=_argocd-applications

# Filename for infra configuration
INFRA_FILE_NAME=01_infra.yaml

# Filename for ArgoCD Application Config
ARGOCD_APP_FILE_NAME=application.yaml

##############################
# Determine Environment DONE #
##############################

#############################
#   EXCLUDE APPS VARIABLE   #
#############################

# Exclude apps for testing. Add folder name from _argocd-applications/applications/$app/application.yaml

EXCLUDEDAPPS=(
at-activemq-jdbc
    )

EXCLUDEDAPPS_OUTPUT=$(echo ${EXCLUDEDAPPS[@]}|tr " " "|")

##############################
#        BEGIN TESTING       #
##############################

envFiles=$(find * -name $INFRA_FILE_NAME | grep -v "_argocd-applications")

#
# Only applications that are synced with argocd will be tested. This includes all files inside ./$ARGOCDFOLDER/applications/
#

ARGO_APPS=$(ls ./$ARGOCDFOLDER/applications/ | grep -Ev "$EXCLUDEDAPPS_OUTPUT"); for argoapp in $ARGO_APPS; do yq r $argoapp "spec.source.path"; done > /dev/null 2>&1

# Check if 01_infra.yaml exist in enabled sync folders
for folder in $ARGO_APPS; do
    files=`ls $folder/`
        if [[ $files != *"$INFRA_FILE_NAME"* ]]; then echo "folder "$folder" does not contain $INFRA_FILE_NAME"; exitCodeInfraFileExist=1; fi
    done

if [[ $exitCodeInfraFileExist -eq 1 ]]; then exit 1;fi

# Require filename application.yaml for argocd definitions
for argoapp in $ARGO_APPS; do
    argofiles=$(ls $ARGOCDFOLDER/applications/$argoapp/)
    for argofile in $argofiles; do if [[ $argofile != $ARGOCD_APP_FILE_NAME ]]; then
        echo -e "ArgoCD Applicaton file must be named $ARGOCD_APP_FILE_NAME.\nPlease rename the following file to $ARGOCD_APP_FILE_NAME: $ARGOCDFOLDER/applications/$argoapp/$argofile.\nIf you have multiple files in $ARGOCDFOLDER/applications/$argoapp/, please consider merging these files into one with yaml separator ---"
        exitCodeArgoCDAppFileName=1
    fi
    done
done

 if [[ $exitCodeArgoCDAppFileName -eq 1 ]]; then exit 1;fi

# API's that must be present
checkApiKinds=(
Namespace
EgressNetworkPolicy
NetworkPolicy
)

# Check That API Object exist
for argoapp in $ARGO_APPS; do
    for kind in ${checkApiKinds[@]}; do
        if ! grep -q "$kind" "$argoapp/$INFRA_FILE_NAME"; then
            echo "Required API $kind does not exist in file $argoapp/$INFRA_FILE_NAME"
            exitCodeAPIObject=1
            fi
        if  checkOnlyInInfraFile=$(grep -rn --exclude=$INFRA_FILE_NAME "$kind" $argoapp/); then
            echo "Please move $kind api definition into the $argoapp/$INFRA_FILE_NAME"
            echo DEBUG: $checkOnlyInInfraFile
            exitCodeOnlyInInfraFile=1
        fi

        done
    done

if [[ $exitCodeAPIObject || $exitCodeOnlyInInfraFile -eq 1 ]]; then exit 1;fi

# checkApiKinds should only be defined in $INFRA_FILE_NAME


# Check Namespace & ArgocdName

### Check for duplicate namespace names

for argoapp in $ARGO_APPS; do nsname=$(yq r -d0 $argoapp/$INFRA_FILE_NAME metadata.name); nsnames+=($nsname); done
printf '%s\n' "${nsnames[@]}" > /tmp/nsnames
output=`sort /tmp/nsnames | uniq -d`
if [[ -z $output ]]; then :
else echo "Namespace $output does already exist"; exit 1
fi

### Check for prefix in namespace and argocd application
for argoapp in $ARGO_APPS; do
	nsname=$(yq r -d0 $argoapp/$INFRA_FILE_NAME metadata.name)
    if ! [[ $nsname == $NAMESPACE_PREFIX* ]]; then echo "Namespace $nsname does not have reqiured name prefix: $NAMESPACE_PREFIX"
		 exitCodeNamespacePrefix=1
    fi
    argoname=$(yq r -d0 $ARGOCDFOLDER/applications/$argoapp/$ARGOCD_APP_FILE_NAME metadata.name)
    if ! [[ $argoname == $NAMESPACE_PREFIX* ]]; then echo -e "ArgoCD application name $argoname does not have reqiured name prefix: $NAMESPACE_PREFIX\nCheck: $ARGOCDFOLDER/applications/$argoapp/$ARGOCD_APP_FILE_NAME"
         exitCodeArgocdnamePrefix=1
    fi

done

if [[ $exitCodeNamespacePrefix || $exitCodeArgocdnamePrefix -eq 1 ]]; then exit 1;fi

# Check if rolebindings is present, there should only be three rolebindings

for argoapp in $ARGO_APPS; do countRoleBindings=`grep -e system:image-pullers -e system:image-builders -e system:deployers $argoapp/$INFRA_FILE_NAME | wc -l`; if [[ "$countRoleBindings" != 3 ]]; then echo "$argoapp/$INFRA_FILE_NAME is missing one or more required rolebindings: system:image-pullers, system:image-builders, system:deployers";exit 1;fi; done

# Check EgressNetworkPolicy - Check if default deny rule is present

for argoapp in $ARGO_APPS; do
    infraFileContent=$(<$argoapp/$INFRA_FILE_NAME)
    read -r -d '' egress_deny_rule  << EOF
    - to:
        cidrSelector: 0.0.0.0/0
      type: Deny
EOF

    if ! [[ "$infraFileContent" == *"$egress_deny_rule"* ]]; then
           exitCode_egress_deny_rule=1
           echo "$argoapp/$INFRA_FILE_NAME does not contain egress_deny_rule networkpolicy:"; echo "$egress_deny_rule"
    fi
done
if [[ $exitCode_egress_deny_rule -eq 1 ]]; then exit 1;fi

# Check NetworkPolicy

## allow_from_same_namespace
for argoapp in $ARGO_APPS; do
    nsname=$(yq r -d0 $argoapp/$INFRA_FILE_NAME metadata.name)
    infraFileContent=$(<$argoapp/$INFRA_FILE_NAME)
    read -r -d '' allow_from_same_namespace  << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-same-namespace
  namespace: $nsname
spec:
  ingress:
  - from:
    - podSelector: {}
  podSelector: null
EOF
    if ! [[ "$infraFileContent" == *"$allow_from_same_namespace"* ]]; then
        exitCode_allow_from_same_namespace=1
        echo "$argoapp/$INFRA_FILE_NAME does not contain allow-from-same-namespace networkpolicy:"; echo "$allow_from_same_namespace"
    fi
done
if [[ $exitCode_allow_from_same_namespace -eq 1 ]]; then exit 1;fi

## allow-from-label-access-to-all-namespaces

for argoapp in $ARGO_APPS; do
    nsname=$(yq r -d0 $argoapp/$INFRA_FILE_NAME metadata.name)
    infraFileContent=$(<$argoapp/$INFRA_FILE_NAME)
    read -r -d '' allow_from_label_access_to_all_namespaces  << EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-from-label-access-to-all-namespaces
  namespace: $nsname
spec:
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          $NETWORKPOLICY_LABEL/access-to-all-namespaces: enabled
  podSelector: null
EOF
       if ! [[ "$infraFileContent" == *"$allow_from_label_access_to_all_namespaces"* ]]; then
           exitCode_allow_from_label_access_to_all_namespaces=1
           echo "$argoapp/$INFRA_FILE_NAME does not contain allow_from_label_access_to_all_namespaces networkpolicy:"; echo "$allow_from_label_access_to_all_namespaces"
       fi
done
   if [[ $exitCode_allow_from_label_access_to_all_namespace -eq 1 ]]; then exit 1;fi
