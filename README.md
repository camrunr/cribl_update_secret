This script allows you to update secrets in Cribl via the API. As of this first release, it only applies to a username/password style secret. Secrets are found under Group Settings -> Security -> Secrets.

Usage:   
    `cribl_update_secret.py [-h] [-D] -l LEADER -g GROUP -s SECRETID -S SECRETVALUE -u USERNAME [-P PASSWORD]`

* Leader: The full URL to your Leader node, eg https://leadherhost:9000
* Group: The name of the Worker Group you are targeting
* SecretID: The name of the secret we want to update the password for
* SecretValue: The value to replace in the secret password
* Username: The username to get into Cribl. If you're a Cribl Cloud user, this is the Client ID from the API Management page
* Password: This is optional. If you leave it out, you will be prompted for it. If you're a Cloud user, this is the Client Secret from the API Management page
* DEBUG: The -D flag will output verbose info on the progress

The process:

* Get a bearer token for auth
* Via a PATCH call, update the secret
* Via a PATCH call, commit the change for this single change
* Via a PATCH call, deploy this single committed change

Improvements needed:

* Support other than username/password types of secrets
