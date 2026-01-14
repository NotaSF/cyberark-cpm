Okta:
Create application > API Services
Set Client authentication from 'Client secret' to 'Public key / Private key'
Set scope for application to just 'okta.users.manage'
Create admin role that only has the 'Manage Users' permission
Create resource group that only has the users you want it to manage (i.e. create an Okta group called 'localaccounts', with members being your users)
Assign admin role within the resource scope for that group.
Export the private key as a file (example: okta.pem)
Run pem-to-pfx.ps1 - password for the pfx is optional.


CyberArk:
TPC plugin (should be already included)
powershell 7 installed on your CPM
Rest of info TBD until I can get into my lab


Something something here's how it should be stored in CyberArk-
account you want to manage:
username - username
address - oktadomain.okta.com (or .oktapreview.com)
password - you can put the current password here but you really don't need to once you get it to reconcile

create a separate reconcile account on a different platform which contains the application/api service's secrets-
username - client_id
password - somehow get the PFX in there as a single line (is this even possible lol)
-actually try to do the base64pfx output followed by :: as a delimiter

link the reconcile account to the account you want to manage

you can convert the pfx to a base64 string by doing this:

$pfxBytes = [IO.File]::ReadAllBytes("C:\path\to\okta.pfx")
$base64   = [Convert]::ToBase64String($pfxBytes)

"$base64::"


How do i use this?
-ok so first you want to test this probably right?

first make sure you have your token generation working with dpop - use okta-token-test-dpop-nonce-v2.ps1:
pwsh .\okta-token-test-dpop-nonce-v2.ps1 -OktaDomain "domain@okta.com" -ClientId "ClientID goes here" -PfxPath "C:\path\to\okta.pfx" -Scope "okta.users.manage"

should return something like this:
OK: access token acquired (DPoP + nonce).
token_type: DPoP
expires_in: 3600

If it does, cool. now try to set the password for the account - use okta-set-password-dpop.ps1:
pwsh .\okta-set-password-dpop.ps1 -OktaDomain "domain@okta.com" -ClientId "ClientID goes here" -PfxPath "C:\path\to\okta.pfx" -Scope "okta.users.manage" -UserLogin "usertobemanaged@domain.com" -NewPassword "just put a random password here that aligns with your organization's policies"

You should see the following if successful:
Getting DPoP access token...
Resolving user id for usertobemanaged@domain.com...
Setting password for userId useridwow...
OK: password set for usertobemanaged@domain.com


OK now you want to test it using base64 stuff huh big champ? be careful is all i can say because idk how to put that in safely.


Soooo finally, you know what Okta-Reconcile.ps1 can do. But how do i use it you ask!!!
effectively you will tell the TPC something like this equivalent (double check this when you get your damn lab online nota ffs)
pwsh.exe -NoProfile -ExecutionPolicy Bypass -File "C:\path\to\Okta-Reconcile.ps1" -OktaDomain "account address" -ManagedLogin "account username" -NewPassword  "generated pw" -ClientId "reconcile username" -PfxBundle "reconcile password"

Might need some line breaks or something i really dont know the character limits of powershell lines and the effects on parsing



SO YOU REALLY WANNA TEST THIS ONE LAST TIME HUH CHAMP???

ok go for it:

pwsh.exe Okta-Reconcile.ps1 `
-OktaDomain https://poop.okta.com `
-ManagedLogin user@poop.com `
-NewPassword "hey-this-is-a-password-you-really-shouldnt-use-for-obvious-reasons"
-ClientId "put ur client id here" `
-PfxBundle "put your base64 pfx in here"
