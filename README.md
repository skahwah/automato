### automato.rb 

automato is one of the first programs I wrote after taking a ruby course. 

automato should help with automating some of the user-focused enumeration tasks during an internal penetration test.

automato is also capable of conducting limited brute force attacks such as:

- Testing to see if a list of users with a common password exists in the target domain
- Identifying if a domain user is a local administrator against machines in the target domain

automato will create outfiles automatically for evidence preservation. 

#### Usage

``` shell
skawa-mbp:automato $ ruby automato.rb 
Written by: Sanjiv Kawa
Twitter: @skawasec

Usage: ruby automato.rb [options]
Main Arguments:
    -d, --domain DOMAIN              The target domain.
    -u, --username USERNAME          A domain user account name.
    -p, --password PASSWORD          The password for the corresponding domain user account.
    -i, --ip DC_IP                   The IP address of a domain controller with RPC and LDAP listening.
Options:
    -a, --all                        Run a bulk of automato's features. Enumerate all domain groups, administrators, computers and user account attributes.
    -c, --domain-users               Get all domain users in the domain.
    -g, --groups                     Get all domain groups for the domain.
    -m, --member GROUP               List all users in a specified domain group. Make sure yo u escape spaces with a backslash!
    -t, --attributes                 Get the domain account attributes for all domain users.
    -b, --bad                        Get the bad password count for all domain users.
    -z, --du-hunter USER_FILE        Brute force a list of common usernames with a common password against the target domain.
    -l, --la-hunter IP_FILE          Test if a domain user is a local admin against a list of IP addresses with SMB listening in the target domain.
```
