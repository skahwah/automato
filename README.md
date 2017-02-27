### automato.rb 

automato should help with automating some of the user-focused enumeration tasks during an internal penetration test.

automato is also capable of conducting password guessing attacks, for example, testing to see if a list of users with a common password exists in the target domain

automato will create outfiles automatically for evidence preservation.

#### Usage
~~~ 
[17:43][skawa@skawa-mbp:automato] :] ruby automato.rb
automato.rb v2.0
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
    -m, --member GROUP               List all users in a specified domain group. Make sure you escape spaces with a backslash!
    -s, --user USER                  List all groups that a supplied user is a member of.
    -r, --priv                       Recurse through the Administrators, DA and EA groups then dump users from all nested groups.
    -t, --attributes                 Get the domain account attributes for all domain users.
    -b, --bad                        Get the bad password count for all domain users.
    -z, --du-hunter USER_FILE        Password spraying attack. Requires a list of usernames and a common password. Currently set to 25 threads.
[17:43][skawa@skawa-mbp:automato] :]
~~~

Use the following syntax when conducting a password spraying attack:
~~~
[17:43][skawa@skawa-mbp:automato] :] ruby automato.rb -d domain -p password -i 192.168.1.100 -z users.txt
~~~

I usually use the following command once domain user credentials have been obtained:
~~~
[17:43][skawa@skawa-mbp:automato] :] ruby automato.rb -d domain -u user -p password -i 192.168.1.100 -a
~~~


