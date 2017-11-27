### automato.rb

automato should help with automating some of the user-focused enumeration tasks during an internal penetration test.

automato is also capable of conducting password guessing attacks, for example, testing to see if a list of users with a common password exists in the target domain

automato will create outfiles automatically for evidence preservation.

#### Usage
~~~
automato.rb v1.7
Written by: Sanjiv Kawa
Twitter: @hackerjiv

Usage: ruby automato.rb [options]
Authenticated Domain Enumeration:
    -a, --all                        Run a bulk of automato's features. Enumerate all domain groups, administrators, computers and user account attributes.
    -d, --domain-users               Get all domain users in the domain.
    -g, --groups                     Get all domain groups for the domain.
    -m, --member GROUP               List all users in a specified domain group.
    -p, --priv                       Recurse through the Administrator and DA groups then dump users from all nested groups.
    -u, --user USER                  List all groups that a supplied user is a member of.
    -t, --attributes                 Get the domain account attributes for all domain users.
Additional Features:
    -b, --bad                        Get the bad password count for all domain users.
    -l, --local IP_FILE              List members who are local administrators on a remote host. (Requires a list of ip addresses with SMB open.)
    -z, --du-hunter USER_FILE        Password spraying attack. (Requires a list of usernames and a common password.)
~~~

I usually use the following command once domain user credentials have been obtained:
~~~
$ ruby automato.rb -a
~~~

### General Use
[![asciicast](https://asciinema.org/a/KgGBaXEEuGOEO5cvQxVlM1rs7.png)](https://asciinema.org/a/KgGBaXEEuGOEO5cvQxVlM1rs7)

### Password Spraying
[![asciicast](https://asciinema.org/a/74HrwKGq6gsjuhIpkyrokVAFT.png)](https://https://asciinema.org/a/74HrwKGq6gsjuhIpkyrokVAFT)

### Local Administrator Enumeration
[![asciicast](https://asciinema.org/a/kve2sdSSqGY9MRNo7RfwHAd4b.png)](https://asciinema.org/a/kve2sdSSqGY9MRNo7RfwHAd4b)
