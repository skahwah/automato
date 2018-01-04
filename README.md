### automato.rb

automato uses native LDAP libraries to automate the collection and enumeration of various directory objects. This is incredibly useful during an internal penetration test.

automato can also conduct password spraying attacks, and identify if a user is a local administrator against any number of systems.

Output files are automatically created for evidence preservation.

#### Usage
~~~
$ ruby automato.rb
automato v2.0
Written by: Sanjiv Kawa
Twitter: @hackerjiv

Commands:
  automato.rb all                                          # Run the most popular features. (computers, users, groups, priv, attributes)
  automato.rb attr                                         # Get the account attributes for all domain users.
  automato.rb bad                                          # Get the bad password count for all domain users.
  automato.rb computers                                    # Get all domain computers.
  automato.rb groups                                       # Get all domain groups.
  automato.rb help [COMMAND]                               # Describe available commands or one specific command
  automato.rb laps                                         # Get the laps password for systems in the network
  automato.rb localadmin DOMAIN USERNAME PASSWORD IP_FILE  # Identify if a user is a local admin against a list of IP's with SMB open
  automato.rb member GROUP                                 # List all users in a supplied domain GROUP.
  automato.rb priv                                         # Recurse through administrative groups and get users from all nested groups.
  automato.rb spray USER_FILE PASSWORD                     # Conduct a password spraying attack against the domain using a USER_FILE and common PASSWORD
  automato.rb user USER                                    # Get the group memberships for a supplied USER
  automato.rb users                                        # Get all domain users.

$
~~~

I usually use the following command once domain user credentials have been obtained:
~~~
$ ruby automato.rb all
~~~

### General Use
[![asciicast](https://asciinema.org/a/jZo3xL9gu6nOneluDWaH3ogdx.png)](https://asciinema.org/a/jZo3xL9gu6nOneluDWaH3ogdx)

### Retrieve LAPS passwords
[![asciicast](https://asciinema.org/a/aFsp8iQpzKcJSFieILMFskmdm.png)](https://asciinema.org/a/aFsp8iQpzKcJSFieILMFskmdm)

### Password Spraying
[![asciicast](https://asciinema.org/a/bGk28X36Hd60lBPvSw59sofe1.png)](https://asciinema.org/a/bGk28X36Hd60lBPvSw59sofe1)

### Local Administrator Enumeration
[![asciicast](https://asciinema.org/a/WZCZX2KQlAzSfJwipjQAo4kGl.png)](https://asciinema.org/a/WZCZX2KQlAzSfJwipjQAo4kGl)
