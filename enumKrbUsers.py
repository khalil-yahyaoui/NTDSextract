def findKerberoastableUsers(users): 
    kerberoastableusers = []
    for user in users.keys():
        spn = users[user]["servicePrincipalName"]
        if spn != "":
            kerberoastableusers.append(user)
    return kerberoastableusers
def asReproastableUsers(users):
    asreproastableusers = []
    for user in users.keys():
        if "PASSWD_NOTREQD" in users[user]["userAccountControl"] and "ACCOUNTDISABLE" not in users[user]["userAccountControl"] :
            asreproastableusers.append(user)
    return asreproastableusers
