def findKerberoastableUsers(users): 
    kerberoastableusers = []
    for user in users.keys():
        spn = users[user]["servicePrincipalName"]
        if spn != "":
            kerberoastableusers.append(user)
    return kerberoastableusers
