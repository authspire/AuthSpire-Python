from authspire import api

def logo():
    logo = r"""
Yb  dP                        db              
 YbdP  .d8b. 8   8 8d8b      dPYb   88b. 88b. 
  YP   8' .8 8b d8 8P       dPwwYb  8  8 8  8 
  88   `Y8P' `Y8P8 8       dP    Yb 88P' 88P' 
                                    8    8    
"""
    print(logo)

authSpire = api(
    app_name = "",
    userid = "",
    secret = "",
    currentVersion = "1.0",
    publicKey = ""
)


def main():
    logo()

    print("[1] Register")
    print("[2] Login")
    print("[3] License only")
    print("[4] Add Log")

    option = input(">> ")
    print()
    if option == "1":
        username = input("Username: ")
        password = input("Password: ")
        license = input("License: ")
        email = input("Email: ")

        registered = authSpire.register(username, password, license, email)
        if registered:
            print("Thanks for registering!")
    elif option == "2":
        username = input("Username: ")
        password = input("Password: ")

        logged_in = authSpire.login(username, password)
        if logged_in:
            print("Welcome back " + authSpire.user.username)
            print()
            print(authSpire.user.email)
            print(authSpire.user.ip)
            print(authSpire.user.expires)
            print(authSpire.user.hwid)
            print(authSpire.user.last_login)
            print(authSpire.user.created_at)
            print(authSpire.user.variable)
            print(authSpire.user.level)
    elif option == "3":
        license = input("License: ")
        if authSpire.license(license):
            print("Welcome back " + authSpire.user.username)
            print()
            print(authSpire.user.email)
            print(authSpire.user.ip)
            print(authSpire.user.expires)
            print(authSpire.user.hwid)
            print(authSpire.user.last_login)
            print(authSpire.user.created_at)
            print(authSpire.user.variable)
            print(authSpire.user.level)
    elif option == "4":
        username = input("Username: ")
        action = input("Action: ")
        authSpire.add_log(username, action)
        print("Log added!")
    input()

main()