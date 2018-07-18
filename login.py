#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import print_function
# Import the CGI, string, sys, and md5crypt modules
import cgi, string, sys, hashlib

print("Content-Type: text/html")    # HTML is following
print()                             # blank line, end of headers

import cgitb
cgitb.enable()





# Define function to generate HTML form.
def generate_form():
    print ("<HTML>\n")
    print ("<HEAD>\n")
    print ("\t<TITLE>MuPIF VPN-Monitor login Form</TITLE>\n")
    print ("</HEAD>\n")
    print ("<BODY BGCOLOR = white>\n")
    print ("\t<H3>Please, enter your username and password.</H3>\n")
    print ("\t<TABLE BORDER = 0>\n")
    print ("\t\t<FORM METHOD = post ACTION = \"login.py\">\n")
    print ("\t\t<TR><TH>Username:</TH><TD><INPUT TYPE = text NAME = \"username\"></TD><TR>\n")
    print ("\t\t<TR><TH>Password:</TH><TD><INPUT TYPE = password NAME = \"password\"></TD></TR>\n")
    print ("\t</TABLE>\n")
    print ("\t<INPUT TYPE = hidden NAME = \"action\" VALUE = \"display\">\n")
    print ("\t<INPUT TYPE = submit VALUE = \"Enter\">\n")
    print ("\t</FORM>\n")
    print ("</BODY>\n")
    print ("</HTML>\n")

# Define function to test the password.
def test(id, passwd):
    #print ("test called</br>")
    passwd_file = open('passwords.txt', 'r')
    line = passwd_file.readline()
    #print (line+'</br>')
    passwd_file.close()
    combo = line.split(":")
    #encrypted_pw = md5crypt.unix_md5_crypt(passwd, 'ab')
    m = hashlib.sha256(b"kjjyf75633hgd!")
    encrypted_pw = m.update(passwd.encode('utf-8'))
    encrypted_pw = m.hexdigest()
    print(encrypted_pw)
    if ((id == combo[0]) and (encrypted_pw[0:20] == combo[1][0:20])):
         return "passed"
    else:
         return "failed"


# Define function to create a session.
def create_session(id):
    #print ("Create_session called")
    session_file = open('sessions.txt', 'w')
    if (session_file):
        #print (str(session_file))
        # In practice, use the random module for key value.
        session_key = "a12bc78z"
        session_file.write(session_key+":"+id)
        session_file.close()
    else:
        print("Failed to open session file")
    return session_key

# Define a function to return username.
def fetch_username(key):
    session_file = open('sessions.txt', 'r')
    # In practice, search file for correct key.
    line = session_file.readline()
    session_file.close()
    pair = string.split(line, ":")
    return pair[1]

# Define function to delete a session.
def delete_session(id):
    session_file = open('sessions.txt', 'w')
    # In practice, search the file for the correct key.
    # In our example, we just erase the only line in the file.
    session_file.write(" ")
    session_file.close()



# Define function display_page.
def display_page(result, id, session_key=0):
    #print ("display__page called")
    if (result == "passed"):
        if (session_key == 0):
            session_key = create_session(id)
            #print ("session key is "+str(session_key))
            print ("<HTML>\n")
            print ("<HEAD>\n")
            print ("<meta http-equiv=\"refresh\" content=\"0;url=monitor?session_key={0}\">\n".format(session_key))
            print ("<title>You are going to be redirected</title>")
            print ("</HEAD>\n")
            print ("<BODY BGCOLOR = white>\n")
            print ("Succesfully authorized, your session_key is"+str(session_key))
            print ("</BODY>\n")
            print ("</HTML>\n")
    else:
            print ("<HTML>\n")
            print ("<HEAD>\n")
            print ("</HEAD>\n")
            print ("<BODY BGCOLOR = white>\n")
            print ("Authorization Failed")
            print ("</BODY>\n")
            print ("</HTML>\n")

# Define main function.
def main():
    form = cgi.FieldStorage()
    print (form)
    if (form and "session_key" in form):
        if ("logout" in form):
            delete_session(form["session_key"].value)
            generate_form()
        else:
            u_id = fetch_username(form["session_key"].value)
            display_page("passed", u_id, form["session_key"].value)
    elif (form and "action" in form and "username" in form and "password" in form):
        if (form["action"].value == "display"):
            #print ("Action defined")
            result = test(form["username"].value, form["password"].value)
            display_page(result, form["username"].value)
    else:
        generate_form()

# Call main function.
if __name__ == "__main__":
    # Required header that tells the browser how to render the HTML.
    #print ("Content-Type: text/html\n\n")
    main()
