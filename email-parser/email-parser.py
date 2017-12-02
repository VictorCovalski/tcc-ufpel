############################
# @author Victor Covalski  #
# @date 12/11/2017         #
# UFPel                    #
############################

import mailbox
import email.utils
import validators
import os
import sys
import re
import csv

from bs4 import BeautifulSoup
from urllib.parse import urlparse

global debug
debug = True

def main( arguments ):
    in_mbox = arguments[1]
    dataset_type = arguments[2]
    out_csv = arguments[3]

    if debug:
        print ("Input mbox file: " + in_mbox)
        print ("Dataset type: " + dataset_type)
        print ("Output file: " + out_csv)

    emails = mailbox.mbox(in_mbox)

    extracted_features = {
            'url_ip':                 None, #1.1
            'href_dif_text_url':         None, #1.2
            'keywords_link_text':         None, #1.3
            'no_dots_domain':            None, #1.4
            'html_email':                None, #1.5
            'word_javascript':           None, #1.6
            'no_links':                  None, #1.7
            'no_link_dn':                None, #1.8
            'from_dif_dn':               None, #1.9
            'update_confirm':        None, #Update; Confirm; #1.10
            'user_cust_clie':        None, #User; Customer; Client;
            'susp_rest_hold':        None, #Suspend; Restrict; Hold;
            'veri_acco_noti':        None, # Verify; Account; Notif;
            'logi_user_pass':        None, # Login; Username; Password; Click; Log;
            'ssn_social_sec':        None, #SSN; Social Security; Secur; Inconvinien.
            'flag'          :        dataset_type

    }

    writer = csv.writer(open(out_csv,'w+'))
    keys = []
    for key,value in extracted_features.items():
        keys.append(key)
    writer.writerow(keys)

    for email in emails:
        email_body = get_email_body(email)
        email_html = BeautifulSoup(email_body,'html.parser')
        a_tags = email_html.find_all('a') #get all <a> tags

        extracted_features['html_email'] = hasHTML(email) #1.5

        #

        url_list = []
        if(extracted_features['html_email']):
            extracted_features['href_dif_text_url'] = check_href_text(a_tags) #1.2
            extracted_features['keywords_link_text']= has_keywords(a_tags)    #1.3 Description: checks
            for tag in a_tags:
                url_list.append(tag.get('href'))
        else:
            extracted_features['href_dif_text_url'] = False
            for r in re.findall('(?<=http://).*',email_body): # get url list from plain/text emails
                url_list.append('http://' + r.split('<')[0].split('>')[0].split("\"")[0])

        extracted_features['no_dots_domain'] = check_dots_domain(url_list) #1.4
        extracted_features['url_ip'] = ip_in_url(url_list)                 #1.1
        extracted_features['word_javascript'] = check_javascript(email_body) #1.6

        extracted_features['no_links'] = len(url_list) #1.7
        extracted_features['no_link_dn'] = get_distinct_domain(url_list)
        extracted_features['from_dif_dn'] = check_from_dn(email['from'],url_list) #1.9
        #1.10
        extracted_features['update_confirm'] = check_keywords(['update','confirm'],email_body)
        extracted_features['user_cust_clie'] = check_keywords(['user','customer','client'],email_body)
        extracted_features['susp_rest_hold'] = check_keywords(['suspend','restrict','hold'],email_body)
        extracted_features['veri_acco_noti'] = check_keywords(['verify','account','notif'],email_body)
        extracted_features['logi_user_pass'] = check_keywords(['login','username','password','click','log'],email_body)
        extracted_features['ssn_social_sec'] = check_keywords(['ssn','social security','secur','inconvinien'],email_body)

        row = json2list(extracted_features)
        writer.writerow(row)
        #print(extracted_features)

def json2list(json):
    array = []
    for key,value in json.items():
        array.append(value)
    return array

def get_email_body(message): #getting plain text 'email body'
    body = None
    if message.is_multipart():
        for part in message.walk():
            if part.is_multipart():
                for subpart in part.walk():
                    if subpart.get_content_type() != 'multipart/alternative':
                        body = subpart.get_payload(decode=True)
            elif part.get_content_type() != 'multipart/alternative':
                body = part.get_payload(decode=True)
    elif message.get_content_type() != 'multipart/alternative':
        body = message.get_payload(decode=True)
    return str(bytes.decode(body,errors='ignore'))

#gets the domain from a given url
def get_domain(url):
    return urlparse(url).netloc.split(':')[0]

# The 11 characteristics that are to be extracted


#Description: if there's a valid url in link text, and it's domain differs from href, this feature is true
def check_href_text(tags): #1.2
    for tag in tags:
        try:
            domain_url  = get_domain(tag.get('href'))
            link_text = tag.contents[0].string
            #print(link_text)
            if(validators.domain(link_text)):
                return (link_text != domain_url)
            elif(validators.url(link_text)):
                return (get_domain(link_text) != domain_url)
        except:
            continue

#Description: checks email for presence of keywords
def check_keywords(words,email): #1.10
    pattern = "("
    for word in words:
        pattern += word.lower() + "|"
    pattern = pattern[0:-1] + ")"
    no_words = len(email.split(' '))
    return len(re.findall(pattern,email.lower()))/no_words

def has_keywords(tags): #1.3
    pattern = '(click|here|login|update|link)'
    for tag in tags:
        try:
            text = tag.contents[0].string
            if re.search(text,pattern) != None:
                return True
        except:
            continue
    return False

#Description: if the number of dots in the domain name is above 3 this feature is True
def check_dots_domain(url_list): #1.4
    for url in url_list:
        try:
            if(number_dots(get_domain(url)) > 3):
                return True
        except:
            continue
    return False

def hasHTML(email_mbox): #1.5
    if (email_mbox.is_multipart()):
        for part in email_mbox.walk():
            if part.is_multipart():
                for subpart in part.walk():
                    if subpart.get_content_type() == 'text/html':
                        return True
            elif part.get_content_type() == 'text/html':
                return True
    elif email_mbox.get_content_type() == 'text/html':
        return True
    return False

#Description: Looks for javascript keyword in email body and links
def check_javascript(body): #1.6
    if body.lower().find('javascript') >= 0:
        return True
    return False

#Description: Checks the sender(user@bogus.com) domain name (bogus.com) with the domain for every url in email
def check_from_dn(sender,url_list): #1.9
    from_domain = str(sender).split('@')[-1][0:-1] #get domain name of sender

    for url in url_list:
        try:
            if(from_domain != get_domain(url)): #if there's a disparity
                return True #likely phishing
        except:
            continue
    return False

def number_dots(string):
    dots=0
    for char in string:
        if(char == '.'):
            dots+=1
    return dots

def ip_in_url(urls):
    for url in urls: #http://ufpel.edu.br/portal
        try:
            if(validators.url(url)): #if url is valid
                netlocal = get_domain(url) #ufpel.edu.br
                #return on first occurrence of ip in URL
                if validators.ipv4(netlocal):
                    return True
                if validators.ipv6(netlocal):
                    return True
        except:
            continue
    return False
def get_domain(url):
    return urlparse(url).netloc.split(':')[0]


def get_distinct_domain(url_list):
    domains = {}
    distinct_count = 0
    for url in url_list:
        try:
            domain = get_domain(url)
            if( domain not in domains):
                domains[domain] = 1
                distinct_count += 1
        except:
            continue
    return distinct_count

def validate_domain(tags,sender):
    for tag in tags:
        if(get_domain(tag.get('href')) != sender.split('@')[1]):
            return True

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.stderr.write("Uso: ./feature-extractor.py input.mbox <phishing|ham> output.csv\n")
        sys.exit(1)
    sys.exit( main(sys.argv) )
