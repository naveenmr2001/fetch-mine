from flask import Flask,redirect,request,session,render_template,url_for,jsonify,flash
import os,socket,multiprocessing,re
import sqlite3
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import google.auth.exceptions
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from request_file import logo,website_name
from database import create_database,create_email_table,create_footprint_table
from datetime import datetime
from machine_learning import FetchBreach,PredictRisk

app = Flask(__name__)
app.secret_key = '92736'
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 60

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

conn = sqlite3.connect('database.db',check_same_thread=False)


flow = Flow.from_client_secrets_file(
    'c.json',
    scopes=['https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/userinfo.profile'],
    redirect_uri='http://localhost:5000/oauth2callback'
)

@app.route('/clear')
def clear_flash():
    flash('')
    return redirect(url_for('index'))


def get_messages_limit(query):

    try:

        credentials = Credentials.from_authorized_user_info(session['credentials'])
        service = build('gmail', 'v1', credentials=credentials)

        response = service.users().messages().list(userId='me',maxResults=20).execute()

        messages = []

        if 'messages' in response:
            messages.extend(response['messages'])

        print('Number of messages:', len(messages))
        
        domain_list = set()
        missed_list = list()
        
        toemail = str()
        subjectemail = str()

        conn = sqlite3.connect('database.db',check_same_thread=False,timeout=5)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='emails';")
        exists = bool(cursor.fetchone())

        if(not exists):
            create_email_table()

        for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                if msg:
                    headers = msg['payload']['headers']
                    for header in headers:
                        if header['name'] == 'From':
                            sender = header['value']
                            emails = sender.split()[-1]
                            res = emails[emails.index('@') + 1 :]
                            print(res)
                            if(res[-1] == '>'):
                                res = res[0:-1]                            
                            domain_parts = res.split('.')
                            res = '.'.join(domain_parts[-2:])
                            try:
                                socket.gethostbyname(res)
                                domain_list.add(res)
                            except:
                                missed_list.append(res)

                        if header['name'] == 'Subject':
                            subjectemail = header['value']

                        if header['name'] == 'To':
                            match = re.search(r'\<(.*?)\>', header['value'])
                            if match:
                                toemail = match.group(1)
                                print(toemail)
                            else:
                                toemail = header['value']
                                print(toemail)
                            
                internal_date = int(msg['internalDate'])/1000
                date_str = datetime.fromtimestamp(internal_date).strftime('%Y-%m-%d %H:%M:%S')

                cursor.execute("SELECT * FROM emails WHERE fromemail=? AND toemail=? AND subjectemail=? AND date=?",
                           (res, toemail, subjectemail, date_str))
                email_id = cursor.fetchone()
            
                if email_id is None:

                    cursor.execute("INSERT INTO emails (fromemail, toemail, subjectemail, date) VALUES (?, ?, ?, ?)",
                                (res, toemail, subjectemail, date_str))
                    conn.commit()
                else:
                    print('Email message already exists in the database.')

        domain_list = list(domain_list)
        return domain_list
    
    except HttpError as error:

        print(f'An error occurred: {error}')
        return []

def get_messages(query):

    try:

        credentials = Credentials.from_authorized_user_info(session['credentials'])
        service = build('gmail', 'v1', credentials=credentials)

        response = service.users().messages().list(userId='me',maxResults=10).execute()

        messages = []

        if 'messages' in response:
            messages.extend(response['messages'])
            while 'nextPageToken' in response:
                page_token = response['nextPageToken']
                response = service.users().messages().list(userId='me', pageToken=page_token).execute()
                if 'messages' in response:
                    messages.extend(response['messages'])

        print('Number of messages:', len(messages))
        
        domain_list = set()

        missed_list = list()
        
        toemail = str()
        subjectemail = str()

        conn = sqlite3.connect('database.db',check_same_thread=False)
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='emails';")
        exists = bool(cursor.fetchone())

        if(not exists):
            create_email_table()

        for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                if msg:
                    headers = msg['payload']['headers']
                    for header in headers:
                        if header['name'] == 'From':
                            sender = header['value']
                            emails = sender.split()[-1]
                            res = emails[emails.index('@') + 1 :]
                            print(res)
                            if(res[-1] == '>'):
                                res = res[0:-1]                            
                            domain_parts = res.split('.')
                            res = '.'.join(domain_parts[-2:])
                            try:
                                socket.gethostbyname(res)
                                domain_list.add(res)
                            except:
                                missed_list.append(res)

                        if header['name'] == 'Subject':
                            subjectemail = header['value']

                        if header['name'] == 'To':
                            match = re.search(r'\<(.*?)\>', header['value'])
                            if match:
                                toemail = match.group(1)
                                print(toemail)
                            else:
                                toemail = header['value']
                                print(toemail)
                            
                internal_date = int(msg['internalDate'])/1000
                date_str = datetime.fromtimestamp(internal_date).strftime('%Y-%m-%d %H:%M:%S')

                cursor.execute("SELECT * FROM emails WHERE fromemail=? AND toemail=? AND subjectemail=? AND date=?",
                           (res, toemail, subjectemail, date_str))
                email_id = cursor.fetchone()
            
                if email_id is None:

                    cursor.execute("INSERT INTO emails (fromemail, toemail, subjectemail, date) VALUES (?, ?, ?, ?)",
                                (res, toemail, subjectemail, date_str))
                    conn.commit()

        domain_list = list(domain_list)
        return domain_list
    
    except HttpError as error:

        print(f'An error occurred: {error}')
        return []
    

@app.route('/logout')
def logout():
    
    flash("You have been logged out.")
    session.pop('credentials', None)
    return redirect("/")


@app.route('/footprintDetails')
def footprintDetails():

    if 'credentials' not in session:

        flash("Oops! It looks like you're not signed in.")

        return redirect("/")
     
    websiteName = request.args.get('websieName')
    websiteUrl = request.args.get('webstieUrl')
    websiteLogo = request.args.get('websiteLogo')
    websiteDomain = websiteUrl.split('//')[-1].split('/')[0].replace('www.', '')
    breachCount = FetchBreach(websiteDomain)
    riskOfWebsite = PredictRisk(websiteDomain,breachCount)
    if(riskOfWebsite == "Low"):
        flash("The risk is low so website no danger")
    elif(riskOfWebsite == "Medium"):
        flash("The risk is Medium so website lower danger")
    elif(riskOfWebsite == "High"):
        flash("The risk is High so website danger so please log out")
    cursor = conn.execute("SELECT * FROM emails WHERE  fromemail = ?", (websiteDomain,))
    rows = cursor.fetchall()
    email_list = []
    for i in rows:
        print(i)
        email , date = i[2] , i[3]
        email_list.append([email,date])
    print(email_list)
    return render_template("footprint-details.html",name=websiteName,url=websiteUrl,logo=websiteLogo,email = email_list,risk=riskOfWebsite)

@app.route("/footprint")
def footprint():

    if 'credentials' not in session:

        flash("Oops! It looks like you're not signed in.")

        return redirect("/")
    
    userEmail = request.args.get('email')
    print(userEmail)
    conn = sqlite3.connect('database.db',check_same_thread=False)
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='footprint';")
    exists = bool(cursor.fetchone())

    if(not exists):
        create_footprint_table()

    cursor = conn.execute("SELECT * FROM footprint WHERE email = ?", (userEmail,))
    rows = cursor.fetchall()
    print(rows)
    if rows:
        query = ''
        pool = multiprocessing.Pool(processes=4)
        queries = [f'{query} label:{label}' for label in ['INBOX','SENT', 'SPAM', 'TRASH']]
        results = pool.map(get_messages_limit,queries)
        messages = [item for sublist in results for item in sublist]
        print(messages)
        value = set(messages)
        res = list(value)
        content_list = list()
        for domain in res:
            protocol = "https"
            url = f"{protocol}://{domain}"
            logo_data = logo(url)
            website = website_name(url)

            cursor.execute("SELECT * FROM footprint WHERE name=? AND url=? AND logo=? AND email=?",
                           (website, url, logo_data, userEmail))
            
            email_id = cursor.fetchone()

            if email_id is None:
                cursor.execute("INSERT INTO footprint (name, url, logo, email) VALUES (?, ?, ?, ?)",
                        (website, url, logo_data, userEmail))
                conn.commit()

        cursor = conn.execute("SELECT * FROM footprint WHERE email = ?", (userEmail,))
        rows = cursor.fetchall()    
        print(rows)
        for row in rows:
            name, url, logolink = row[0], row[1], row[2]
            content_list.append([name,url,logolink])

        return render_template("footprint.html",output = content_list)
    else:
        query = ''
        pool = multiprocessing.Pool(processes=4)
        queries = [f'{query} label:{label}' for label in ['INBOX','SENT', 'SPAM', 'TRASH']]
        results = pool.map(get_messages,queries)
        messages = [item for sublist in results for item in sublist]
        value = set(messages)
        res = list(value)
        content_list = list()
        for domain in res:
            protocol = "https"
            url = f"{protocol}://{domain}"
            logo_data = logo(url)
            website = website_name(url)

            cursor.execute("SELECT * FROM footprint WHERE name=? AND url=? AND logo=? AND email=?",
                        (website, url, logo_data, userEmail))
        
            email_id = cursor.fetchone()

            if email_id is None:
                cursor.execute("INSERT INTO footprint (name, url, logo, email) VALUES (?, ?, ?, ?)",
                        (website, url, logo_data, userEmail))
                conn.commit()

        cursor = conn.execute("SELECT * FROM footprint WHERE email = ?", (userEmail,))
        rows = cursor.fetchall()    
        print(rows)
        for row in rows:
            name, url, logolink = row[0], row[1], row[2]
            content_list.append([name,url,logolink])
        return render_template("footprint.html",output = content_list)
    



@app.route("/main")
def main():
    email = request.args.get('email')

    if 'credentials' not in session:

        flash("Oops! It looks like you're not signed in")

        return redirect("/")
    
    return render_template("main.html",email=email)

@app.route('/signin',methods=['POST','GET'])
def signin():

    if 'credentials' not in session:

        flash("Oops! It looks like you're not signed in")

        return redirect("/")
    
    if request.method == 'POST':
        email = request.args.get('email')
        password_check = request.form['password']
        password = password_check
        conn = sqlite3.connect('database.db',check_same_thread=False)
        query = "SELECT * FROM users WHERE gmail = ? and password = ?;"
        cursor = conn.execute(query, (email,password,))
        user = cursor.fetchone()
        conn.close()
        if(user):

            flash("Welcome back! We're glad to see you again")

            return redirect(url_for('main',email=email))
        
        else:
            
            session.pop('credentials', None)
            
            flash("Invalid input: Please double-check your input and try again")

            return redirect("/")

@app.route('/signup',methods=["POST"])
def signup():

    if 'credentials' not in session:

        flash("Oops! It looks like you're not signed in")

        return redirect("/")

    if request.method == 'POST':
        name = request.args.get('name')
        email = request.args.get('email')
        photo = request.args.get('photo')
        password = request.form['password']
        query = "INSERT INTO users (name, gmail, logo, password) VALUES (?, ?, ?, ?);"
        conn.execute(query, (name, email, photo, password))
        conn.commit()
        flash('Congratulations! You have successfully signed up')
        return redirect(url_for('displayUserDetails',email=email))



@app.route('/displayUserDetails',methods=['GET', 'POST'])
def displayUserDetails():

    if 'credentials' not in session:

        flash("Oops! It looks like you're not signed in")

        return redirect("/")

    name = request.args.get('name')

    email = request.args.get('email')

    profile_photo_url = request.args.get('photourl')
    
    user_present = request.args.get('flag')

    return render_template("details.html",name=name,email=email,photourl=profile_photo_url,flag=user_present)

@app.route('/userDetails')
def userDetails():
    
    if 'credentials' not in session:

        flash("Oops! It looks like you're not signed in")

        return redirect("/")

    user_present = False

    credentials = Credentials.from_authorized_user_info(session['credentials'])
    service = build('gmail', 'v1', credentials=credentials)

    profile = service.users().getProfile(userId='me').execute()

    email = profile['emailAddress'] 

    profile = service.users().getProfile(userId='me').execute()
    people_service = build('people', 'v1', credentials=credentials)

    photo_response = people_service.people().get(
        resourceName='people/me',
        personFields='names,emailAddresses,photos'
    ).execute()

    if 'photos' in photo_response:
        photos = photo_response['photos']

    if len(photos) > 0:
        profile_photo_url = photos[0]['url']
    
    if 'names' in photo_response:
        user_name = photo_response['names'][0]['displayName']

    conn = sqlite3.connect('database.db',check_same_thread=False)
    cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users';")
    exists = bool(cursor.fetchone())

    if(exists):
        query = "SELECT * FROM users WHERE gmail = ?;"
        cursor = conn.execute(query, (email,))
        if(bool(cursor.fetchone())):
            user_present = True
            return redirect(url_for('displayUserDetails',name=user_name,email=email,photourl=profile_photo_url,flag=user_present))
        else:
            return redirect(url_for('displayUserDetails',name=user_name,email=email,photourl=profile_photo_url,flag=user_present))
    else:
        create_database()
    
    return redirect(url_for('displayUserDetails',name=user_name,email=email,photourl=profile_photo_url,flag=user_present))

@app.route('/oauth2callback')
def oauth2callback():
    try:
        flow.fetch_token(authorization_response = request.url)
        
        credentials = flow.credentials

        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes
        }

        return redirect('/userDetails')

    except google.auth.exceptions.RefreshError:

        return redirect('/login')

@app.route('/login')
def login():

    authorization_url,state = flow.authorization_url(prompt='consent',include_granted_scopes='true',access_type='offline')

    session['state'] = state

    return redirect(authorization_url)

@app.route("/sign")
def sign():
    return redirect(url_for('login'))

@app.route('/')
def index():
    redirect(url_for('clear_flash'))
    return render_template("login.html")

if __name__ == '__main__':

    flash('')
    app.debug = True

    app.run()
