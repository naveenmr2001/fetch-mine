from flask import Flask,redirect,request,session,render_template,url_for
import os,socket,multiprocessing,pickle
import sqlite3
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import google.auth.exceptions
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from request_file import logo,website_name
from database import create_database

app = Flask(__name__)
app.secret_key = '92736'

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

conn = sqlite3.connect('database.db',check_same_thread=False)


flow = Flow.from_client_secrets_file(
    'c.json',
    scopes=['https://www.googleapis.com/auth/gmail.readonly','https://www.googleapis.com/auth/userinfo.profile'],
    redirect_uri='http://localhost:5000/oauth2callback'
)


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
        
        for message in messages:
                msg = service.users().messages().get(userId='me', id=message['id']).execute()
                if msg:
                    headers = msg['payload']['headers']
                    for header in headers:
                        if header['name'] == 'From':
                            sender = header['value']
                            emails = sender.split()[-1]
                            res = emails[emails.index('@') + 1 :]
                            if(res[-1] == '>'):
                                res = res[0:-1]                            
                            domain_parts = res.split('.')
                            res = '.'.join(domain_parts[-2:])
                            try:
                                socket.gethostbyname(res)
                                domain_list.add(res)
                            except:
                                missed_list.append(res)

        domain_list = list(domain_list)
        return domain_list

    except HttpError as error:

        print(f'An error occurred: {error}')
        return []

@app.route("/google")
def call():
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
        content_list.append([website,url,logo_data])
    return render_template("footprint.html",output = content_list)



@app.route("/main")
def main():
    if 'credentials' not in session:
        return redirect('/')
    return render_template("main.html")

@app.route('/signup',methods=["POST"])
def signup():

    if 'credentials' not in session:
        return redirect('/')

    if request.method == 'POST':
        name = request.args.get('name')
        email = request.args.get('email')
        photo = request.args.get('photo')
        password = request.form['password']
        query = "INSERT INTO users (name, gmail, logo, password) VALUES (?, ?, ?, ?);"
        conn.execute(query, (name, email, photo, password))
        conn.commit()
        return url_for('main',email=email)

@app.route('/signin',methods=['POST','GET'])
def signin():

    if 'credentials' not in session:
        return redirect('/')
    
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
            return redirect("/main")
        else:
            return redirect("/")

@app.route('/displayUserDetails',methods=['GET', 'POST'])
def displayUserDetails():

    if 'credentials' not in session:
        return redirect('/')

    name = request.args.get('name')

    email = request.args.get('email')

    profile_photo_url = request.args.get('photourl')
    
    user_present = request.args.get('flag')

    return render_template("details.html",name=name,email=email,photourl=profile_photo_url,flag=user_present)

@app.route('/userDetails')
def userDetails():
    if 'credentials' not in session:
        return redirect('/')

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

    conn = sqlite3.connect('database.db',check_same_thread=False,timeout=5)
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
    if 'credentials' not in session:
        return redirect('/login')

@app.route('/')

def index():

    return render_template("login.html")

if __name__ == '__main__':

    app.debug = True

    app.run()
