from flask import Flask, redirect, request, session,render_template
import os,socket,multiprocessing,pickle,base64
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
import google.auth.exceptions
from google.auth.transport import requests
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from request_file import logo,website_name

app = Flask(__name__)
app.secret_key = '92736'

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

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

            # while 'nextPageToken' in response:
            #     page_token = response['nextPageToken']
            #     response = service.users().messages().list(userId='me', pageToken=page_token).execute()
            #     if 'messages' in response:
            #         messages.extend(response['messages'])

        print('Number of messages:', len(messages))
        
        email_list = []
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

@app.route("/query",methods=['GET', 'POST'])
def predict():

    if request.method == 'POST':
        domain = request.form['name']
        breachcount = request.form['email']
    else:
        return '''
            <form action="/query" method="post">
              <label for="name">Domain:</label>
              <input type="text" id="name" name="name"><br><br>
              <label for="email">BreachCount:</label>
              <input type="text" id="email" name="email"><br><br>
              <input type="submit" value="Submit">
            </form>
        '''

    le = LabelEncoder()
    filename = "./model/model.pkl"
    loaded_model = pickle.load(open(filename, 'rb'))
    columns = ['Domain','BreachCount']
    data = [[domain, breachcount]]
    df = pd.DataFrame(data, columns=columns)
    print(df)
    df['Domain'] = le.fit_transform(df['Domain'])
    Y_prediction = loaded_model.predict(df)
    print(Y_prediction)
    result = str()
    if(Y_prediction[0] == 1):
        result = "Risk of the domain : LOW"
    elif(Y_prediction[0] == 2):
        result = "Risk of the domain : MEDIUM"
    elif(Y_prediction[0] == 0):
        result = "Risk of the domain : HIGH"
    return render_template("query.html",result = result)

@app.route('/login')
def login():
    flow.from_client_secrets_file(
        'c.json', scopes=['openid', 'email', 'profile']
    )
    authorization_url,state = flow.authorization_url(prompt='consent',include_granted_scopes='true',access_type='offline')
    session['state'] = state
    return redirect(authorization_url)

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
        return redirect('/main')
    except google.auth.exceptions.RefreshError:
        return redirect('/login')

@app.route("/main")
def main():
    
    credentials = Credentials.from_authorized_user_info(session['credentials'])
    service = build('gmail', 'v1', credentials=credentials)
    profile = service.users().getProfile(userId='me').execute()
    email = profile['emailAddress'] 
    people_service = build('people', 'v1', credentials=credentials)
    photo_response = people_service.people().get(
        resourceName='people/me',
        personFields='names,emailAddresses,photos'
    ).execute()

    service = build('gmail', 'v1', credentials=credentials)
    profile = service.users().getProfile(userId='me').execute()

    if 'photos' in photo_response:
        photos = photo_response['photos']

    if len(photos) > 0:
        profile_photo_url = photos[0]['url']
    
    if 'names' in photo_response:
        user_name = photo_response['names'][0]['displayName']

    email = profile['emailAddress']
    
    print(user_name)
    print(profile_photo_url)
    print(email)
    return render_template("main.html")


@app.route("/signin")
def sign():
    if 'credentials' not in session:
        return redirect('/login')
    credentials = Credentials.from_authorized_user_info(session['credentials'])

@app.route('/')
def index():
    return render_template("login.html")

if __name__ == '__main__':
    app.debug = True
    app.run()
