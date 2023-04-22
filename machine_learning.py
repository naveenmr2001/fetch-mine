import requests,pickle
from sklearn import preprocessing
import pandas as pd


def FetchBreach(domainName):
    url = "https://haveibeenpwned.com/api/v3/breaches"
    params = {"domain": domainName}
    headers = {"hibp-api-key": "b155ac2e3f6743febba24bbb758dac77"}

    response = requests.get(url, headers=headers, params=params)

    if response.ok:
        breaches = response.json()
        breachCount = 0
        for breach in breaches:
            breachCount =  breach["PwnCount"]
        return breachCount
    else:
        return 0

def PredictRisk(domainName,breachCount):
    le = preprocessing.LabelEncoder()
    filename = "./model/model.pkl"
    loaded_model = pickle.load(open(filename, 'rb'))
    columns = ['Domain','BreachCount']
    data = [[domainName,breachCount]]
    df = pd.DataFrame(data, columns=columns)
    print(df)
    df['Domain'] = le.fit_transform(df['Domain'])
    Y_prediction = loaded_model.predict(df)
    print(Y_prediction)
    result = str()
    if(Y_prediction[0] == 1):
        return "Low"
    elif(Y_prediction[0] == 2):
        return "Medium"
    elif(Y_prediction[0] == 0):
        return "High"