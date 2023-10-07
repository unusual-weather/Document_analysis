import pandas as pd
import numpy as np
import joblib
import xgboost as xgb
import re
from tld import get_tld

def construct_df(domain,res):
    df = pd.DataFrame([np.zeros(27)],columns=['http', 'https', 'www', 'IP', 'short_url',
                               '!', '*', "'", '(', ')',
                               ';',':', '@', '&', '=', '+',
                               '$', '"', ',', '/', '?',
                               '%', '#', '[', ']','total_len',
                               'tld_len'],dtype='int64')
    for column in df.columns:
        if column =="IP":
            df[column] = 1 if re.match("https?:\/\/(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",domain) else 0
        elif column =="total_len":
            df[column] = len(domain)
        elif column =="tld_len":
            try:
                df[column] = len(get_tld(domain))
            except:
                df[column] = 0
        elif column == "http":
            df[column] = 1 if "https" not in domain and "http" in domain else 0
        elif column == "https":
            df[column] = 1 if "https" in domain else 0
        elif column == "short_url":
            df[column] = len(res.history)
        else:
            df[column] = domain.count(column)
            
    df.rename(columns={']':'=+'},inplace=True)
    df.rename(columns={'[':'+='},inplace=True)
    # df['short_url']=1
    # df['/']=2
    # df['total_len'] = 17
    # df['tld_len'] = 3
    df = xgb.DMatrix(df)
    return df

def load_model():
    model = joblib.load("./models/XGBoost_model_2.pkl")
    return model

def binary_test(domain,res):
    df = construct_df(domain,res)
    model = load_model()
    predict = model.predict(df)
    result = 1 if predict>0.5 else 0 
    return result