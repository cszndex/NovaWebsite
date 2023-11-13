from flask import Flask, render_template, request, redirect, url_for, g, flash, abort, jsonify, make_response
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from pymongo import MongoClient
from datetime import datetime
from bs4 import BeautifulSoup
import requests
import base64
import hashlib
import time
import socket
import threading
import random
import string
import os
import re

#App Handler
app = Flask(__name__)
app.config['SECRET_KEY'] = "nova"
app.config.update(
  SESSION_COOKIE_SECURE=True,
  SESSION_COOKIE_HTTPONLY=True,
  SESSION_COOKIE_SAMESITE='Lax',
)
app.config['RECAPTCHA_PUBLIC_KEY'] = "6LcA7LkoAAAAAGYF3EQworMXZfCocLwNfwm8NOg-"
app.config['RECAPTCHA_PRIVATE_KEY'] = "6LcA7LkoAAAAAHlJ20AHcSJU1mBVCM5CZnSopPo-"
app.config['RECAPTCHA_DATA_ATTRS'] = {"theme": "light"}

MongoConnection = MongoClient("mongodb+srv://Zenith:ejaybaog@quantumix.smje85r.mongodb.net/?retryWrites=true&w=majority")
Database = MongoConnection['Nova']
Keys = Database['Keys']
Users = Database['Users']
Dex = Database['Dex']

#Functions
def generate_key():
  return 'nova_'+''.join(random.choices(string.ascii_letters + string.digits, k=15))

def encrypt(x):
  v = x + "5gz"
  return hashlib.md5(v.encode())

def convert(userid, url):
  base_url = f"https://link-to.net/{userid}/{random.random() * 1000}/dynamic"
  encoded = base64.b64encode(url.encode("utf-8")).decode("utf-8")
  href = f"{base_url}?r={encoded}"
  return href

#Error Handler
@app.errorhandler(404)
def notfound(e):
  return render_template('error.html')

# Forms
class KeySystem(FlaskForm):
  captcha = RecaptchaField()
  key_complete = RecaptchaField()
  
class Tools(FlaskForm):
  captcha = RecaptchaField()
  linkvertise_id = StringField('id', validators=[DataRequired()], render_kw={"placeholder": "Linkvertise ID (ex. 927181)"})
  url = StringField('url', validators=[DataRequired()], render_kw={"placeholder": "URL"})

#Admin
@app.route('/analytics')
def dashboard():
  return render_template('dashboard.html')

#Routes Handler
@app.route('/')
def home():
  DATA = Dex.find_one({"_id": "executes"})
  
  EXEC = DATA['total']
  DLS = str(DATA['total'] // 2)
  
  if DATA['total'] >= 1000:
    if DATA['total'] % 1000 == 0:
      EXEC = str(DATA['total'] // 1000) + "k"
    else:
      EXEC = str(DATA['total'] / 1000) + "k"
  
  return render_template('home.html', EXEC=EXEC, DLS=DLS)

@app.route('/linkvertise', methods=['POST', 'GET'])
def linkvertise():
  CONVERTED = None
  
  if request.method == "POST":
    USERID = request.form.get("id")
    URL = request.form.get("url")
    CONVERTED = convert(USERID, URL)
    return render_template('linkvertiser.html', CONVERTED=CONVERTED)
  
  return render_template('linkvertiser.html', CONVERTED=CONVERTED)

@app.route('/scripts', methods=["GET"])
def scripts():
  return render_template('scripts.html')

@app.route('/getkey', methods=['POST', 'GET'])
def getkey():
  CHECKPOINT = request.args.get('checkpoint', type=int)
  HWID = request.args.get('hwid', '')
  IP = encrypt(request.remote_addr)
  FORM = KeySystem()
  CURRENT = 0
  
  URL = ['https://link-hub.net/885916/quantumix-checkpoint', 'https://link-hub.net/885916/quantumix-checkpoint-2', 'https://link-hub.net/885916/quantumix-checkpoint-3']
  
  USERS = Keys.find_one({"IP": IP.hexdigest()})
  
  if USERS:
    CURRENT = USERS['CHECKPOINT']
    if CHECKPOINT != CURRENT:
      return redirect(url_for('getkey') + f"?hwid={IP.hexdigest()}" + f"&checkpoint={CURRENT}")
    elif CURRENT == 3:
      KEY = USERS['KEY']
      return redirect(url_for('finished') + f"?key={KEY}")
  else:
    Keys.insert_one({
      "IP": IP.hexdigest(),
      "KEY": "none",
      "CHECKPOINT": 1,
      "CREATED": datetime.utcnow()
    })
    CURRENT = 1
    return redirect(url_for('getkey') + f"?hwid={IP.hexdigest()}" + f"&checkpoint={CURRENT}")
  
  if HWID == USERS['IP']:
    if CHECKPOINT > CURRENT or CHECKPOINT < CURRENT:
      abort(404)
    else:
      if request.method == "POST":
        if CHECKPOINT == 3 and USERS["CHECKPOINT"] == 3:
          resp = make_response(redirect(URL[2])
          resp.set_cookie('NGCH', str(3), httponly=True, secure=True, samesite="Lax")
          return resp
        elif CHECKPOINT == 2 and USERS["CHECKPOINT"] == 2:
          resp = make_response(redirect(URL[1])
          resp.set_cookie('NGCH', str(2), httponly=True, secure=True, samesite="Lax")
          return resp
        elif CHECKPOINT == 1 and USERS["CHECKPOINT"] == 1:
          resp = make_response(redirect(URL[0]))
          resp.set_cookie('NGCH', str(1), httponly=True, secure=True, samesite="Lax")
          return resp
    
    return render_template('checkpoint.html', CURRENT=CURRENT, FORM=FORM)
  else:
    return abort(404)

@app.route('/getkey/validate', methods=['POST', 'GET'])
def checkpoint():
  IP = encrypt(request.remote_addr)
  REFERER = request.headers.get('Referer')
  NGCH = request.cookies.get("NGCH")
  
  USER = Keys.find_one({"IP": IP.hexdigest()})
  CURRENT = 0
  KEY = None
  
  if USER:
    CURRENT = USER['CHECKPOINT']
  
  if REFERER == "https://linkvertise.com/" and CURRENT == 3 and NGCH == "3":
    KEY = generate_key()
    Keys.update_one({"IP": IP.hexdigest()}, {"$set": {"KEY": KEY}})
    request.headers.get('Authorization', '')
    return redirect(url_for('finished') + f"?key={KEY}")
  elif REFERER == "https://linkvertise.com/" and CURRENT == 2 and NGCH == "2":
    Keys.update_one({"IP": IP.hexdigest()}, {"$inc": {"CHECKPOINT": 1}})
    return render_template('validate.html', CURRENT=CURRENT + 1, hwid=IP.hexdigest(), REDIRECT_URL=url_for('getkey'))
  elif REFERER == "https://linkvertise.com/" and CURRENT == 1 and NGCH == "1":
    Keys.update_one({"IP": IP.hexdigest()}, {"$inc": {"CHECKPOINT": 1}})
    return render_template('validate.html', CURRENT=CURRENT + 1 , hwid=IP.hexdigest(), REDIRECT_URL=url_for('getkey'))
  else:
    flash('Dont try to bypass.')
    return render_template('validate.html', CURRENT=CURRENT, hwid=IP.hexdigest(), REDIRECT_URL=url_for('getkey'))
  
  return "Nothing in here"

@app.route('/getkey/finished', methods=['POST', 'GET'])
def finished():
  KEY_ARGS = request.args.get('key', '')
  IP = encrypt(request.remote_addr)
  
  USERS = Keys.find_one({"IP": IP.hexdigest()})
  CAPTCHA_FINISHED = False
  RECAPTCHA = KeySystem()
  KEY = None
  
  if USERS and USERS['CHECKPOINT'] == 3 and KEY_ARGS == USERS['KEY']:
    if RECAPTCHA.validate_on_submit():
      CAPTCHA_FINISHED = True
      KEY = KEY_ARGS
  else:
    flash('Dont try to bypass')
    return render_template('validate.html', CURRENT=USERS['CHECKPOINT'], hwid=IP.hexdigest(), REDIRECT_URL=url_for('getkey'))
  
  return render_template('finished.html', KEY=KEY, RECAPTCHA=RECAPTCHA, CAPTCHA_FINISHED=CAPTCHA_FINISHED, CHECKPOINT=USERS['CHECKPOINT'])

# Tools Handler
def tool_extract_hwid(url):
  match = re.search(r'HWID=([\w\d]+)', url)
  return match.group(1) if match else None

def tool_bypass(hwid):
  Base_Url = f"https://fluxteam.net/android/checkpoint/start.php?HWID={hwid}"
  Referrer = {
    'Referer': "https://linkvertise.com/",
    'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36"
  }
  session = requests.Session()
  session.get(Base_Url, headers={'Referer': "https://fluxteam.net/"})
  time.sleep(1)
  session.get('https://fluxteam.net/android/checkpoint/check1.php', headers=Referrer)
  session.get('https://fluxteam.net/android/checkpoint/check2.php', headers=Referrer)
  session.get('https://fluxteam.net/android/checkpoint/check3.php', headers=Referrer)
  time.sleep(1)
  response = session.get("https://fluxteam.net/android/checkpoint/main.php", headers=Referrer)
  time.sleep(1)
  soup = BeautifulSoup(response.text, 'html.parser')
  body_code = soup.select_one('body > main > code').get_text()
  key = re.sub(r'\s+', '', body_code) + "\n"
  return key

@app.route('/tools/fluxus', methods=["POST", "GET"])
def tools_fluxus():
  KEY = None
  REFERER = request.headers.get('Referer')
  NGKEY = request.cookies.get('NGKEY')
  
  if request.method == "POST":
    URL = request.form.get("url")
    EXTRACT = tool_extract_hwid(URL)
    if EXTRACT:
      KEY = tool_bypass(EXTRACT)
      if KEY:
        resp = make_response(render_template('nexus.html'))
        resp.set_cookie('NGKEY', KEY) 
        return resp 
  if REFERER == "https://linkvertise.com/" and NGKEY:
    flash("Key Generated Successfully!")
    return render_template('flux.html', KEY=NGKEY)
  return render_template("flux.html", KEY=KEY)

# Script Handler
@app.route("/utility")
def dex():
  return render_template("dex.html")

#API Handler
def api_get_executed():
  DATA = Dex.find_one({"_id": "executes"})
  if DATA:
    DATA.get("total", 1)
  return 1
def api_increment_executes():
  Dex.update_one({"_id": "executes"}, {"$inc": {"total": 1}}, upsert=True)

@app.route('/api/<parameter>', methods=["GET", "POST"])
def api(parameter):
  TYPES = ["ip", "validate", "executed"]
  HEXED = encrypt(request.remote_addr)
  
  if parameter == TYPES[0]:
    return HEXED.hexdigest()
  elif parameter == TYPES[1]:
    DATA = request.get_json(silent=True)
    
    if not DATA or 'KEY' not in DATA or 'IP' not in DATA or 'CHECKPOINT' not in DATA:
      return jsonify({"ERROR": "Invalid Arguments"}), 400
    IP = DATA["IP"]
    KEY = DATA["KEY"]
    CHECKPOINT = DATA["CHECKPOINT"]
    
    DOCS = Keys.find_one({"IP": IP})
    if DOCS:
      if KEY == DOCS["KEY"] and IP == DOCS["IP"] and CHECKPOINT >= DOCS["CHECKPOINT"]:
        return jsonify({"NOVA": True, "SUCCESS": "Valid Credentials"}), 200
    return jsonify({"ERROR": "Invalid Arguments"}), 400
  elif parameter == TYPES[2]:
    DATA = request.get_json(silent=True)
    if not DATA or 'RECENT' not in DATA:
      return jsonify({"ERROR": "Missing Arguments"}), 404
    EXECUTE = DATA['RECENT']
    if EXECUTE:
      api_increment_executes()
      return jsonify({"SUCCESS": 'Executed Successful'}), 200
  return abort(404)