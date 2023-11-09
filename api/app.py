from flask import Flask, render_template, request, redirect, url_for, g, flash, abort, jsonify
from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired
from pymongo import MongoClient
from datetime import datetime
import requests
import base64
import hashlib
import time
import socket
import threading
import random
import string
import os

#App Handler
app = Flask(__name__)
app.config['SECRET_KEY'] = "nova"
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
  return render_template('home.html')

@app.route('/linkvertise', methods=['POST', 'GET'])
def tool():
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
      if FORM.validate_on_submit():
        if CHECKPOINT == 3 and USERS["CHECKPOINT"] == 3:
          return redirect(URL[2])
        elif CHECKPOINT == 2 and USERS["CHECKPOINT"] == 2:
          return redirect(URL[1])
        elif CHECKPOINT == 1 and USERS["CHECKPOINT"] == 1:
          return redirect(URL[0])
    
    return render_template('checkpoint.html', CURRENT=CURRENT, FORM=FORM)
  else:
    return abort(404)

@app.route('/getkey/validate', methods=['POST', 'GET'])
def checkpoint():
  IP = encrypt(request.remote_addr)
  REFERER = request.headers.get('Referer')
  
  USER = Keys.find_one({"IP": IP.hexdigest()})
  CURRENT = 0
  KEY = None
  
  if USER:
    CURRENT = USER['CHECKPOINT']
  
  if REFERER == "https://linkvertise.com/" and CURRENT == 3:
    KEY = generate_key()
    Keys.update_one({"IP": IP.hexdigest()}, {"$set": {"KEY": KEY}})
    request.headers.get('Authorization', '')
    return redirect(url_for('finished') + f"?key={KEY}")
  elif REFERER == "https://linkvertise.com/" and CURRENT == 2:
    Keys.update_one({"IP": IP.hexdigest()}, {"$inc": {"CHECKPOINT": 1}})
    return render_template('validate.html', CURRENT=CURRENT + 1, hwid=IP.hexdigest(), REDIRECT_URL=url_for('getkey'))
  elif REFERER == "https://linkvertise.com/" and CURRENT == 1:
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
def api_increment_executes(recent):
  Dex.update_one({"_id": "executes"}, {"$inc": {"total": 1}}, {"$set": {"latest": str(recent)}}, upsert=True)

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
        return jsonify({"NOVA": True, "SUCCESS": "Valid Credentials"}) 200
    return jsonify({"ERROR": "Invalid Arguments"}), 400
  elif parameter == TYPES[2]:
    DATA = request.get_json(silent=True)
    if not DATA or 'RECENT' not in DATA:
      return jsonify({"ERROR": "Missing Arguments"}) 404
    EXECUTE = DATA['RECENT']
    if EXECUTE:
      api_increment_executes(str(EXECUTE))
      return jsonify({"SUCCESS": 'Executed Successful'}) 200
  return abort(404)
