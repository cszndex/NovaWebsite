from flask_wtf import FlaskForm, RecaptchaField
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired

class KeySystem(FlaskForm):
  captcha = RecaptchaField()
  key_complete = RecaptchaField()
  
class Tools(FlaskForm):
  captcha = RecaptchaField()
  linkvertise_id = StringField('id', validators=[DataRequired()], render_kw={"placeholder": "Linkvertise ID (ex. 927181)"})
  url = StringField('url', validators=[DataRequired()], render_kw={"placeholder": "URL"})