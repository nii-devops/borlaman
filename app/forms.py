from flask_wtf import FlaskForm
from wtforms import (StringField, PasswordField, BooleanField, SubmitField, SelectField, TextAreaField, 
                     FloatField, EmailField, FileField)
from wtforms.validators import DataRequired, Email, EqualTo, ValidationError, Length, Optional
from wtforms_sqlalchemy.fields import QuerySelectField, QuerySelectMultipleField
from app.models import *





class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    remember_me = BooleanField('Remember Me')
    submit = SubmitField('Sign In')



class RegistrationForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=64)])
    phone = StringField('Phone', validators=[DataRequired(), ], render_kw={'placeholder': 'Enter MoMo number'})
    email = EmailField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    password2 = PasswordField('Repeat Password', validators=[DataRequired(), EqualTo('password')])
    role = QuerySelectField('Role', query_factory=lambda: Role.query.filter(Role.name != 'Admin').all(), get_label='name', allow_blank=False)
    
    submit = SubmitField('Register')

    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')


class AdminUserForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=64)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', render_kw={'placeholder': 'Enter MoMo number'})
    password = PasswordField('Password', validators=[DataRequired()])
    password_2 = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Submit')

    
class EditAdminUserForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=64)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', render_kw={'placeholder': 'Enter MoMo number'})
    submit = SubmitField('Submit')


class EditUserForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=64)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    phone = StringField('Phone', render_kw={'placeholder': 'Enter MoMo number'})
    role = QuerySelectField(
        'Role',
        query_factory=lambda: Role.query.filter(Role.name != 'Admin').all(),
        get_label='name',
        allow_blank=False,
    )
    submit = SubmitField('Submit')


class CompleteForm(FlaskForm):
    first_name = StringField('First Name', validators=[DataRequired(), Length(min=2, max=64)])
    last_name = StringField('Last Name', validators=[DataRequired(), Length(min=2, max=64)])
    email = StringField('Email', validators=[DataRequired(), Email(), Length(max=120)])
    role = SelectField('Register as', choices=[('client', 'Client'), ('driver', 'Driver')], validators=[DataRequired()])
    submit = SubmitField('Register')


class PostJobForm(FlaskForm):
    description = TextAreaField('Job Description', validators=[DataRequired(), Length(min=10, max=500)])
    location_text = StringField('Location (e.g., Address or Landmark)', validators=[DataRequired(), Length(max=255)])
    image = FileField('Upload Picture')
    price = FloatField('Offered Payment (Optional)', validators=[Optional()]) # Made optional for MVP
    submit = SubmitField('Post Job')