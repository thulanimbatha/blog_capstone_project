from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField
from wtforms.validators import DataRequired, URL, Email, Length
from flask_ckeditor import CKEditorField
# import email_validator

##WTForm
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")

# WTForm - Register page
class RegisterForm(FlaskForm):
    email = StringField(label="Email", validators=[Email(message="Please enter valid email!") ,DataRequired()])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=8, message="Password needs 8 or more characters")])
    name = StringField(label="Name", validators=[DataRequired()])
    submit = SubmitField(label="Sign in")

# WTForm - Login page
class LoginForm(FlaskForm):
    email = StringField(label="Email", validators=[DataRequired(), Email(message="Please enter valid email!")])
    password = PasswordField(label="Password", validators=[DataRequired(), Length(min=8, message="Password needs 8 or more characters")])
    submit = SubmitField(label="Login")

# Comment form for users to comment on a blog post
class CommentForm(FlaskForm):
    comment = CKEditorField(label="Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")