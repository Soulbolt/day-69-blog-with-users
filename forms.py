from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, EmailField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField


# WTForm for creating a blog post
class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


# WTForm for creating user accounts
class RegisterForm(FlaskForm):
    name = StringField(label="Name", validators=[DataRequired()])
    email = EmailField(label="Email", validators=[DataRequired(), Email()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    submit = SubmitField(label="SIGN ME UP")

# Create a LoginForm to login existing users
class LoginForm(FlaskForm):
    email = EmailField(label="Email", validators=[DataRequired(), Email()])
    password = PasswordField(label="Password", validators=[DataRequired()])
    subbit = SubmitField(label="LET ME IN")

# Create a CommentForm so users can leave comments below posts
class CommentForm(FlaskForm):
    comment = CKEditorField(label="Comment", validators=[DataRequired()])
    submit = SubmitField(label="Submit Comment")
