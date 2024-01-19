from datetime import date
from flask import Flask, abort, render_template, redirect, url_for, flash, request
from flask_bootstrap import Bootstrap5
from flask_ckeditor import CKEditor
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.orm import relationship, Mapped, mapped_column
from sqlalchemy import ForeignKey
# from flask_gravatar import Gravatar #package dependency deprecrated - would need to downgrade Flask to 2.3.3
# Import your forms from the forms.py
from forms import RegisterForm, LoginForm, CreatePostForm, CommentForm


app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap5(app)

#Gravatar for avatars
# gravatar = Gravatar(app,
#                     size=100,
#                     rating='g',
#                     default='retro',
#                     force_default=False,
#                     force_lower=False,
#                     use_ssl=False,
#                     base_url=None)

# Configure Flask-login's Login Manager
login_manager = LoginManager()
login_manager.init_app(app)

# Create a user_loader callback
@login_manager.user_loader
def load_user(user_id):
    return db.session.execute(db.select(User).where(User.id == user_id)).scalar()

def admin_check(func):
    admin_id = 1
    @wraps(func)
        # function to check if current_user.id is equals to admin_id
    def is_admin(*args, **kwargs):
        # if id is not admin_id return abort(403) error
        if current_user.id != admin_id:
            return abort(403)
        # else continue
        return func(*args, **kwargs)
    return is_admin


# CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///posts.db'
db = SQLAlchemy()
db.init_app(app)


# CONFIGURE TABLES
class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    # Foreign key from user.id as a relationship to user table.
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    # Reference to user object, "posts" is the relationship to the user table
    author: Mapped["User"] = relationship(back_populates="posts")
    img_url = db.Column(db.String(250), nullable=False)
    # Reference to comment object, "parent_post" is the relationship to the comments table
    comments: Mapped[list["Comment"]] = relationship(back_populates="parent_post")


# CREATE TABLE IN DB
class User(UserMixin, db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))
    # This is the list of Blogpost objects that belongs to each user. "author" is the relationship to the Blogpost table
    posts: Mapped[list["BlogPost"]] = relationship(back_populates="author")
    # This is the list of Comment objects that belongs to each user. "author" is the relationship to the Comment table
    comments: Mapped["Comment"] = relationship(back_populates="comment_author")

# Create comments table
class Comment(db.Model):
    __tablename__ = "comments"
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    date = db.Column(db.String(250), nullable=False)
    # Foreign key from user.id as a relationship to user table.
    author_id: Mapped[int] = mapped_column(ForeignKey("users.id"))
    # Reference to user object, "posts" is the relationship to the user table
    comment_author: Mapped["User"] = relationship(back_populates="comments")
    # Reference to blogpost object, "comments" is the relationship to the blogpost table
    post_id: Mapped[int] = mapped_column(ForeignKey("blog_posts.id"))
    parent_post: Mapped[list["BlogPost"]] = relationship(back_populates="comments")

with app.app_context():
    db.create_all()


# Use Werkzeug to hash the user's password when creating a new user.
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        email = form.email.data
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()

        if user:
            # User already exists
            flash("You've already signed up with this email, log in instead!")
            return redirect(url_for('login'))
        
        new_user = User(
            email = form.email.data,
            password = generate_password_hash(form.password.data, method="pbkdf2:sha256", salt_length=8),  # hash and salted poassword
            name = form.name.data
        )
        db.session.add(new_user)
        db.session.commit()

        # Log in and authenticate user after adding details to DB.
        login_user(new_user)
        # Can redirect and get name from teh current_user
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=form, logged_in=current_user.is_authenticated)


#  Retrieve a user from the database based on their email. 
@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        # Find user by email provided.
        result = db.session.execute(db.select(User).where(User.email == email))
        user = result.scalar()
        if user:
            # Check stored password hash against entered password hashed.
            if check_password_hash(user.password, password):
                login_user(user)
                flash("You  were successfully logged in!")
                return redirect(url_for("get_all_posts"))
            else:
                error = "Password is incorrect, please try again."
        else:
            error = "That email does not exist, please try again."
    return render_template("login.html", error=error, form=form, logged_in=current_user.is_authenticated)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("You were successfully logged out!")
    return redirect(url_for('get_all_posts'))


@app.route('/')
def get_all_posts():
    print(current_user)
    result = db.session.execute(db.select(BlogPost))
    posts = result.scalars().all()
    return render_template("index.html", all_posts=posts)


# Allow logged-in users to comment on posts
@app.route("/post/<int:post_id>", methods={"GET", "POST"})
def show_post(post_id):
    form = CommentForm()
    requested_post = db.get_or_404(BlogPost, post_id)
    if form.validate_on_submit():
        if not current_user.is_authenticated:
            flash("You need to login or register to comment.")
            return redirect(url_for("login"))
        
        new_comment = Comment(
            text = form.comment.data,
            author_id=current_user.id,
            post_id=requested_post.id,
            date = date.today().strftime("%B %d, %Y - %X")
        )
        db.session.add(new_comment)
        db.session.commit()
        print(requested_post.comments)
    return render_template("post.html", post=requested_post, form=form, current_user=current_user)


# Use a decorator so only an admin user can create a new post
@app.route("/new-post", methods=["GET", "POST"])
@login_required
@admin_check
def add_new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        new_post = BlogPost(
            title=form.title.data,
            subtitle=form.subtitle.data,
            body=form.body.data,
            img_url=form.img_url.data,
            author=current_user,
            date=date.today().strftime("%B %d, %Y")
        )
        db.session.add(new_post)
        db.session.commit()
        return redirect(url_for("get_all_posts"))
    return render_template("make-post.html", form=form)


# Use a decorator so only an admin user can edit a post
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
@login_required
@admin_check
def edit_post(post_id):
    post = db.get_or_404(BlogPost, post_id)
    edit_form = CreatePostForm(
        title=post.title,
        subtitle=post.subtitle,
        img_url=post.img_url,
        author=post.author,
        body=post.body
    )
    if edit_form.validate_on_submit():
        post.title = edit_form.title.data
        post.subtitle = edit_form.subtitle.data
        post.img_url = edit_form.img_url.data
        post.author = current_user
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))
    return render_template("make-post.html", form=edit_form, is_edit=True)


# TODO: Use a decorator so only an admin user can delete a post
@app.route("/delete/<int:post_id>")
@login_required
def delete_post(post_id):
    post_to_delete = db.get_or_404(BlogPost, post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")


if __name__ == "__main__":
    app.run(debug=True, port=5002)
