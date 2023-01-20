from flask import Flask, render_template, redirect, url_for, flash, abort
from flask_bootstrap import Bootstrap
from flask_ckeditor import CKEditor
from datetime import date
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from forms import CreatePostForm
from flask_gravatar import Gravatar
from forms import RegisterForm, CreatePostForm, LoginForm, CommentForm
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = '8BYkEfBA6O6donzWlSihBXox7C0sKR6b'
ckeditor = CKEditor(app)
Bootstrap(app)

##CONNECT TO DB
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///blog.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# flask login
login_manager = LoginManager()
login_manager.init_app(app=app)

# user loader callback function
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# create admin-only decorator
def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # if id != 1 then return 403 error message
        if current_user.id != 1:
            return abort(403)
        # else continue with route function
        return f(*args, **kwargs)
    return decorated_function

##CONFIGURE TABLES
class User(UserMixin, db.Model):
    __tablename__ = "user" # create new table in same db
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), unique=True, nullable=False)
    password = db.Column(db.String(250))

    # create one-to-many relationship: one user can write many posts
    # relationship with "author" in BlogPost class
    # parent - each user has a post(s)
    posts = relationship("BlogPost", back_populates="author")

class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)

    # create foreign key - eg. each posts written by author 5 will have foreign = 5
    author_id = db.Column(db.Integer, db.ForeignKey("user.id")) # user.id is the name of the table
    # relationship with "posts" in User class
    # child - each blog post has an author
    author = relationship("User", back_populates="posts")

    # author = db.Column(db.String(250), nullable=False)
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)

with app.app_context():
    db.create_all()

@app.route('/')
def get_all_posts():
    posts = BlogPost.query.all()
    return render_template("index.html", all_posts=posts, logged_in=current_user.is_authenticated)


@app.route('/register', methods=['GET', 'POST'])
def register():
    # instantiate form object
    registration = RegisterForm()
    if registration.validate_on_submit():

        # check if user email exists
        if User.query.filter_by(email=registration.email.data).first():
            flash("You have already signed up with that email, login instead!")
            return redirect(url_for('login'))

        # create new user
        new_user = User(
            name = registration.name.data,
            email = registration.email.data,
            # encrypt password
            password = generate_password_hash(
                password=registration.password.data,
                method='pbkdf2:sha256',
                salt_length=8
                ),
        )
        # add user to the database
        db.session.add(new_user)
        db.session.commit()
        # login user
        login_user(new_user)
        return redirect(url_for("get_all_posts"))
    return render_template("register.html", form=registration)


@app.route('/login', methods=['GET', 'POST'])
def login():
    # form object
    login_form = LoginForm()
    if login_form.validate_on_submit():
        # get the attributes
        email = login_form.email.data
        password = login_form.password.data
        
        # find the user using the email
        user = User.query.filter_by(email=email).first()
        # if user is not found - display error message
        if not user:
            flash('Email does not exist, please try again')
            return redirect(url_for('login'))
        # else if passwords do not match
        elif not check_password_hash(user.password, password):
            flash('Password invalid, try again')
            return redirect(url_for('login'))
        # if user exists and passwords match - login user
        else:
            # log in user
            login_user(user)
            return redirect(url_for('get_all_posts'))

    return render_template("login.html", logged_in=current_user.is_authenticated, form=login_form)


@app.route('/logout')
def logout():
    # logout
    logout_user()
    return redirect(url_for('get_all_posts'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    comment_form = CommentForm()
    return render_template("post.html", post=requested_post, form=comment_form)


@app.route("/about")
def about():
    return render_template("about.html")


@app.route("/contact")
def contact():
    return render_template("contact.html")

# decorator
@admin_only
@app.route("/new-post", methods=["GET", "POST"])
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
    return render_template("make-post.html", form=form, current_user=current_user)

# decorator
@admin_only
@app.route("/edit-post/<int:post_id>", methods=["GET", "POST"])
def edit_post(post_id):
    post = BlogPost.query.get(post_id)
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
        post.author = edit_form.author.data
        post.body = edit_form.body.data
        db.session.commit()
        return redirect(url_for("show_post", post_id=post.id))

    return render_template("make-post.html", form=edit_form)

# decorator
@admin_only
@app.route("/delete/<int:post_id>")
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('get_all_posts'))


if __name__ == "__main__":
    app.run(debug=True)
