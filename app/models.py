from datetime import datetime
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from markdown import markdown
import bleach
from flask import current_app, request, url_for
from flask.ext.login import UserMixin, AnonymousUserMixin
from app.exceptions import ValidationError
from . import db, login_manager
from sqlalchemy.dialects.mysql import INTEGER

class Permission:
    FOLLOW = 0x01
    COMMENT = 0x02
    WRITE_ARTICLES = 0x04
    MODERATE_COMMENTS = 0x08
    ADMINISTER = 0x80


class Role(db.Model):
    __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)
    default = db.Column(db.Boolean, default=False, index=True)
    permissions = db.Column(db.Integer)
    users = db.relationship('User', backref='role', lazy='dynamic')

    @staticmethod
    def insert_roles():
        roles = {
            'User': (Permission.FOLLOW |
                     Permission.COMMENT |
                     Permission.WRITE_ARTICLES, True),
            'Moderator': (Permission.FOLLOW |
                          Permission.COMMENT |
                          Permission.WRITE_ARTICLES |
                          Permission.MODERATE_COMMENTS, False),
            'Administrator': (0xff, False)
        }
        for r in roles:
            role = Role.query.filter_by(name=r).first()
            if role is None:
                role = Role(name=r)
            role.permissions = roles[r][0]
            role.default = roles[r][1]
            db.session.add(role)
        db.session.commit()

    def __repr__(self):
        return '<Role %r>' % self.name


class Follow(db.Model):
    __tablename__ = 'follows'
    follower_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    followed_id = db.Column(db.Integer, db.ForeignKey('users.id'),
                            primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def generate_fake():
        user_count = User.query.count()
        for x in range(1,user_count+1):
            follower = User.query.get(x)
            for y in range(10):
                followed = User.query.get((x+y)%user_count+1)
                f = Follow(followed=followed,follower=follower)
                db.session.add(f)
        db.session.commit()


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(64), unique=True, index=True)
    username = db.Column(db.String(64), unique=True, index=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    password_hash = db.Column(db.String(128))
    confirmed = db.Column(db.Boolean, default=False)
    name = db.Column(db.String(64))
    location = db.Column(db.String(64))
    about_me = db.Column(db.Text())
    member_since = db.Column(db.DateTime(), default=datetime.utcnow)
    last_seen = db.Column(db.DateTime(), default=datetime.utcnow)
    avatar_hash = db.Column(db.String(32))
    use_default_avatar = db.Column(db.Boolean, default = True)
    followed = db.relationship('Follow',
                               foreign_keys=[Follow.follower_id],
                               backref=db.backref('follower', lazy='joined'),
                               lazy='dynamic',
                               cascade='all, delete-orphan')
    followers = db.relationship('Follow',
                                foreign_keys=[Follow.followed_id],
                                backref=db.backref('followed', lazy='joined'),
                                lazy='dynamic',
                                cascade='all, delete-orphan')
    comments = db.relationship('Comment', backref='author', lazy='dynamic')
    questions = db.relationship('Question', backref='author', lazy='dynamic')
    answers = db.relationship('Answer', backref='author', lazy='dynamic')
    upvotes = db.relationship('Upvote',backref='author',lazy='dynamic')

    @staticmethod
    def generate_fake(count=100):
        from sqlalchemy.exc import IntegrityError
        from random import seed
        import forgery_py

        seed()
        for i in range(count):
            u = User(email=forgery_py.internet.email_address(),
                     username=forgery_py.internet.user_name(True),
                     password='Aa123456',
                     confirmed=True,
                     name=forgery_py.name.full_name(),
                     location=forgery_py.address.city(),
                     about_me=forgery_py.lorem_ipsum.sentence(),
                     member_since=forgery_py.date.date(True))
            db.session.add(u)
            try:
                db.session.commit()
            except IntegrityError:
                db.session.rollback()

    @staticmethod
    def add_self_follows():
        for user in User.query.all():
            if not user.is_following(user):
                user.follow(user)
                db.session.add(user)
                db.session.commit()

    def __init__(self, **kwargs):
        super(User, self).__init__(**kwargs)
        if self.role is None:
            if self.email == current_app.config['FLASKY_ADMIN']:
                self.role = Role.query.filter_by(permissions=0xff).first()
            if self.role is None:
                self.role = Role.query.filter_by(default=True).first()
        if self.email is not None and self.avatar_hash is None:
            self.avatar_hash = hashlib.md5(
                self.email.encode('utf-8')).hexdigest()
        self.follow(self)

    @property
    def password(self):
        raise AttributeError('password is not a readable attribute')

    @password.setter
    def password(self, password):
        self.password_hash = generate_password_hash(password)

    def verify_password(self, password):
        return check_password_hash(self.password_hash, password)

    def generate_confirmation_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'confirm': self.id})

    def confirm(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('confirm') != self.id:
            return False
        self.confirmed = True
        db.session.add(self)
        return True

    def generate_reset_token(self, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'reset': self.id})

    def reset_password(self, token, new_password):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('reset') != self.id:
            return False
        self.password = new_password
        db.session.add(self)
        return True

    def generate_email_change_token(self, new_email, expiration=3600):
        s = Serializer(current_app.config['SECRET_KEY'], expiration)
        return s.dumps({'change_email': self.id, 'new_email': new_email})

    def change_email(self, token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return False
        if data.get('change_email') != self.id:
            return False
        new_email = data.get('new_email')
        if new_email is None:
            return False
        if self.query.filter_by(email=new_email).first() is not None:
            return False
        self.email = new_email
        self.avatar_hash = hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
        db.session.add(self)
        return True

    def can(self, permissions):
        return self.role is not None and \
            (self.role.permissions & permissions) == permissions

    def is_administrator(self):
        return self.can(Permission.ADMINISTER)

    def ping(self):
        self.last_seen = datetime.utcnow()
        db.session.add(self)

    def gravatar(self, size=100, default='identicon', rating='g'):
        if request.is_secure:
            url = 'https://secure.gravatar.com/avatar'
        else:
            url = 'http://cn.gravatar.com/avatar'
        hash = self.avatar_hash or hashlib.md5(
            self.email.encode('utf-8')).hexdigest()
        return '{url}/{hash}?s={size}&d={default}&r={rating}'.format(
            url=url, hash=hash, size=size, default=default, rating=rating)

    def up_answer(self,answer):
        query = self.upvotes.filter_by(answer=answer).first()
        if(query is None):
            u = Upvote(author=self,answer=answer,value=1)
            db.session.add(u)
        elif(query.value == -1):
        #cancel down
            db.session.delete(query)
        db.session.commit()

    def down_answer(self,answer):
        query = self.upvotes.filter_by(answer=answer).first()
        if(query is None):
            u = Upvote(author=self,answer=answer,value=-1)
            db.session.add(u)
        elif(query.value == 1):
        # cancel up
            db.session.delete(query)
        db.session.commit()


    def has_upvoted(self,answer):
        query = self.upvotes.filter_by(
            answer=answer).first()
        if query is None:
            return False
        else:
            return True if query.value == 1 else False

    def has_downvoted(self,answer):
        query = self.upvotes.filter_by(
            answer=answer).first()
        if query is None:
            return False
        else:
            return True if query.value == -1 else False

    def follow(self, user):
        if not self.is_following(user):
            f = Follow(follower=self, followed=user)
            db.session.add(f)

    def unfollow(self, user):
        f = self.followed.filter_by(followed_id=user.id).first()
        if f:
            db.session.delete(f)

    def is_following(self, user):
        return self.followed.filter_by(
            followed_id=user.id).first() is not None

    def is_followed_by(self, user):
        return self.followers.filter_by(
            follower_id=user.id).first() is not None

    @property
    def followed_posts(self):
        return Question.query.join(Follow, Follow.followed_id == Question.author_id)\
            .filter(Follow.follower_id == self.id)

    @property
    def feed(self):
        q = Question.query.join(Follow, Follow.followed_id == Question.author_id)\
            .filter(Follow.follower_id == self.id).all()
        a = Answer.query.join(Follow, Follow.followed_id == Answer.author_id)\
            .filter(Follow.follower_id == self.id).all()
        u = Upvote.query.join(Follow, Follow.followed_id == Upvote.author_id)\
            .filter(Follow.follower_id == self.id,Upvote.value ==1).all()
        feed = q + a + u
        feed.sort(key=lambda x:x.timestamp,reverse=True)
        return feed

    @property
    def notification(self):
        n = []
    # all answers for user's questions
        for question in self.questions:
            for answer in question.answers:
                n.append(answer)
        for answer in self.answers:
            for upvote in answer.upvotes :
                if(upvote.value):
                    n.append(upvote)
            for comment in answer.comments:
                n.append(comment)
        n.sort(key=lambda x:x.timestamp,reverse=True)
        return n
    # def to_json(self):
    #     json_user = {
    #         'url': url_for('api.get_user', id=self.id, _external=True),
    #         'username': self.username,
    #         'member_since': self.member_since,
    #         'last_seen': self.last_seen,
    #         'posts': url_for('api.get_user_posts', id=self.id, _external=True),
    #         'followed_posts': url_for('api.get_user_followed_posts',
    #                                   id=self.id, _external=True),
    #         'post_count': self.posts.count()
    #     }
    #     return json_user

    def generate_auth_token(self, expiration):
        s = Serializer(current_app.config['SECRET_KEY'],
                       expires_in=expiration)
        return s.dumps({'id': self.id}).decode('ascii')

    @staticmethod
    def verify_auth_token(token):
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except:
            return None
        return User.query.get(data['id'])

    def __repr__(self):
        return '<User %r>' % self.username


class AnonymousUser(AnonymousUserMixin):
    def can(self, permissions):
        return False

    def is_administrator(self):
        return False

login_manager.anonymous_user = AnonymousUser


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class Desc(db.Model):
    __tablename__ = 'descs'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64))
    body = db.Column(db.Text)
    questions = db.relationship('Question', backref='desc', lazy='dynamic')
    answers = db.relationship('Answer', backref='desc', lazy='dynamic')
    comments = db.relationship('Comment',backref='desc', lazy='dynamic')
    upvotes = db.relationship('Upvote',backref='desc', lazy='dynamic')
    @staticmethod
    def insert_desc():
        desc = {'Question':'adds a question',
                'Answer':'adds a answer',
                'Comment':'adds a comment',
                'Upvote':'upvotes for this answer'}
        for k,v in desc.items():
            q = Desc.query.filter_by(name = k).first()
            if q is None:
                a = Desc(name = k,body = v)
                db.session.add(a)
                db.session.commit()



class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    desc_id = db.Column(db.Integer, db.ForeignKey('descs.id'))
    answers = db.relationship('Answer', backref='question', lazy='dynamic')
    def __init__(self, **kwargs):
        super(Question, self).__init__(**kwargs)
        d = Desc.query.filter_by(name='Question').first()
        self.desc = d

    @staticmethod
    def generate_fake(count=100):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        for i in range(count):
            # d = Desc.query.filter_by(name = 'Question').first()
            u = User.query.offset(randint(0, user_count - 1)).first()
            p = Question(body=forgery_py.lorem_ipsum.sentences(randint(1, 5)),
                     timestamp=forgery_py.date.date(True),
                     author=u)
            db.session.add(p)
            db.session.commit()

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
                        'em', 'i', 'li', 'ol', 'pre', 'strong', 'ul',
                        'h1', 'h2', 'h3', 'p','img']
        allowed_attrs = {'img': ['src', 'alt']}
#        target.body_html = bleach.linkify(bleach.clean(
#            markdown(value, output_format='html'),
#            tags=allowed_tags, strip=True))
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True, attributes=allowed_attrs))

    # def to_json(self):
    #     json_post = {
    #         'url': url_for('api.get_post', id=self.id, _external=True),
    #         'body': self.body,
    #         'body_html': self.body_html,
    #         'timestamp': self.timestamp,
    #         'author': url_for('api.get_user', id=self.author_id,
    #                           _external=True),
    #         'comments': url_for('api.get_post_comments', id=self.id,
    #                             _external=True),
    #         'comment_count': self.comments.count()
    #         }
    # @staticmethod
    # def from_json(json_post):
    #     body = json_post.get('body')
    #     if body is None or body == '':
    #         raise ValidationError('post does not have a body')
    #     return Post(body=body)


db.event.listen(Question.body, 'set', Question.on_changed_body)


class Answer(db.Model):
    __tablename__ = 'answers'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    body_html = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'))
    desc_id = db.Column(db.Integer, db.ForeignKey('descs.id'))
    comments = db.relationship('Comment', backref='answer', lazy='dynamic')
    upvotes  = db.relationship('Upvote',backref='answer',lazy='dynamic')

    def __init__(self, **kwargs):
        super(Answer, self).__init__(**kwargs)
        d = Desc.query.filter_by(name='Answer').first()
        self.desc = d

    def abs_upvote(self):
        count = 0
        for upvote in self.upvotes:
            count+=upvote.value
        return count

    @staticmethod
    def on_changed_body(target, value, oldvalue, initiator):
        allowed_tags = ['a', 'abbr', 'acronym', 'b', 'code', 'em', 'i',
                        'strong']
        target.body_html = bleach.linkify(bleach.clean(
            markdown(value, output_format='html'),
            tags=allowed_tags, strip=True))

    @staticmethod
    def generate_fake(count=400):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        question_count = Question.query.count()
        for i in range(count):
            # d = Desc.query.filter_by(name = 'Answer').first()
            u = User.query.offset(randint(0, user_count - 1)).first()
            q = Question.query.offset(randint(0,question_count - 1)).first()
            if(Answer.query.filter_by(author=u,question=q).first()):
                continue
            p = Answer(body=forgery_py.lorem_ipsum.sentences(randint(1, 5)),
                     timestamp=forgery_py.date.date(True),
                     author=u,
                     question=q)
            db.session.add(p)
            db.session.commit()

    # def to_json(self):
    #     json_comment = {
    #         'url': url_for('api.get_comment', id=self.id, _external=True),
    #         'post': url_for('api.get_post', id=self.post_id, _external=True),
    #         'body': self.body,
    #         'body_html': self.body_html,
    #         'timestamp': self.timestamp,
    #         'author': url_for('api.get_user', id=self.author_id,
    #                           _external=True),
    #     }
    #     return json_comment

    # @staticmethod
    # def from_json(json_comment):
    #     body = json_comment.get('body')
    #     if body is None or body == '':
    #         raise ValidationError('comment does not have a body')
    #     return Comment(body=body)


db.event.listen(Answer.body, 'set', Answer.on_changed_body)

class Comment(db.Model):
    #plain text only
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    body = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    disabled = db.Column(db.Boolean)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    answer_id = db.Column(db.Integer, db.ForeignKey('answers.id'))
    desc_id = db.Column(db.Integer, db.ForeignKey('descs.id'))

    def __init__(self, **kwargs):
        super(Comment, self).__init__(**kwargs)
        d = Desc.query.filter_by(name='Comment').first()
        self.desc = d

    @staticmethod
    def generate_fake(count=700):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        answer_count = Answer.query.count()
        for i in range(count):
            # d = Desc.query.filter_by(name = 'Comment').first()
            u = User.query.offset(randint(0, user_count - 1)).first()
            a = Answer.query.offset(randint(0,answer_count - 1)).first()
            if(Comment.query.filter_by(author=u,answer=a).first()):
                continue
            p = Comment(body=forgery_py.lorem_ipsum.sentences(randint(1, 5)),
                     timestamp=forgery_py.date.date(True),
                     author=u,
                     answer=a)
            db.session.add(p)
            db.session.commit()

class Upvote(db.Model):
    #up or down to an answer
    #value=1 -> up      value=-1 -> down
    __tablename__ = 'upvotes'
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(INTEGER(unsigned=True))
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    answer_id = db.Column(db.Integer, db.ForeignKey('answers.id'))
    desc_id   = db.Column(db.Integer, db.ForeignKey('descs.id'))

    def __init__(self, **kwargs):
        super(Upvote, self).__init__(**kwargs)
        d = Desc.query.filter_by(name='Upvote').first()
        self.desc = d

    @staticmethod
    def generate_fake(count=500):
        from random import seed, randint
        import forgery_py

        seed()
        user_count = User.query.count()
        answer_count = Answer.query.count()
        for i in range(count):
            u = User.query.offset(randint(0, user_count - 1)).first()
            a = Answer.query.offset(randint(0,answer_count - 1)).first()
            query = Upvote.query.filter_by(author=u, answer=a).first()
            if(query is None):
                v = Upvote(author=u,
                           answer=a,
                           value=1)
                db.session.add(v)
                db.session.commit()
